### Title
Multi-org webhook signature verification keyed off unauthenticated payload field allows cross-repository status/deploy forgery - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to verify the incoming webhook against by reading `repository_owner` directly out of the still-unverified JSON body, and `GitHubApp#verify_webhook_signature` treats a blank/not-configured `webhook_secret` as "verification not required." This mirrors the M-04 bug class: a value that is "not configured" (blank) is indistinguishable from "explicitly disabled," so the fallback (skip verification) silently applies wherever an organization's `webhook_secret` was never set, and the org used for that check is chosen from attacker-controlled data before the signature has been validated.

### Finding Description
`verify_signature` picks the verifying key using data taken straight from the raw, unauthenticated request body: [1](#0-0) [2](#0-1) 

`repository_owner` is `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` — both come from `JSON.parse(request.raw_post)`'s payload, i.e. attacker-controlled content that has not yet been verified against any signature. This value is used to look up `Shipit.github(organization: repository_owner)`, which selects the per-organization app config (secret, private key, etc.) for a multi-org deployment: [3](#0-2) 

The signature is then checked with `GitHubApp#verify_webhook_signature`, which returns `true` (verified) whenever the org's `webhook_secret` is blank — the documented default for a newly configured org (see `webhook_secret: # nil` in the setup docs and templates): [4](#0-3) 

Because "webhook secret not configured" and "webhook verification intentionally disabled" both collapse to the same `webhook_secret.blank?` state — exactly the class of bug described in the report, where "not set" and "explicitly zero/absent" cannot be distinguished — any org in a multi-org install that has not (yet) had a `webhook_secret` populated will accept a forged payload naming that org as `repository.owner.login`, with an arbitrary `X-Hub-Signature` header (or none at all, since it's never actually checked). The handlers dispatched afterward (`PushHandler`, `StatusHandler`, etc.) then act on the same attacker-controlled `repository.full_name`/`sha` fields to mutate live `Stack`/`Commit` state: [5](#0-4) [6](#0-5) [7](#0-6) 

This breaks the binding: `organization whose credentials authenticated the request == organization owning the repository being written`. An unprivileged, unauthenticated attacker can pick which side of that equality gets evaluated by simply naming a different (secret-less) organization in the JSON body, then have handlers act on a repository/branch/commit belonging to any organization onboarded to the Shipit instance.

### Impact Explanation
A `push` webhook forged this way triggers `stack.sync_github(expected_head_sha: ...)`, which reconciles the stack's known commits/branch head from GitHub using the (also attacker-influenced) SHA — feeding directly into subsequent deploy eligibility and continuous-deployment triggers. A forged `status`/`check_suite` webhook can mark arbitrary commits as passing CI (`create_status_from_github!`), which is exactly the signal Shipit's continuous-deployment and merge-queue logic use to decide whether a commit is safe to autodeploy or merge. Chained together, this can result in an unauthorized deploy being triggered for a stack the attacker has no legitimate access to — matching the "Critical: unauthorized deploy" impact bucket. It is capped to organizations whose `webhook_secret` is blank/misconfigured, which is realistic in the multi-org GitHub App setup this codebase explicitly supports (documented default is an empty `webhook_secret`).

### Likelihood Explanation
Requires zero credentials — only network access to the public `/webhooks` endpoint and knowledge that at least one configured organization has not set a `webhook_secret` (a documented, blank-by-default field for every org entry). No repository write access, API token, or session is needed. Likelihood is Medium-to-High in any multi-org deployment where operators haven't populated every org's `webhook_secret`, and the vulnerable code path (unauthenticated field selecting the verification key) is unconditionally reachable pre-authentication.

### Recommendation
- Do not let attacker-supplied payload fields select which secret is used to verify that very payload. Verify the signature against every configured org's secret (or a canonical shared secret) and only then determine which organization/repository the payload refers to, or bind organization to signature via a per-org route/webhook URL instead of a body field.
- Change `GitHubApp#verify_webhook_signature` so a blank `webhook_secret` is treated as "reject" (fail closed) rather than "accept" (fail open), and make `webhook_secret` a required, validated field rather than an implicit `nil`-defaulted optional one — mirroring the report's recommendation to distinguish "not configured" from "verification intentionally disabled."

### Proof of Concept
1. Deploy Shipit with a multi-org GitHub App config where `OrgB` has no `webhook_secret` set (default per `docs/setup.md`/`template.rb`), while `OrgA` (target victim org/repo) does have one set.
2. As an unauthenticated attacker, POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha belonging to OrgA's tracked repo>",
  "repository": { "owner": { "login": "OrgB" }, "full_name": "OrgA/target-repo" }
}
```
Include any `X-Hub-Signature` value (or omit it).
3. `verify_signature` calls `Shipit.github(organization: "OrgB")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally — bypassing verification entirely.
4. `PushHandler` runs using `repository.full_name` = `OrgA/target-repo`, invoking `stack.sync_github(expected_head_sha: ...)` on OrgA's stack despite the request never being authenticated against OrgA's GitHub App/secret.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** lib/shipit.rb (L170-200)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
```

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-25)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
      end
```
