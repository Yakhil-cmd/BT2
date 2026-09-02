### Title
Webhook signature verification keys off `repository.owner.login` while event handlers act on the independent `repository.full_name` field, letting a valid signature from one GitHub organization authorize writes against another organization's stack - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
In Shipit's multi-organization GitHub App configuration, `WebhooksController#verify_signature` selects which organization's `webhook_secret` to use for HMAC verification based on the attacker-controlled, **unverified** JSON field `repository.owner.login` (or `organization.login`). Once the HMAC check passes using that organization's secret, the entire raw payload is treated as trusted and dispatched to event handlers, which resolve the actual repository/stack to mutate using a *different*, independently-controlled field: `repository.full_name`. Because nothing ties `repository.owner.login` to `repository.full_name`, an org-A-authenticated payload can claim to be for `org-b/some-repo`.

### Finding Description
`verify_signature` computes the app/secret to verify against like this: [1](#0-0) 

using `repository_owner`, which is read straight from the raw request body before any authenticity check: [2](#0-1) 

`Shipit.github(organization:)` resolves per-organization secrets from `secrets.github`, supporting exactly this multi-org setup: [3](#0-2) 

After `head(422) unless verified` (a *non-halting* check - it does not `return`/`throw` before continuing, so if `verified` happened to be computed truthy for the attacker-chosen org, execution proceeds normally), `create` parses the same raw JSON again and dispatches to handlers using the same payload: [4](#0-3) 

Every handler resolves the target repository/stack from `repository.full_name`, a field completely independent from `repository.owner.login`: [5](#0-4) [6](#0-5) 

For example, the push handler triggers a GitHub sync for whatever stack matches `full_name`+branch, and the status handler flips CI status on any commit whose `sha` matches, independent of which org's secret verified the signature: [7](#0-6) [8](#0-7) 

**The binding that should hold but doesn't:** `organization authenticated by the webhook signature == organization that owns the repository being mutated`. Before the PR/payload: `repository.owner.login` (used to pick the secret) and `repository.full_name`'s owner segment (used to pick the mutated repository) are implicitly assumed to be the same GitHub-supplied field. After a crafted payload, they can diverge: an entity holding organization A's webhook secret (e.g., an app installer/admin for org A, or anyone who has learned it) can send `repository.owner.login = "org-a"` (to pass HMAC verification against org A's secret) together with `repository.full_name = "org-b/private-repo"` (to target a stack owned by org B, an organization the attacker has no relationship with).

This exactly mirrors the reported Solana bug class: a field (the instruction sysvar account / here, `repository.owner.login`) is used to make a trust decision (which secret authorizes the call / which org "owns" the request), while a *different* field that is actually acted upon (`instruction` sysvar re-used inside CPI account list / here, `repository.full_name` used to resolve the mutated record) is never checked for consistency with it.

### Impact Explanation
This crosses the "organization that authenticated versus the repository that is written" boundary called out as in-scope. Consequences, depending on which handler fires:
- `push` handler: forces `Stack#sync_github` for an arbitrary stack in another org, based on an attacker-forged `after` SHA - a step toward unauthorized deploy state manipulation once combined with continuous delivery.
- `status` handler: forges a commit status (`state: success`) on any commit whose SHA is known/guessable, which can flip a commit to "deployable" and, under `continuous_deployment: true`, cause an unauthorized automatic deploy on a stack the attacker has no access to (`Impact: unauthorized deploy`, Critical per the rules).
- `check_suite`/`membership` handlers likewise act on payload-controlled `organization`/`team` fields without validating that they match the org that authenticated the request.

This is only exploitable in the documented multi-organization GitHub App configuration (`docs/setup.md` "Using Multiple Github Applications", `config/secrets.development.shopify.yml`), which is a first-class, documented feature of the engine, not an unsupported configuration.

### Likelihood Explanation
Requires the deployment to use multiple GitHub App configs (each org has its own secret) - a supported and documented configuration. The attacker needs to know (or control) one organization's webhook secret (e.g., they administer/own the GitHub App installation for org A) but has no relationship to org B. They then send one crafted webhook POST with mismatched `owner.login`/`full_name` fields signed with org A's secret. No session, API token, or GitHub write access to org B is required - only knowledge of org A's webhook secret, which is a much weaker credential than the assets Shipit is trying to protect for org B.

### Recommendation
In `WebhooksController#verify_signature`/`create`, after establishing which `github_app`/organization authenticated the signature, re-validate that every repository/organization field consumed downstream (`repository.full_name`'s owner segment, `organization.login`, etc.) matches that authenticated organization before dispatching to handlers. Reject (422) any payload where these fields diverge.

### Proof of Concept
1. Configure Shipit with two GitHub Apps: `org-a` and `org-b` (per `docs/setup.md`'s multi-org schema), each with its own `webhook_secret`.
2. As someone who legitimately controls org A's GitHub App (and thus knows `org-a`'s `webhook_secret`), craft a `push` (or `status`) webhook JSON body where:
   - `repository.owner.login = "org-a"`
   - `repository.full_name = "org-b/private-repo"`
3. Sign the raw body with org A's `webhook_secret` (`sha1=` HMAC) and send it as `X-Hub-Signature` to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` looks up `Shipit.github(organization: "org-a")`, verifies successfully (since it's signed with org A's real secret), and does not halt the request.
5. `Shipit::Webhooks.for_event('push')` dispatches `PushHandler`, which resolves `Repository.from_github_repo_name("org-b/private-repo")` and calls `stack.sync_github` on a stack belonging to org B - an organization for which the attacker never proved GitHub authorization.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-24)
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

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
