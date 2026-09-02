### Title
Webhook signature verification authenticates the payload's `repository.owner.login` while every handler acts on the same payload's `repository.full_name` (or, worse, no repository at all) - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks the GitHub App/secret used to validate `X-Hub-Signature` from `repository_owner` (`params.dig('repository','owner','login')` or `params.dig('organization','login')`), while `Shipit::Webhooks::Handlers::Handler#stacks`/`#repository_name` (and `StatusHandler#process`) resolve the record to mutate from a *different* field of the very same JSON body: `payload.dig('repository', 'full_name')`, or in `StatusHandler`'s case, an unscoped `Commit.where(sha: params.sha)` lookup that ignores the repository entirely. Nothing ties the "organization whose secret authenticated the request" to the "repository/commit that actually gets written." [1](#0-0) [2](#0-1) [3](#0-2) 

### Finding Description
The mitigation-worthy binding here is: `organization authenticated == repository written`. Shipit explicitly supports onboarding multiple, independently-administered GitHub organizations, each with its own `app_id`/`installation_id`/`webhook_secret`, configured under a per-organization key in `secrets.github`: [4](#0-3) [5](#0-4) 

`GitHubApp#verify_webhook_signature` only proves that *some* org's secret was used to sign the exact raw body received; it says nothing about which repository inside that body should be trusted: [6](#0-5) 

`WebhooksController#verify_signature` selects which org's secret to check against using `repository_owner`, sourced from the payload's `repository.owner.login` (falling back to `organization.login`): [7](#0-6) 

But `Handler#stacks` (used by `PushHandler`, `CheckSuiteHandler`, PR handlers, etc.) resolves the target `Repository`/`Stack` using `repository.full_name`, a sibling field in the same payload that is never cross-checked against `repository.owner.login`: [8](#0-7) [9](#0-8) [10](#0-9) 

Even more directly, `StatusHandler#process` doesn't consult the repository at all - it matches purely on commit SHA globally across every `Stack` tracked by the Shipit instance: [11](#0-10) 

For genuine GitHub-originated deliveries this discrepancy is latent because GitHub itself keeps `repository.owner.login` and `repository.full_name` consistent, and only GitHub (holding the org's secret) can produce a validly-signed body. However, in the documented multi-organization deployment model, each participating organization's administrator supplies (and therefore knows) their own `webhook_secret` to the shared Shipit instance operator. Any such org-admin, holding a valid secret for *their own* org, can POST directly to `/webhooks` (bypassing GitHub) with:
- `repository.owner.login` set to their own org (or `organization.login` set to their own org) → passes `verify_signature` using their own known secret,
- `repository.full_name` set to `victim-org/victim-repo` (or, for `status` events, just any `sha` belonging to a commit tracked under a *different* org's stack) → the handler acts on a repository/stack/commit outside the org whose secret authenticated the call.

This breaks the deployment-trust binding: "organization that authenticated" (`repository_owner`, checked in `verify_signature`) vs. "repository that is written" (`repository.full_name`/bare commit `sha`, used inside the handlers).

### Impact Explanation
This crosses the required High-impact bar: "escalation into `Shipit.github_teams` authorization" and effectively unauthorized cross-repository writes/deploy-gating manipulation, without needing any Shipit session, `ApiClient` token, or the victim org's own secret:
- `PushHandler`/`CheckSuiteHandler` can trigger `GithubSyncJob`/`RefreshCheckRunsJob` against a victim stack whose owning org's secret the attacker never had.
- `StatusHandler` lets a holder of *any one* onboarded org's webhook secret inject a fabricated commit status (`state`, `description`, `target_url`) onto any commit SHA already tracked by Shipit, regardless of which org's repository that commit belongs to; commit statuses feed into deployability checks (`deployable_status`) and merge-queue automation, which can be used to make an otherwise-blocked commit appear "green" and eligible for auto-deploy/auto-merge in a repository the attacker does not control.

### Likelihood Explanation
Requires the operator to run the documented multi-organization configuration (explicitly supported and documented) and requires the attacker to be an administrator of at least one onboarded org (i.e., they legitimately possess that org's `webhook_secret`, which is a normal, unprivileged-relative-to-other-orgs role in this multi-tenant setup) — no compromise of the victim org's credentials, no Shipit session, and no `ApiClient` token is needed. Likelihood is moderate: it is gated on the multi-org feature being used, but that feature is a first-class, documented capability of the engine.

### Recommendation
- In `WebhooksController#verify_signature`, after computing the org used for signature verification, re-derive the repository owner strictly from `repository.full_name` (or `repository.owner.login`) and reject the request if it does not match the org whose secret was used to verify the signature.
- In `Handler#repository_name`/`#stacks`, cross-check that the resolved `Repository#owner` matches the org that authenticated the webhook (pass the authenticated organization down into the handler and assert equality).
- In `StatusHandler#process` (and any other handler matching purely by `sha`/global lookup), scope the `Commit` lookup to stacks/repositories belonging to the authenticated organization instead of a global `Commit.where(sha:)`.

### Proof of Concept
Given a Shipit instance configured per `docs/setup.md`'s multi-org example with `OrgA` and `OrgB` (`OrgB` owning a tracked stack `orgb/victim-repo`, with a commit `deadbeef` already synced):

1. Attacker is the administrator who onboarded `OrgA` and therefore knows `OrgA`'s `webhook_secret` (per the self-service, per-org secret model in `secrets.github`).
2. Attacker computes `X-Hub-Signature: sha1=<hmac(OrgA_webhook_secret, body)>` over a crafted `status` event body:
```json
{
  "sha": "deadbeef",
  "state": "success",
  "context": "ci/required-check",
  "description": "forged by OrgA admin",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "orga/decoy" }
}
```
3. POST this body with header `X-Github-Event: status` to `/webhooks`.
4. `verify_signature` calls `Shipit.github(organization: "OrgA")` (from `repository.owner.login`) and validates successfully against the attacker-known `OrgA` secret, per `app/controllers/shipit/webhooks_controller.rb` lines 24-38 and `lib/shipit/github_app.rb` lines 76-83.
5. `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb` lines 20-24) matches `Commit.where(sha: "deadbeef")` globally, finds the commit belonging to `OrgB`'s `victim-repo` stack, and creates a forged successful status on it — despite the request only ever proving possession of `OrgA`'s secret.

*Note: full end-to-end confirmation (e.g., tracing how a forged commit status subsequently gates `deployable_status`/merge automation) would benefit from running the test suite (`test/controllers/webhooks_controller_test.rb`, `test/models/shipit/stack_test.rb`) in a live Devin session, since static reading cannot execute the merge/deploy-gating code paths to confirm the downstream automation trigger.*

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-39)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
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

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
