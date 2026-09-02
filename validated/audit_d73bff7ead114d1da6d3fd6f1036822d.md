### Title
Webhook `status` event forges CI status for any repository regardless of which organization's signature was verified - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
The `WebhooksController` selects which organization's HMAC secret to verify a webhook against using an unauthenticated field of the payload itself (`repository.owner.login`), then hands the same raw payload to event handlers. The `status` event handler never re-checks that the commit it mutates actually belongs to the organization whose secret validated the signature — it looks up commits by SHA alone, across the entire Shipit installation. This breaks the binding "the organization that authenticated == the repository that is written," letting an actor who legitimately controls one configured GitHub organization's webhook secret forge a CI status for a commit belonging to a completely different, unrelated organization's stack, which can trigger an unauthorized automated deploy.

### Finding Description
`Shipit::WebhooksController#verify_signature` picks the `GitHubApp`/secret to validate against based on `repository_owner`, itself derived from the still-unverified JSON body: [1](#0-0) [2](#0-1) 

Shipit explicitly supports multiple independently-configured GitHub organizations, each with its own `app_id`/`installation_id`/`webhook_secret`, selected via `Shipit.github(organization:)`: [3](#0-2) [4](#0-3) 

Once the signature check passes (using the secret belonging to whichever org the attacker names in `repository.owner.login`), the full attacker-controlled payload is dispatched to handlers: [5](#0-4) 

The `status` handler, however, does not scope by repository/organization at all — it resolves commits purely by SHA across the whole database: [6](#0-5) 

Compare this to `PushHandler`, which at least scopes lookups through `Repository.from_github_repo_name(repository_name)` (itself independent from `repository_owner` used for signature selection, but at least a scoping attempt): [7](#0-6) [8](#0-7) 

`StatusHandler` has no such scoping. A commit matching the attacker-supplied `sha` in *any* org's repository will receive a forged status, and status creation directly drives continuous delivery: [9](#0-8) [10](#0-9) 

**Equality broken:** `organization whose secret validated the HMAC (repository.owner.login)` ≠ `organization/repository whose commit/stack is mutated (resolved purely by SHA, no owner check)`.

Before the attack: only GitHub's servers (or Shipit admins holding the specific org's secret) can post statuses for that org's commits; each org's webhook traffic is isolated by its own secret. After forging a `status` webhook signed with Org A's secret but naming a SHA that belongs to Org B's tracked repository, the handler happily creates a `Status` on Org B's commit/stack, since it never checks the org.

### Impact Explanation
If the targeted stack has `continuous_deployment: true` and relies on generic CI status reporting (rather than GitHub Checks) to gate deploys, a forged `success` status can flip `commit.deployable?` and trigger `ContinuousDeliveryJob`, causing `Stack#trigger_continuous_delivery` to deploy the commit automatically — an unauthorized deploy of another organization's stack, initiated entirely from within the attacker's own (less-trusted) organization's webhook channel. This matches the "unauthorized deploy" high/critical-impact category, and is a cross-organization/cross-repository write achieved without ever needing the target organization's webhook secret, GitHub App credentials, or a Shipit account.

### Likelihood Explanation
Requires the attacker to control (or know) the webhook secret of at least one organization configured in the same multi-tenant Shipit instance — a realistic scenario for a Shipit installation shared across multiple business units/orgs, each administering their own GitHub App integration. The target commit SHA is typically discoverable (commits/PRs are usually public or knowable to anyone tracking the target repo), and `Commit.where(sha:)` matching is by content only, not by any private secret. No changes to GitHub's platform behavior are required — this is purely a Shipit-side authorization gap.

### Recommendation
In `StatusHandler#process` (and any other handler lacking repository scoping), verify that `payload.dig('repository', 'full_name')` resolves to a repository/stack that matches `commit.stack.repository`, and reject/skip statuses where they don't match. More generally, `WebhooksController#verify_signature` should bind the verified organization to the specific repository being mutated for every handler (not just some), e.g. by passing the verified `repository_owner` into `Handler.call` and having each handler assert `commit.stack.repository.owner == verified_owner` before mutating state.

### Proof of Concept
1. Shipit is configured with two organizations, `org-a` and `org-b`, each with its own `webhook_secret` (per `config/secrets.development.example.yml` multi-org schema).
2. Attacker administers `org-a`'s GitHub App and therefore knows `org-a`'s `webhook_secret`.
3. Attacker observes a pending/undeployed commit SHA `abcd1234...` in `org-b/target-repo`, tracked by a Shipit stack with `continuous_deployment: true`.
4. Attacker POSTs to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "sha": "abcd1234...",
  "state": "success",
  "context": "ci/forged",
  "repository": { "owner": { "login": "org-a" }, "full_name": "org-a/unrelated-repo" }
}
```
signed with `org-a`'s `webhook_secret` in `X-Hub-Signature`.
5. `verify_signature` resolves `repository_owner` = `org-a`, fetches `org-a`'s `GitHubApp`, and the signature validates successfully (attacker legitimately knows this secret).
6. `Shipit::Webhooks.for_event('status')` dispatches to `StatusHandler`, which runs `Commit.where(sha: "abcd1234...")` — matching the `org-b/target-repo` commit regardless of the payload's `repository` fields — and creates a `success` `Status` on it.
7. `Status#schedule_continuous_delivery` fires `commit.schedule_continuous_delivery`, and if the commit becomes `deployable?`, `ContinuousDeliveryJob` deploys `org-b`'s stack — an unauthorized deploy triggered by an `org-a`-only actor.

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

**File:** config/secrets.development.example.yml (L18-38)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-27)
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
    end
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-27)
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
    end
  end
end
```

**File:** app/models/shipit/status.rb (L18-20)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

```

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```
