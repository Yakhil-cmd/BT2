Confirmed: the sync/dispatch path for `push` and other events resolves the target purely from `repository.full_name` inside the JSON body, e.g. `Handler#repository_name` reading `payload.dig('repository', 'full_name')` [1](#0-0) , while the signature check that gates the whole request selects which org's secret to verify against using `params.dig('repository', 'owner', 'login')` [2](#0-1) [3](#0-2) . `verify_webhook_signature` returns `true` unconditionally whenever no `webhook_secret` is configured for that org [4](#0-3) , and the setup docs/fixtures explicitly show `webhook_secret` as an optional, often-nil per-organization field in a multi-org config [5](#0-4) .

### Title
Webhook signature is validated against an attacker-chosen organization while the mutated repository/stack is selected from an unrelated field in the same unauthenticated payload - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
### Finding Description
`WebhooksController#verify_signature` picks which GitHub App configuration (and therefore which `webhook_secret`) to check the `X-Hub-Signature` against using `repository_owner`, computed as `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [3](#0-2) . This value comes straight from the raw, attacker-controlled JSON body of an unauthenticated POST to `/github/webhooks` (the request is unauthenticated by design — that's the whole point of HMAC signing) [6](#0-5) .

`GitHubApp#verify_webhook_signature` treats a missing `webhook_secret` as automatic success: `return true unless webhook_secret` [4](#0-3) . Shipit is explicitly designed to host multiple organizations side by side, each with independently optional `webhook_secret` (`webhook_secret: # nil` is shown as a valid/expected default in the example config) [5](#0-4) .

Once `verify_signature` passes, the very same untrusted payload is dispatched to handlers, none of which re-check the organization used for authentication — they instead resolve the target repository purely from `payload.dig('repository', 'full_name')` [1](#0-0) . `repository.owner.login` (used for signature-org selection) and `repository.full_name` (used for target-stack selection) are two independent, attacker-supplied strings within the same forged JSON body — nothing enforces that `full_name`'s owner matches `owner.login`.

This breaks the intended binding: `organization whose secret authenticated the request == organization whose repository/stack is mutated`. An attacker only needs one organization in the Shipit installation to have no `webhook_secret` configured (common for smaller/less-critical orgs, or during initial onboarding as the docs' own template shows) to forge signature-valid webhook events (`push`, `pull_request`, `membership`, etc.) that mutate stacks belonging to a *different, properly-secured* organization, simply by setting `repository.owner.login` to the org lacking a secret while setting `repository.full_name` to `other-org/other-repo`.

### Impact Explanation
Concretely, with `PushHandler`, an attacker can enqueue `stack.sync_github(expected_head_sha: ...)` for any stack under `other-org/other-repo` by forging a `push` payload whose `repository.owner.login` names the unsecured org and whose `repository.full_name`/`ref`/`after` name the victim stack/branch/sha [7](#0-6) . `sync_github` re-syncs Shipit's view of the repository state (fetches commits/CI status) using the app's own GitHub credentials for that stack, and other event types (`membership`, `pull_request` opened/labeled/closed handlers, etc.) similarly act on the org resolved from `repository.full_name` without re-validating it against the authenticating org [8](#0-7) . This can desynchronize a victim stack's commit/CI state, spuriously (un)archive review stacks, or add/remove team memberships tied to a victim organization — state that subsequently feeds Shipit's own deploy-eligibility and merge-queue logic (`Commit#deployable?`, `MergeRequest#reject_unless_mergeable!`), potentially enabling downstream unauthorized ship/merge decisions to be based on attacker-forged CI/webhook state.

### Likelihood Explanation
Exploitability requires only: (a) a public-facing Shipit instance hosting at least two GitHub organizations, and (b) at least one of those organizations not having configured a `webhook_secret` (explicitly supported/expected by the codebase and setup docs as a valid, "public" configuration). No credentials, session, or API token of any kind are needed — the webhook endpoint is intentionally unauthenticated and reachable by anyone who can send an HTTP POST.

### Recommendation
Cross-check the organization used to select/verify the webhook secret against the organization implied by `repository.full_name` (or `organization.login`) before dispatching to handlers, and reject the request if they don't match. Additionally, consider refusing to treat a webhook as verified when `webhook_secret` is unset for any org that isn't explicitly marked public/untrusted, rather than defaulting to `true`.

### Proof of Concept
1. Configure Shipit with two orgs: `secured-org` (has `webhook_secret`) hosting the victim stack `secured-org/app`, and `open-org` (no `webhook_secret` configured).
2. POST to `/github/webhooks` with header `X-Github-Event: push` and no valid `X-Hub-Signature` for `secured-org`, but a JSON body:
```json
{
  "ref": "refs/heads/production",
  "after": "<attacker-chosen-sha>",
  "repository": { "owner": { "login": "open-org" }, "full_name": "secured-org/app" }
}
```
3. `verify_signature` resolves `repository_owner` = `"open-org"`, finds no `webhook_secret` for it, and `verify_webhook_signature` returns `true` unconditionally [4](#0-3) .
4. `PushHandler` resolves the target stack via `repository.full_name` = `"secured-org/app"` and triggers `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on the victim stack [9](#0-8) , despite the request never having been authenticated against `secured-org`'s secret.

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L4-9)
```ruby
  class WebhooksController < ActionController::Base
    skip_before_action :verify_authenticity_token, raise: false
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature

    respond_to :json

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-54)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
