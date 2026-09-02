### Title
Webhook signature verification is bound to an attacker-supplied `repository.owner.login`, while event handlers act on unrelated fields (`repository.full_name`, or nothing at all) — breaking the "organization that authenticated" vs. "repository/commit that is written" binding - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which GitHub App (and thus which `webhook_secret`) is used to validate an inbound webhook's HMAC signature based on `params.dig('repository', 'owner', 'login')`, a field taken directly from the attacker-controlled JSON body itself. [1](#0-0) [2](#0-1) 

Once the signature "passes," the handler that actually mutates state does not re-derive or re-check that same `owner.login` value. `PushHandler`/`Handler#stacks` resolves the target repository from `payload.dig('repository', 'full_name')` — a completely independent field in the same JSON body, never covered by the check that selected the verifying secret. [3](#0-2) [4](#0-3) 

Worse, `StatusHandler#process` doesn't even use the repository at all — it matches purely by `sha` across the *entire* commits table, with no repository/stack scoping whatsoever: [5](#0-4) 

And crucially, `GitHubApp#verify_webhook_signature` silently returns `true` if the org selected for verification has no `webhook_secret` configured: [6](#0-5) 

This is shipped as the default in the repo's own sample configs (`webhook_secret: # nil`), so it is a realistic, in-scope deployment state, not an undocumented misconfiguration. [7](#0-6) 

### Finding Description
The binding that should hold is: **organization whose secret authenticated the request == organization/repository the handler acts on**. Before the fix this binding is violated:

- Attacker sends an unauthenticated POST to `/github/webhooks` (this endpoint requires no session, `ApiClient` token, or GitHub credentials — it is the public webhook intake point) with `X-Github-Event: status` (or `push`) and a crafted JSON body.
- `repository_owner` is read straight from the attacker's JSON: `params.dig('repository', 'owner', 'login')`. [2](#0-1) 
- `Shipit.github(organization: repository_owner)` looks up the corresponding `GitHubApp` config; if that org exists in `Shipit`'s multi-org config but has no `webhook_secret` set, `verify_webhook_signature` trivially returns `true` for *any* signature header, with no HMAC check performed at all. [8](#0-7) 
- The request now passes as "verified," and `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the full attacker-controlled body to the handler. [9](#0-8) 
- For `status` events, `StatusHandler#process` looks up commits **globally by `sha`**, with no reference to `repository.owner.login` or `repository.full_name` at all, letting the attacker mark any commit in any tracked stack/repository (belonging to any organization, including ones with a securely configured secret) with an arbitrary CI `state`, `description`, and `target_url`. [10](#0-9) 
- For `push` events, `PushHandler` resolves the target `Repository`/`Stack` via `repository.full_name`, a field independent of `repository.owner.login`, so the org that satisfied the (trivially-bypassed) signature check need not have any relationship to the repository actually synced. [11](#0-10) 

In short: the equality **`github_app_used_for_verification.organization == repository_actually_written.owner`** does not hold, because the first is taken from `repository.owner.login` and the second from `repository.full_name` (or ignored entirely), and the verification itself can be satisfied for free if the selected org has no secret configured.

### Impact Explanation
An unprivileged, unauthenticated attacker can inject forged GitHub `status` webhook events that flip the CI/commit status of arbitrary commits tracked by Shipit, across any stack/repository in the installation, as long as any single configured organization in `Shipit.github`'s multi-org config lacks a `webhook_secret` (a state the repo's own sample configuration ships with). Since deploy/merge gating in Shipit relies on commit statuses (`deployable_status`, `merge_status`), this enables marking unreviewed or malicious commits as "success," which can lead to unauthorized ships/merges — matching the "Critical: unauthorized deploy/merge" impact bar. It also allows forged `push` events to trigger `GithubSyncJob`/`sync_github` on repositories unrelated to the org that satisfied the (bypassed) signature check, an additional cross-repository write.

### Likelihood Explanation
Requires no credentials, no session, and no valid webhook secret — only that at least one organization entry in the Shipit multi-org GitHub config has no `webhook_secret` set (shown as the shipped default in `config/secrets.development.shopify.yml`), or that an attacker can otherwise cause the verification to select a "no-secret" org path. Given the code explicitly treats a missing secret as "verified," and the two identity checks (signature-selection org vs. handler-target repository/commit) are never reconciled, exploitation is straightforward once that condition holds.

### Recommendation
- Do not treat a missing `webhook_secret` as automatically verified; require an explicit, secure `webhook_secret` for every configured GitHub App, and reject (422) webhooks for orgs without one rather than accepting them.
- Bind the verified organization to the object actually mutated: after verifying the signature for `repository_owner`, ensure every handler re-derives the target repository from that same verified owner (or re-validates that `repository.full_name`'s owner segment matches `repository_owner`) before acting.
- Scope `StatusHandler#process` (and any other handler) to the repository identified in the verified payload rather than matching commits globally by `sha`.

### Proof of Concept
1. Deploy Shipit with a multi-org GitHub config where at least one org, e.g. `someothergithuborg`, has `webhook_secret` unset (as in the shipped `config/secrets.development.shopify.yml` template).
2. As an anonymous attacker, POST to `/github/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "repository": { "owner": { "login": "someothergithuborg" }, "full_name": "victim-org/victim-repo" },
  "sha": "<victim commit sha tracked in Shipit>",
  "state": "success",
  "context": "ci/forged",
  "created_at": "2026-09-01T00:00:00Z"
}
```
3. `verify_signature` selects `Shipit.github(organization: 'someothergithuborg')`; since its `webhook_secret` is blank, `verify_webhook_signature` returns `true` for any/no `X-Hub-Signature` header.
4. `StatusHandler#process` runs `Commit.where(sha: params.sha)` — matching the victim commit irrespective of `someothergithuborg` — and calls `create_status_from_github!`, forging a passing CI status on a commit belonging to an unrelated, properly-secured organization/repository.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-24)
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

**File:** config/secrets.development.shopify.yml (L9-9)
```yaml
    webhook_secret: # nil
```
