## Title
Webhook signature binds to the wrong field — `repository.owner.login` is authenticated but `repository.full_name` is the value used to select the stack that gets written to - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App/secret to verify an inbound webhook's HMAC signature against using `repository_owner`, computed from `params.dig('repository', 'owner', 'login')` (or `organization.login`). Once verification passes, the payload is dispatched unchanged to event handlers (e.g. `PushHandler`), which resolve the target `Stack`/`Repository` using a **different** field: `payload.dig('repository', 'full_name')`. These two fields are never cross-checked against each other.

### Finding Description [1](#0-0) verifies the signature using only the organization derived from `repository_owner`: [2](#0-1) 

The signature check itself is a no-op whenever the resolved GitHub App config has no `webhook_secret` set: [3](#0-2) 

Meanwhile, every default event handler (e.g. `PushHandler`) resolves the actual write target purely from `repository.full_name`, via the shared base class: [4](#0-3) [5](#0-4) 

`Repository.from_github_repo_name` splits `full_name` on `/` to find the target repository/stack independently of whatever value was used for `repository_owner`: [6](#0-5) 

So the equality the engine actually enforces is: *"the sender knows a valid signature (or targets an org configured with no secret) for `repository.owner.login`"* — but the equality it should enforce for a legitimate event is: *"the sender is authorized for the org owning `repository.full_name`."* These are never the same field, and the controller never asserts `repository.owner.login == full_name.split('/').first`.

### Impact Explanation
For any GitHub App organization configured in `Shipit.github` with a blank/absent `webhook_secret` (a state the code explicitly permits — `return true unless webhook_secret`), an unauthenticated attacker can craft a webhook body where `repository.owner.login` is set to that secret-less org (so `verify_signature` trivially passes) while `repository.full_name` names an entirely unrelated, secret-protected repository/stack. The forged event is then routed to real handlers (`push`, `status`, `check_suite`, `membership`, `pull_request`, etc.) acting on that unrelated stack — e.g. triggering `GithubSyncJob` with an attacker-chosen `expected_head_sha`, injecting forged commit `Status` records that CI-gating merge/deploy logic relies on, or manipulating `Team`/`Membership` records for `Shipit.github_teams`-based authorization. This crosses the "organization that authenticated versus the repository that is written" trust boundary called out in scope, and can escalate into unauthorized sync/deploy-adjacent state changes and forged commit statuses that feed deploy-gating decisions.

### Likelihood Explanation
No credentials, session, or `ApiClient` token are required — the webhook endpoint is unauthenticated by design (`skip_before_action :verify_authenticity_token`), and the only requirement is that at least one configured GitHub org lacks a `webhook_secret` (a state the templates/docs present as optional, not enforced-mandatory). Any host running with a mixed/partial secrets configuration is exposed.

### Recommendation
In `WebhooksController#verify_signature`, after verifying the signature, additionally assert that the owner segment of `repository.full_name` (and/or `organization.login`) matches the `repository_owner` used to select the GitHub App/secret; reject the request (`head 422`) on mismatch. Consider also making `webhook_secret` mandatory for all configured GitHub App organizations rather than allowing a bypass when absent.

### Proof of Concept
1. Configure two orgs in `Shipit.github`: `org-no-secret` (no `webhook_secret`) and `victim-org` (protected repo/stack exists for `victim-org/app`).
2. POST to `/github/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeef",
  "repository": { "owner": { "login": "org-no-secret" }, "full_name": "victim-org/app" }
}
```
No `X-Hub-Signature` header, or any arbitrary value, is required since `Shipit.github(organization: "org-no-secret").verify_webhook_signature` short-circuits to `true`.
3. `verify_signature` passes; `PushHandler` resolves `Repository.from_github_repo_name("victim-org/app")` and enqueues `GithubSyncJob` for `victim-org`'s stack, even though the request was never authenticated for `victim-org`.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
