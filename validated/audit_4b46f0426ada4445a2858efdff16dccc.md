### Title
Webhook signature is verified against the organization named in an unverified payload field, letting any onboarded organization's webhook secret authenticate pushes/events for a *different* organization's repositories - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to validate the HMAC against by reading `repository_owner` straight out of the untrusted, not-yet-verified JSON body, then dispatches the event to handlers that independently trust `repository.full_name` (also read from the same untrusted body) to resolve the target `Repository`/`Stack`. Because these two lookups are decoupled, an attacker who legitimately controls the webhook secret for *organization A* (e.g., they administer another GitHub org that is also configured in this multi-org Shipit instance) can forge a signed payload whose `repository.owner.login` is `A` (so the HMAC check passes using A's secret) while `repository.full_name` names a repository belonging to *organization B*, causing `Handler#stacks`/`Repository.from_github_repo_name` to act on B's stack.

### Finding Description
`verify_signature` computes `repository_owner` from the payload and uses it purely to pick which secret to check the signature with: [1](#0-0) [2](#0-1) 

The HMAC itself only proves the request was signed with *some* organization's `webhook_secret` known to Shipit — it does not bind the signature to any specific `repository.full_name` value, since `verify_webhook_signature` just recomputes an HMAC over the raw body using the secret for whatever organization the attacker declared in `repository_owner`: [3](#0-2) 

Once verification passes, `WebhooksController#create` dispatches the same raw payload to handlers: [4](#0-3) 

Handlers resolve the target stacks using `repository.full_name` from that same payload, with no re-check that this repository belongs to the organization whose secret validated the signature: [5](#0-4) [6](#0-5) 

Concretely, `PushHandler` uses `stacks` (derived from `repository.full_name`) to call `stack.sync_github(expected_head_sha: params.after)`, and other handlers (pull request, membership, etc.) behave the same way: [7](#0-6) 

This is the same trust-binding break as the report's analog: the value used to authenticate (`repository_owner`, i.e., the organization whose secret validated the HMAC) is not the value actually acted upon (`repository.full_name`, i.e., the repository/stack that receives the mutation).

### Impact Explanation
In a Shipit deployment onboarding more than one GitHub organization (each with its own `webhook_secret`), any org administrator who can generate a valid signature for their own org can forge webhook events (push, pull_request, membership, status, check_suite, etc.) that are attributed to and acted upon a **different** organization's repositories/stacks. This can trigger unintended deploy syncs (`stack.sync_github`), archive/unarchive stacks, mutate PR-driven review stacks, or add/remove team memberships tied to another organization — a cross-repository/cross-organization write performed without ever compromising that target organization's own webhook secret.

### Likelihood Explanation
Requires the attacker to already have webhook-secret-level access to *any one* organization configured in the same Shipit instance, which is the only credential in the trust model that this analog crosses (a boundary explicitly allowed by the rules — the attacker never needs the *target* org's secret, a Shipit session, an `ApiClient` token, or GitHub write access to the victim repo). Any single-organization Shipit deployment is unaffected; this only manifests in the documented multi-organization configuration path (`Shipit.github(organization:)` scoping described in `docs/setup.md`).

### Recommendation
After successfully verifying the HMAC signature, re-derive and enforce that `repository.full_name`'s owner matches the `repository_owner` (or `organization.login`) that was actually used to validate the signature, rejecting the webhook (422) on mismatch, before any handler resolves stacks from `repository.full_name`.

### Proof of Concept
1. Shipit instance is configured with two organizations, `org-a` and `org-b`, each with its own `github.webhook_secret` (per `docs/setup.md` multi-org setup and `Shipit.github(organization:)`).
2. Attacker legitimately knows `org-a`'s webhook secret (e.g., they are an admin of `org-a`'s GitHub App installation).
3. Attacker crafts a push payload: `{"repository": {"owner": {"login": "org-a"}, "full_name": "org-b/victim-repo"}, "ref": "refs/heads/main", "after": "<attacker-chosen sha>"}`.
4. Attacker signs the raw body with `org-a`'s secret and sends it as `X-Hub-Signature` to `/webhooks`.
5. `verify_signature` computes `repository_owner` = `"org-a"`, fetches `Shipit.github(organization: "org-a")`, and successfully verifies the signature against the attacker-known secret — `app/controllers/shipit/webhooks_controller.rb` lines 24-30, 59-62.
6. `PushHandler` resolves `repository_name` = `"org-b/victim-repo"` (from `repository.full_name`) and calls `stack.sync_github(expected_head_sha: <attacker sha>)` on `org-b`'s stacks — `app/models/shipit/webhooks/handlers/handler.rb` lines 32-38, `app/models/shipit/webhooks/handlers/push_handler.rb` lines 12-17 — even though the signature was never validated against `org-b`'s secret.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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
