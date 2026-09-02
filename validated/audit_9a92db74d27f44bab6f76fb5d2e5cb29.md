This confirms the vulnerability chain. Let me verify one more piece — `sync_github` and `stack.github_api` to confirm the impact scope.### Title
Cross-Organization Webhook Forgery via Organization/Repository Binding Mismatch in Signature Verification - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate a GitHub webhook against by reading `repository.owner.login` (or `organization.login`) directly out of the *same* untrusted, attacker-suppliable JSON body it is trying to authenticate, then hands the *entire* parsed body to event handlers which independently resolve the target repository/stack from a different field (`repository.full_name`). Because the field used to pick the trusted secret is not bound to the field used to select which repository is acted upon, a party who knows the `webhook_secret` for *one* organization configured in this Shipit instance can forge a validly-signed webhook that manipulates state belonging to a *different* organization's repository/stack.

### Finding Description
`verify_signature` computes which organization's app/secret to trust like this: [1](#0-0) 

`repository_owner` is read straight from the request body: [2](#0-1) 

The HMAC is then verified with `Shipit.github(organization: repository_owner)`'s `webhook_secret`, but the signature itself covers the raw POST body verbatim — it does not bind the "owner" field to the "repository being written" — those are two independent JSON keys that an attacker fully controls before signing: [3](#0-2) 

Once the signature check passes (using the secret for whichever `repository.owner.login` value the attacker chose), the full parsed payload is dispatched to handlers unmodified: [4](#0-3) 

Handlers, however, resolve the actual target repository from an entirely different field, `repository.full_name`, via `Repository.from_github_repo_name`: [5](#0-4) [6](#0-5) 

Concretely, for a `push` event, `PushHandler#process` finds all stacks of the resolved repository/branch and triggers a GitHub sync using an attacker-chosen `after` sha: [7](#0-6) 

**The broken binding (as an equality):** `organization authenticated by verify_signature (repository.owner.login)` should equal `organization that owns the repository actually written by handlers (repository.full_name)`. Nothing in the controller or `Handler` enforces this. An attacker who is a legitimate GitHub App administrator for Organization A (and therefore knows or controls Org A's `webhook_secret`, configured per-org in `secrets.github` for multi-org installs — see `Shipit.github_app_config`) can post a webhook body where `repository.owner.login = "org-a"` (so the signature validates against Org A's secret) while `repository.full_name = "org-b/victim-repo"`. The request passes `verify_signature`, and the handler acts on Org B's tracked stack.

### Impact Explanation
This crosses a repository/organization authentication boundary that Shipit is explicitly designed to enforce (multi-organization GitHub App configs each with a distinct `webhook_secret`, meant to isolate tenants). An attacker controlling one organization's webhook credentials can forge signed events (`push`, `status`, `check_suite`, `pull_request`, `membership`, etc.) against any other tracked repository/stack in the same Shipit instance, causing unauthorized cross-repository writes: creating commit statuses, enqueuing `GithubSyncJob`/`RefreshCheckRunsJob` for a victim stack, auto-provisioning review stacks (`OpenedHandler`) on a victim repository, or adding/removing arbitrary GitHub users to/from `Shipit::Team`s via `MembershipHandler` (which in turn affects `Shipit.github_teams` authorization checks in `User#authorized?`). This matches the "cross-repository writes" / "escalation into `Shipit.github_teams` authorization" impact tier.

### Likelihood Explanation
Requires the attacker to be a legitimate operator of at least one organization configured in this Shipit deployment's multi-org GitHub App setup (i.e., knows/controls that org's webhook secret) — this is a realistic "unprivileged relative to the victim org" attacker in any Shipit instance serving multiple organizations, and does not require a Shipit session, API token, or any Shipit-side credential. No other check ties the signing organization to the resource being mutated.

### Recommendation
After verifying the signature, re-derive/require the trusted organization from a value cryptographically tied to the secret used (e.g., the GitHub App installation associated with that organization/secret), and reject the payload if `repository.full_name`'s owner does not match the organization whose secret validated the signature. At minimum, compare `repository_owner` against the owner portion of `repository.full_name` (and `organization.login` for org-level events) before dispatching to handlers.

### Proof of Concept
1. Shipit is configured with two GitHub App organizations, `org-a` and `org-b`, each with its own `webhook_secret` (`lib/shipit/github_app.rb`).
2. Attacker administers `org-a`'s GitHub App and knows `org-a`'s `webhook_secret`.
3. Attacker POSTs to `/github/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "org-a" },
    "full_name": "org-b/victim-repo"
  }
}
```
   signed with `sha1=HMAC(org-a-webhook-secret, body)` in `X-Hub-Signature`.
4. `verify_signature` calls `Shipit.github(organization: "org-a")` and validates successfully against the attacker-known secret.
5. `PushHandler` resolves `Repository.from_github_repo_name("org-b/victim-repo")` and triggers `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on Org B's stack — a cross-organization write the attacker was never authorized to perform.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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
