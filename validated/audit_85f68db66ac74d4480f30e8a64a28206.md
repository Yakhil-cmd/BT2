### Title
Signature-verified GitHub organization is never cross-checked against the repository the webhook payload actually acts on - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` derives the *organization* used to select the HMAC secret from `params.dig('repository','owner','login')` (falling back to `params.dig('organization','login')`), and validates the signature against that organization's configured `webhook_secret`. However, the handlers that actually act on the payload (e.g. `PushHandler`) locate the target `Stack`/`Repository` using an entirely different field of the same JSON body: `payload.dig('repository', 'full_name')` (`app/models/shipit/webhooks/handlers/handler.rb:36-38`). Nothing ties these two fields together, so the organization whose secret authenticated the request is never proven to be the owner of the repository the handler subsequently mutates.

### Finding Description
The signature check:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

selects which org's secret to verify with purely from `repository.owner.login` (or `organization.login`). Once verification passes, the full raw JSON `params` is handed unfiltered to every registered handler:
```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
  head(:ok)
end
``` [2](#0-1) 

`PushHandler` (and every other handler) resolves the affected `Stack` via `Handler#repository_name`, which reads a *different* payload key, `repository.full_name`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [3](#0-2) [4](#0-3) 

Because `repository.owner.login` (used for auth) and `repository.full_name` (used for the write) are two independent, attacker-controllable fields in the same JSON body, the code never enforces the equality `repository.owner.login == repository.full_name.split('/').first`. On a genuine GitHub-originated webhook these two values always agree, but the controller does not require or verify that agreement — it is purely incidental. This is the same class of defect as the Niftyswap "Blue Dragons" report: a value that is supposed to gate a downstream effect (the signing organization) is not actually the value the downstream effect operates on (the target repository/stack), and no invariant links them.

The gate is further weakened by `GitHubApp#verify_webhook_signature`:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [5](#0-4) 
`webhook_secret` is explicitly documented as optional per organization (`docs/setup.md:30`), so any organization configured on a multi-tenant Shipit instance (see `test/dummy/config/secrets_double_github_app.yml` for the supported multi-org config shape) without a secret set causes `verify_signature` to accept **any** payload attributed to that organization, with no signature at all.

### Impact Explanation
Combining the two facts:
1. If any configured GitHub organization on the Shipit instance has no `webhook_secret` set (an explicitly supported, documented configuration), signature verification is a no-op for payloads declaring `repository.owner.login` (or `organization.login`) equal to that org.
2. The handler that performs the actual side effect (`PushHandler#stacks`) keys off `repository.full_name`, an unrelated field with no cross-check to `repository.owner.login`.

An unauthenticated network attacker can therefore POST to `/webhooks` with `X-Github-Event: push`, `repository: {owner: {login: "<org-without-secret>"}, full_name: "<victim-org>/<victim-repo>"}`, `ref`, and `after` set to an arbitrary/real commit SHA. This passes `verify_signature` trivially and reaches `PushHandler#process`, which calls `stack.sync_github(expected_head_sha: params.after)` on the victim's stack (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`), enqueuing `GithubSyncJob` against the real, unrelated `victim-org/victim-repo` stack. This lets the attacker force out-of-band GitHub syncs (and, where continuous delivery is enabled, out-of-band deploy triggers) against a stack whose real GitHub organization/webhook is entirely different from the one whose (missing) secret the attacker exploited — an unauthorized deploy trigger and a cross-repository/cross-organization write, matching the "Critical: unauthorized deploy" and "cross-repository writes" impact classes.

### Likelihood Explanation
Requires: (a) the Shipit deployment tracks at least two GitHub organizations/apps (an explicitly supported multi-tenant configuration), and (b) at least one of those organizations has no `webhook_secret` configured (explicitly documented as optional). Given both, the exploit requires no credentials, no repository access, and no session — a single unauthenticated HTTP POST. Likelihood is conditional on deployment configuration rather than universal, but the vulnerable configuration is a documented, supported setup, not a misuse of the engine.

### Recommendation
- Require `repository.owner.login` (or `organization.login`) to exactly match the owner segment of `repository.full_name` before any handler processes the payload, and reject the request otherwise.
- Do not allow `verify_webhook_signature` to return `true` when `webhook_secret` is blank; require an explicit "no verification" opt-in per organization rather than silently defaulting to unauthenticated acceptance.
- Alternatively, verify the payload's `repository.owner.login` against the repository actually resolved by `Repository.from_github_repo_name(repository.full_name)` and reject on mismatch.

### Proof of Concept
Assume Shipit is configured with two orgs, `OrgWithoutSecret` (no `webhook_secret`, e.g., matching `test/dummy/config/secrets.yml` where `webhook_secret:` is nil) and `VictimOrg/victim-repo` tracked as a Stack.

```
POST /webhooks
X-Github-Event: push
Content-Type: application/json

{
  "ref": "refs/heads/master",
  "after": "<real-existing-victim-repo-sha>",
  "repository": {
    "owner": { "login": "OrgWithoutSecret" },
    "full_name": "VictimOrg/victim-repo"
  }
}
```
- `repository_owner` resolves to `"OrgWithoutSecret"` → `Shipit.github(organization: "OrgWithoutSecret").verify_webhook_signature` returns `true` unconditionally because `webhook_secret` is blank (`lib/shipit/github_app.rb:76-77`), regardless of the (absent/garbage) `X-Hub-Signature` header.
- `PushHandler#stacks` resolves `Repository.from_github_repo_name("VictimOrg/victim-repo")` (`app/models/shipit/webhooks/handlers/handler.rb:36-38`) and calls `stack.sync_github(expected_head_sha: ...)` on the victim's stack, exactly as in the legitimate flow tested in `test/controllers/webhooks_controller_test.rb:23-32`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```
