### Title
Webhook signature is verified against the GitHub App selected by `repository.owner.login`, but the repository actually acted upon is selected independently from `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks *which* GitHub App / `webhook_secret` to verify the HMAC signature against using `repository_owner`, a value read straight out of the unauthenticated JSON body (`repository.owner.login`, falling back to `organization.login`). The repository that is actually mutated by the event handlers, however, is picked independently, via `Handler#repository_name`, which reads `repository.full_name` from the same body. These two fields are not required to agree, so the "organization that authenticated" and the "repository that is written" are two different, attacker-controlled lookups over the same untrusted payload.

### Finding Description
`verify_signature` resolves the GitHub App config solely from `repository_owner`: [1](#0-0) [2](#0-1) 

The chosen app's secret is used in `verify_webhook_signature`, which explicitly treats an app with **no configured secret as always verified**: [3](#0-2) 

Once the signature check passes, the same raw JSON body is dispatched to handlers, but the handlers resolve the target `Repository`/`Stack` from a *different* field, `repository.full_name`, completely independent of `repository_owner`: [4](#0-3) [5](#0-4) 

The `PushHandler`, for example, uses that resolved `stacks` scope to enqueue a sync for whatever repository `repository.full_name` names, using attacker-supplied `after`/`ref` values: [6](#0-5) 

Root cause / broken equality: the engine assumes `organization_that_authenticated == organization_owning_repository_written`, but nothing enforces `repository.owner.login == repository.full_name.split('/').first`. If a Shipit deployment is configured with `Shipit.github(organization: ...)` for multiple GitHub orgs (as supported per `test/dummy/config/secrets_double_github_app.yml`), and any one of them has no `webhook_secret` set (or has a secret the attacker can otherwise obtain, e.g. a personal/testing org), an attacker can:

1. Send a webhook with `repository.owner.login` = "attacker-controlled-or-secretless-org" (so `verify_signature` selects that org's app, whose missing secret makes `verify_webhook_signature` return `true` unconditionally).
2. Set `repository.full_name` = "victim-org/protected-repo", i.e. a real, tracked `Repository`/`Stack` belonging to a *different*, properly secured GitHub App/org.
3. Because `Handler#repository_name` only reads `repository.full_name`, the handler resolves and acts on the victim stack, even though the signature was never checked against the victim org's secret.

### Impact Explanation
This breaks the deployment-trust binding "organization authenticated == repository written." Any handler that trusts payload content for a tracked stack (e.g. `PushHandler` triggering `GithubSyncJob`, or handlers that record commit statuses used by Shipit's deployable/merge status pipeline) can be invoked against a victim repository without ever passing signature verification tied to that repository's own GitHub App/secret. Depending on which handler is reached this can range from forcing spurious syncs to injecting attacker-chosen commit state that Shipit's automatic deploy/merge logic consumes — i.e. an unauthorized deploy path — which falls under the Critical impact category (unauthorized deploy).

### Likelihood Explanation
Exploitability requires a multi-organization Shipit deployment where at least one configured GitHub App organization has no `webhook_secret` (or one otherwise known to the attacker) while another organization's repositories are the intended target. This is a supported and documented configuration (multiple `github_apps`/orgs), not a hypothetical, so the precondition is realistic for larger deployments, though it does depend on operator configuration of a secretless/attacker-reachable organization entry.

### Recommendation
Do not select the verification key from an attacker-controlled field that is disjoint from the field that determines the acted-upon repository. Either:
- Verify the signature using the `webhook_secret` belonging to the organization actually owning `repository.full_name` (not `repository.owner.login`/`organization.login` picked independently), or
- Reject the webhook if `repository.owner.login` does not match the owner segment of `repository.full_name`, or
- Disallow `verify_webhook_signature` from returning `true` when no secret is configured for a live GitHub App (fail closed instead of open).

### Proof of Concept
1. Configure two GitHub App orgs in Shipit config: `victim-org` (has `webhook_secret` set, owns tracked stack `victim-org/protected-repo`) and `attacker-org` (no `webhook_secret` configured).
2. POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "full_name": "victim-org/protected-repo",
    "owner": { "login": "attacker-org" }
  }
}
```
3. `verify_signature` calls `Shipit.github(organization: "attacker-org")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` regardless of the (missing/garbage) `X-Hub-Signature` header. [7](#0-6) 
4. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("victim-org/protected-repo")`, unrelated to "attacker-org", and enqueues `GithubSyncJob` for the victim stack with the attacker-supplied `after` SHA. [8](#0-7)

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
