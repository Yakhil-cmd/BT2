## Analog Found

### Title
Webhook signature verification authenticates the organization key selection but never binds it to the repository the payload writes to - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
The `viewPrice`-class bug is a signature/verification-scope mismatch: a value used to gate/derive on-chain state is not the same value the verification actually covers. In Shipit, `WebhooksController#verify_signature` selects *which* GitHub App configuration (and its `webhook_secret`) to use for HMAC verification by reading `repository.owner.login` (or `organization.login`) straight out of the still-unverified JSON body, and then, once "verified", every downstream `Webhooks::Handlers::Handler` resolves the actual repository to mutate using a **different** field from the same body — `repository.full_name` — which is never re-checked against the organization that was used to select/validate the signature.

### Finding Description
`WebhooksController#verify_signature` picks the GitHub App/secret with: [1](#0-0) 
using [2](#0-1) 
i.e. `repository_owner` is read from the raw, attacker-suppliable JSON body *before* the signature has been validated. `Shipit.github(organization: repository_owner)` returns the `GithubApp` instance configured for that org, whose `verify_webhook_signature` is: [3](#0-2) 
Critically, `return true unless webhook_secret` — if the org resolved from the untrusted `repository.owner.login` field has no `webhook_secret` configured (a state the engine's own setup docs and templates present as a normal, supported option, e.g. `webhook_secret: # nil` in `config/secrets.development.example.yml:11` and `test/dummy/config/secrets_double_github_app.yml:7`), signature verification is bypassed entirely for that request.

Meanwhile, every handler resolves the repository/stack to act on independently, from a *different* JSON field that was never bound to the organization used above: [4](#0-3) 
`PushHandler`, `StatusHandler`, `MembershipHandler`, `CheckSuiteHandler`, and all `PullRequest::*Handler`s use `repository.full_name` (or `Repository.from_github_repo_name`) to look up stacks and mutate their commit/status/PR state, e.g.: [5](#0-4) 

So the equality the code relies on — `organization used to authenticate == organization owning the repository that gets written` — is never enforced. `repository.owner.login` gates which secret authenticates the request; `repository.full_name` decides which tracked stack (potentially under a completely different, unrelated organization) gets synced, has fake commit statuses recorded, or has PR/review-stack state mutated.

### Impact Explanation
Whenever any organization configured under `Shipit.github` has a blank/absent `webhook_secret` (an explicitly documented, valid configuration — see `docs/setup.md:30`: "Webhook secret (optional)"), an unauthenticated external attacker can `POST /webhooks` with a body claiming `repository.owner.login` equal to that unsecured org, while setting `repository.full_name` to any *other* repository/stack tracked by the Shipit instance. Because handlers key exclusively off `full_name`:
- `PushHandler` can be made to invoke `stack.sync_github(expected_head_sha: ...)` for an arbitrary tracked stack belonging to an unrelated org.
- `StatusHandler` can inject fabricated passing/failing commit statuses on real commits of an unrelated repository's stack, which can flip CI-gating used by continuous deployment (`required_statuses`/`continuous_deployment`) and precipitate an unauthorized deploy.
- `PullRequest` handlers can create/unarchive/archive review stacks and mutate PR label/state records for repositories the attacker has no access to.

This satisfies the High/Critical bar ("escalation into authorization", "unauthorized deploy") once the CI-status forgery path is chained into a continuous-deployment stack.

### Likelihood Explanation
Exploitability is fully gated on at least one configured GitHub organization lacking a `webhook_secret` — a state the engine's own templates/docs present as normal rather than as a misconfiguration to avoid. Given that, the attack requires no credentials at all: a bare, unauthenticated POST to the public `/webhooks` endpoint. Even outside that precondition, the structural defect remains: nothing in `WebhooksController` or `Handler` ever asserts that the organization used to select/verify the signature matches the organization implied by `repository.full_name`, so any future/alternate signature short-circuit (test/dev config, `Shipit.github` returning a permissive app, etc.) reopens the same cross-repository write path.

### Recommendation
- Do not allow `verify_webhook_signature` to silently return `true` when `webhook_secret` is blank in production; require a secret to be configured for every org, and fail closed by default.
- After verifying the signature, re-derive and enforce that `repository.full_name`'s owner matches the `repository_owner`/organization actually used to select the verifying secret before dispatching to any handler.

### Proof of Concept
1. Configure Shipit with two orgs, e.g. `OrgA` (no `webhook_secret` set) and `OrgB` (has a stack tracked, e.g. `OrgB/real-repo`).
2. As an unauthenticated attacker, POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha-already-known-to-exist-or-arbitrary>",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/real-repo" }
}
```
3. `WebhooksController#verify_signature` resolves `Shipit.github(organization: "OrgA")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` regardless of any (or missing) `X-Hub-Signature` header — see `app/controllers/shipit/webhooks_controller.rb:24-30` and `lib/shipit/github_app.rb:76-83`.
4. `PushHandler.call` runs against `OrgB/real-repo`'s stacks via `repository_name` (`app/models/shipit/webhooks/handlers/handler.rb:36-38`), triggering `stack.sync_github` for a repository/org the attacker never authenticated against.

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
