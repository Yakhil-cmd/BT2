### Title
Webhook signature verification authenticates a GitHub organization, but every event handler acts on an independent, unauthenticated `repository.full_name` field — (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`Shipit::WebhooksController#verify_signature` selects which `GithubApp`/secret to check the HMAC signature against using `repository_owner` (`params.dig('repository','owner','login')` or `params.dig('organization','login')`), then, once verified, hands the *entire raw payload* to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` unchanged. Every handler (`PushHandler`, `Handler#stacks`/`#repository_name`, the `PullRequest` handlers, etc.) independently re-reads `payload.dig('repository', 'full_name')` to decide which `Stack`/`Repository` to act on, with no check that this repository belongs to the same organization/owner that was used to select and validate the signature.

### Finding Description
The binding that should hold is: `organization authenticated by verify_signature == owner of the repository the handlers write to`. In `verify_signature`, the organization used to fetch the correct `GithubApp` config (and thus the HMAC secret to check) is derived from the payload itself: [1](#0-0) [2](#0-1) 

After verification passes, the raw `params` (the full untouched JSON body) is dispatched to every registered handler for the event: [3](#0-2) 

Handlers never re-derive or cross-check the organization that was authenticated; instead they independently pull the repository to act on straight from the same payload's `repository.full_name` field: [4](#0-3) [5](#0-4) 

Because `repository_owner` (used to pick the signing secret) and `repository.full_name` (used to pick the target `Stack`) are two *independent* JSON fields with no equality constraint enforced between them, an attacker who legitimately controls (or can trigger genuine GitHub webhook deliveries for) one organization/repository with a known-weak or intentionally-absent `webhook_secret` can submit a payload whose `repository.owner.login`/`organization.login` matches that organization (so `verify_signature` picks its — possibly disabled — secret check) while `repository.full_name` names a stack under a completely different, victim organization/repository configured in the same Shipit instance. `GithubApp#verify_webhook_signature` explicitly bypasses verification entirely when no secret is configured for the resolved organization: [6](#0-5) 

This is corroborated by the test fixtures showing multiple orgs configured on one instance where one organization's `webhook_secret` is `nil`: [7](#0-6) 

Once the payload passes the (possibly no-op) signature check for organization A, handlers such as `PushHandler#process` blindly trigger `stack.sync_github` for whatever stack matches `repository.full_name`, which can point to organization B's stack: [8](#0-7) 

This is the same class of bug as the ETH-refund report: the value that is checked/authorized (the organization tied to the verified signature) is never the same value that is subsequently acted upon (the `repository.full_name` a handler writes to), so downstream code trusts an unverified field as if it had been covered by the earlier check.

### Impact Explanation
If exploited, forged/unsigned webhook payloads can trigger `GithubSyncJob`, archive/unarchive review stacks, create teams/users via `membership_handler`, or update `Commit` statuses for a target organization's stack the attacker does not control — all without a valid signature for that target organization. This crosses the "unauthorized deploy/rollback" and "cross-repository writes" impact bar (High/Critical), since synced commits and statuses feed directly into `Stack#trigger_deploy`/continuous-deployment logic elsewhere in the engine.

### Likelihood Explanation
Exploitability is conditional on a specific, realistic misconfiguration: a Shipit instance hosting more than one GitHub organization where at least one has no `webhook_secret` configured (an explicitly supported configuration per `lib/shipit/github_app.rb`'s `return true unless webhook_secret` short-circuit, and reflected in the shipped test fixtures). Given multi-tenant Shipit deployments and that leaving `webhook_secret` blank is a documented, valid configuration state rather than an operator error the engine rejects, this is a realistic and low-effort attack path once such a configuration exists — the attacker only needs to POST a JSON body to `/webhooks` with a mismatched `repository`/`organization` pair, no privileged credentials required.

### Recommendation
Enforce the binding explicitly: after `verify_signature` resolves the authenticating `repository_owner`, require that every downstream handler's target repository (`payload.dig('repository','full_name')`'s owner) matches the same authenticated owner before any handler is allowed to act, rejecting (422) any payload where they diverge. Additionally, treat a missing `webhook_secret` as a configuration error that disables webhook ingestion for that organization rather than silently short-circuiting `verify_webhook_signature` to `true`.

### Proof of Concept
1. Configure a Shipit instance with two organizations: `AttackerOrg` (no `webhook_secret` set) and `VictimOrg` (has a stack, e.g. `victimorg/secret-repo`, tracked in Shipit).
2. POST to `/webhooks` with header `X-Github-Event: push` and no/garbage `X-Hub-Signature`, body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha already known to exist>",
  "repository": { "owner": { "login": "AttackerOrg" }, "full_name": "victimorg/secret-repo" }
}
```
3. `verify_signature` resolves `repository_owner` = `"AttackerOrg"`, fetches `AttackerOrg`'s `GithubApp` (no secret configured), and `verify_webhook_signature` returns `true` unconditionally (`lib/shipit/github_app.rb#L76-L77`), regardless of the actual (missing/invalid) signature.
4. `PushHandler#process` then looks up stacks via `Repository.from_github_repo_name("victimorg/secret-repo")` and calls `stack.sync_github`, triggering a real sync/deploy pipeline action against `VictimOrg`'s stack — an action the attacker was never authorized to perform.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```
