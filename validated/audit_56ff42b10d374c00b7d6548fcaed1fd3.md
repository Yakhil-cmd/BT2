### Title
Cross-organization webhook forgery via `repository.owner.login`/`repository.full_name` binding mismatch - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which organization's webhook secret to validate a payload against using `repository_owner`, derived from `params.dig('repository', 'owner', 'login')` (with an `organization.login` fallback) [1](#0-0) [2](#0-1) . The actual repository/stack that event handlers act on is resolved independently from `payload.dig('repository', 'full_name')` [3](#0-2) . Nothing ties these two fields together, so the field used to select the *verifying* HMAC secret is not the field that determines the *written* repository/stack — the same class of binding break described in the RocketPool report (a value used to authorize an operation is not the value actually verified).

### Finding Description
`Shipit.github(organization:)` looks up a per-organization config; if that organization has no `webhook_secret` configured, `GitHubApp#verify_webhook_signature` returns `true` unconditionally: `return true unless webhook_secret` [4](#0-3) . Shipit's own multi-organization test fixtures show this is a supported configuration shape — one organization ("OrgTwo") is configured with `webhook_secret: # nil` alongside another with a set secret [5](#0-4) .

Because `verify_signature` picks the app/secret using `repository.owner.login` (or `organization.login`) [6](#0-5) , while every downstream handler (`PushHandler`, `StatusHandler`, `Handler#stacks`) resolves the target `Stack`/`Repository` purely from `repository.full_name` [3](#0-2) [7](#0-6) , an attacker who knows (or controls) an organization without a configured `webhook_secret` can:
1. Set `repository.owner.login` = `<org-with-no-secret>` so `verify_webhook_signature` trivially returns `true` for any signature (or none at all — the header is attacker-supplied and not itself validated against a specific org other than by this lookup).
2. Set `repository.full_name` = `<victim-org>/<victim-repo>` for a Stack that belongs to a *different*, properly-secured organization.

The signature check passes (because it was checked against the unsecured org), but the handler acts on the victim organization's stack, triggering `stack.sync_github` / status writes / etc. as if GitHub itself sent the event. The equality this breaks is: `organization whose secret verified the payload == organization owning the repository the handler writes to`. Before the attack these are always equal for genuine GitHub-originated payloads (both fields come from the same real webhook body); after the attacker's crafted payload, they diverge, and the second field silently drives execution.

### Impact Explanation
This allows an unauthenticated external attacker to forge webhook events (`push`, `status`, `check_suite`, `membership`, pull_request family) for any stack/organization in the Shipit instance, as long as any one organization configured in `Shipit.github_organizations` lacks a `webhook_secret`. Consequences include: triggering `GithubSyncJob` for arbitrary branches/SHAs on victim stacks (`PushHandler#process`), injecting fabricated commit statuses (`StatusHandler`), or manipulating team membership (`MembershipHandler.find_or_create_team!`). This can lead to unauthorized deploy triggers or state corruption for stacks the attacker has no legitimate access to — meeting the "unauthorized deploy/rollback" bar in the High/Critical impact criteria, contingent on the described multi-organization/partial-secret configuration existing.

### Likelihood Explanation
Likelihood is conditional: it requires a deployment with more than one GitHub organization configured, where at least one configured organization has no `webhook_secret` set (a state the engine's own fixtures demonstrate as a valid, non-error configuration, not a misconfiguration the code rejects). Given that assumption, exploitation requires no credentials — only knowledge of the unsecured organization's name (which may be discoverable, e.g. via error messages, existing public integrations, or trial and error) and any target victim repo full_name.

### Recommendation
Cross-check that the organization used to select/verify the webhook secret matches the organization embedded in `repository.full_name` (and `organization.login`) before dispatching to handlers — i.e., derive a single canonical organization from the payload and reject/422 if `repository.owner.login`/`organization.login` disagrees with the owner portion of `repository.full_name`. Additionally, treat an organization with no configured `webhook_secret` as unable to authenticate any webhook for repositories it does not itself own, rather than allowing `verify_webhook_signature` to unconditionally succeed for it.

### Proof of Concept
1. Configure two organizations in `secrets.github`: `attacker-org` (no `webhook_secret`) and `victim-org` (has a `webhook_secret`, owns a Stack tracking `victim-org/secret-repo`).
2. POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/secret-repo" }
}
```
No valid `X-Hub-Signature` for `victim-org` is required — any value (or a signature computed against `attacker-org`'s known/empty secret) satisfies `verify_signature` because `GitHubApp#verify_webhook_signature` short-circuits to `true` when `attacker-org`'s `webhook_secret` is blank.
3. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("victim-org/secret-repo")` and enqueues `GithubSyncJob` for the victim stack, despite the payload never being validated by `victim-org`'s secret.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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
