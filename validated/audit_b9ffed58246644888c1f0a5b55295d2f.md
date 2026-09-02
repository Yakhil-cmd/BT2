### Title
Signature verification keyed on `repository.owner.login` while event dispatch keys on `repository.full_name` allows cross-organization webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App (and therefore which `webhook_secret`) to validate an incoming webhook against using a field taken from the **same unauthenticated JSON body** it is trying to authenticate. The event handlers that actually act on the payload (e.g. `PushHandler`) resolve the target `Stack`/`Repository` using a **different** field from that same body. Because these two fields are never cross-checked, an attacker can pick a signature-verification path that trivially succeeds (an organization configured without a `webhook_secret`) while pointing the actual side-effect (`repository.full_name`) at a completely different, secret-protected organization's repository.

### Finding Description
- Signature verification org selection:
`app/controllers/shipit/webhooks_controller.rb` lines 24-30 and 59-62: [1](#0-0) [2](#0-1) 

`repository_owner` is read straight from the attacker-supplied JSON body (`params.dig('repository', 'owner', 'login')`), and that value is used to pick which `GitHubApp` instance (and thus which `webhook_secret`) `verify_webhook_signature` is checked against.

- Secret-less bypass path:
`lib/shipit/github_app.rb` lines 76-83: [3](#0-2) 

`verify_webhook_signature` returns `true` unconditionally `unless webhook_secret` is set. The engine explicitly supports multi-organization configs where some orgs have no `webhook_secret` configured — the shipped example file itself shows this as a valid state (`webhook_secret: # nil`): [4](#0-3) 

- Event/repository resolution used by handlers:
`app/models/shipit/webhooks/handlers/handler.rb` lines 32-38: [5](#0-4) 

`stacks` (and therefore which `Stack` gets `sync_github` called on it, per `PushHandler#process`) is resolved from `payload.dig('repository', 'full_name')`, not from `repository.owner.login`: [6](#0-5) 

**The binding broken:** the organization whose credential (`webhook_secret`) authenticated the request ≠ the repository whose state is written (`Stack#sync_github`, `Commit`/`Status` creation, etc.). Before an attacker's request, only requests signed with a given org's real `webhook_secret` should be able to mutate that org's stacks. After the crafted request — with `repository.owner.login` set to any org that has no `webhook_secret` configured, but `repository.full_name` set to a *different*, secret-protected org's repository — the signature check trivially passes while the handler still mutates the targeted repository's stacks.

### Impact Explanation
This allows an unauthenticated attacker to inject arbitrary `push`, `status`, or `check_suite` events for any repository/stack registered in the Shipit instance, as long as at least one configured GitHub organization has no `webhook_secret` set (a documented, supported configuration state for multi-org setups). This enables:
- Forcing `GithubSyncJob` to sync arbitrary commits into a target stack (`stack.sync_github`), influencing what Shipit believes is deployable.
- Forging `status`/`check_suite` events to mark CI as green on stacks that require CI (`ci.require`/`ci.blocking`), which combined with `continuous_deployment: true` stacks can trigger an unauthorized deploy without ever touching a real GitHub credential.

This lands in the High/Critical band described by the rules (unauthenticated read/write of stack state and, via CI-status forgery on CD-enabled stacks, an unauthorized deploy path).

### Likelihood Explanation
Requires no credentials, session, or `ApiClient` token — only that the Shipit instance is configured for multiple GitHub organizations (a documented and supported feature) and that at least one configured organization lacks a `webhook_secret` (also an explicitly supported/nil-able config value shown in the repo's own example secrets file). Given Shipit's own docs promote multi-org setups and treat `webhook_secret` as an optional per-org field, this is a realistic deployment configuration, not a theoretical one.

### Recommendation
Bind the signature-verification identity to the same repository the handler will act on: after verifying the HMAC signature, re-derive the acting organization from `repository.full_name` (or the resolved `Stack`/`Repository`'s known owner) and reject the request if it doesn't match the organization whose secret validated the signature. Alternatively, disallow `webhook_secret` from being blank/nil for any configured organization once multiple organizations are configured, so `verify_webhook_signature` can never trivially return `true`.

### Proof of Concept
1. Configure Shipit with two organizations in `secrets.yml`: `org-a` (no `webhook_secret`) and `org-b` (has a `webhook_secret`, `org-b` owns a tracked stack `org-b/app`).
2. POST to `/webhooks` (`WebhooksController#create`) with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker chosen sha>",
  "repository": { "owner": { "login": "org-a" }, "full_name": "org-b/app" }
}
```
No valid `X-Hub-Signature` is required because `repository_owner` resolves to `org-a`, whose `verify_webhook_signature` short-circuits to `true` (`lib/shipit/github_app.rb:77`).
3. `PushHandler#process` resolves the target stack via `repository.full_name` = `org-b/app` [7](#0-6)  and calls `stack.sync_github(expected_head_sha: params.after)`, mutating `org-b`'s stack despite the request never being validated against `org-b`'s secret.

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

**File:** config/secrets.development.shopify.yml (L5-14)
```yaml
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
