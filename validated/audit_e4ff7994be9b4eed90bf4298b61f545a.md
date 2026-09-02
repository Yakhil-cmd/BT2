This confirms the exploit path: `Handler#stacks` and `PushHandler#process` locate the target `Repository`/`Stack` purely from `payload.dig('repository', 'full_name')`, an independent JSON field from `repository.owner.login`/`organization.login`, which is what `WebhooksController#repository_owner` uses to select the signing/verification key.

### Title
Webhook signature is verified against a JSON field independent of the repository/stack that is actually mutated - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which `GitHubApp` (and thus which `webhook_secret`) to validate the inbound signature against using `repository_owner`, derived from the attacker-controlled JSON body: `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [1](#0-0) . However, the event handlers that actually mutate state (`PushHandler`, `StatusHandler`, etc.) resolve the target `Repository`/`Stack` from a *different* field of the same payload: `payload.dig('repository', 'full_name')` [2](#0-1) . These two fields are never cross-validated against each other, and only the raw signature bytes are checked — not which organization's key was chosen relative to which repository is targeted.

### Finding Description
`Shipit.github(organization: repository_owner)` looks up per-organization config, and `GitHubApp#verify_webhook_signature` returns `true` unconditionally whenever that organization's `webhook_secret` is blank/unset: `return true unless webhook_secret` [3](#0-2) . Shipit explicitly documents `webhook_secret` as optional/nilable, including in multi-organization setups (`webhook_secret: # nil`) [4](#0-3)  and in `docs/setup.md`'s "Using Multiple Github Applications" section.

Because `repository_owner` and `repository.full_name` are independent JSON keys under attacker control (the `/webhooks` endpoint has no authentication of its own — `webhooks_controller.rb` only performs `skip_before_action :verify_authenticity_token` and `verify_signature`), an attacker can send a payload where:
- `repository.owner.login` = an organization configured *without* a `webhook_secret` (so signature check is bypassed unconditionally), and
- `repository.full_name` = `"<victim-org>/<victim-repo>"`, a completely different, tracked repository that *does* have its own secret configured.

`verify_signature` only ever checks the signature against the org picked from `repository.owner.login`/`organization.login`; it never confirms that this org matches the owner embedded in `repository.full_name` used later by the handler. The binding broken is: **organization authenticated (`repository_owner` → selected `GitHubApp`/secret) ≠ repository that is written (`repository.full_name` → `Stack`/`Repository` resolved by `Handler#stacks`)**.

### Impact Explanation
This allows an unauthenticated, unprivileged attacker to forge GitHub webhook events (push, status, check_suite, membership, pull_request, etc.) for any tracked repository/stack, as long as any single organization in the multi-org configuration lacks a `webhook_secret`. Concretely with `PushHandler`, this triggers `stack.sync_github(expected_head_sha:)` for the victim stack [5](#0-4) , and with `StatusHandler` it forges commit statuses used to gate merges/deploys [6](#0-5) . Forged/manipulated commit statuses can influence merge-queue and deploy gating decisions on a stack the attacker does not control, which can lead to an unauthorized deploy/merge outcome — matching the "High" impact bucket (escalation/unauthenticated write into stack state).

### Likelihood Explanation
Requires only that the deployment has **more than one** GitHub organization configured (a documented, supported configuration) and that at least one configured organization omits `webhook_secret` (also documented as optional/nilable, and shown as `# nil` in the example configs). This is a realistic misconfiguration for the multi-org feature, not a code path requiring a session, token, or app private key — it is reachable by any anonymous internet client that can POST to `/webhooks`.

### Recommendation
In `WebhooksController#verify_signature`, after determining the `GitHubApp` and validating the signature, additionally assert that the organization whose secret validated the signature actually matches the owner embedded in `payload.dig('repository', 'full_name')` (and in `organization.login` for org-scoped events like `membership`) before dispatching to handlers. Alternatively, disallow/reject organizations configured with a blank `webhook_secret` when running in multi-organization mode, since blank secrets there effectively disable authentication for that org's namespace while other orgs' repos remain reachable through the same public endpoint.

### Proof of Concept
1. Configure Shipit with two orgs: `OrgA` (no `webhook_secret` set) and `VictimOrg` (has a `webhook_secret`, and owns a tracked `VictimOrg/app` stack).
2. POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "full_name": "VictimOrg/app",
    "owner": { "login": "OrgA" }
  }
}
```
No valid `X-Hub-Signature` is required, since `repository_owner` resolves to `OrgA`, whose `verify_webhook_signature` short-circuits to `true` (`return true unless webhook_secret`).
3. `WebhooksController#create` re-parses the same body and dispatches to `PushHandler`, which resolves `stacks` via `payload.dig('repository', 'full_name')` = `"VictimOrg/app"`, and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on the victim's stack — despite the request never being authenticated by `VictimOrg`'s webhook secret.

### Citations

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

**File:** config/secrets.development.example.yml (L18-34)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
