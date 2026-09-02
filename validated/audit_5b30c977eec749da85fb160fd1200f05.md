### Title
Webhook signature-verification organization is not bound to the repository the payload writes to, allowing unsigned cross-repository status/sync forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which `GitHubApp` (and therefore which `webhook_secret`) to validate a webhook against using `repository_owner`, read from `params.dig('repository', 'owner', 'login')` (or `organization.login`). But every event handler downstream (`PushHandler`, `StatusHandler`, etc.) resolves the actual `Repository`/`Stack` to act on using a completely different field, `payload.dig('repository', 'full_name')`. Because per-organization `webhook_secret` is documented as optional, and `GitHubApp#verify_webhook_signature` treats a missing secret as an automatic pass, an attacker only needs one configured organization with no `webhook_secret` to bypass signing entirely while still causing writes against an unrelated, fully-signed organization's repositories.

### Finding Description
`verify_signature` fetches the app config for `repository_owner` and calls `verify_webhook_signature`: [1](#0-0) [2](#0-1) 

`verify_webhook_signature` short-circuits to `true` whenever no `webhook_secret` is configured for that organization: [3](#0-2) 

The webhook secret is documented as optional per GitHub App / organization: [4](#0-3) 

Once "verified" (or trivially passed because no secret exists for that org), the raw, attacker-controlled JSON is dispatched unchanged to handlers: [5](#0-4) 

Handlers never re-check `repository_owner`; they instead resolve the write target purely from `repository.full_name`: [6](#0-5) 

`PushHandler` uses that repository/stack resolution to trigger a GitHub sync job for arbitrary branches: [7](#0-6) 

`StatusHandler` uses `params.sha` (not tied to the "verified" org at all) to write commit statuses that gate deploys: [8](#0-7) 

The binding that should hold is: **organization authenticated by the signature check == organization whose repository is written by the dispatched handler**. In this engine that equality is never enforced — `repository_owner` (used only to pick a signing key) and `repository.full_name` (used to pick the actual DB row to mutate) are independent, attacker-supplied fields inside the same unauthenticated-until-then JSON body. An attacker can pick the `owner.login` of an organization configured without a `webhook_secret` (satisfying the "verified" side trivially), while setting `repository.full_name` to any other organization/repository tracked by this Shipit instance (the actually-written side).

This matches the report's bug class: a value used to gate an action (`terminate()`/here, "verified organization") is decoupled from the value the action actually operates on (funds release/here, `repository.full_name`).

### Impact Explanation
This crosses the "organization that authenticated versus the repository that is written" boundary explicitly called out as in-scope. Concretely, an unprivileged remote attacker (no Shipit session, no API token, no GitHub App key, no repository write access — the `/webhooks` route requires none of these) can:
- Force `stack.sync_github(expected_head_sha:)` calls on any repository/stack tracked by the instance via `PushHandler` with a forged `after`/`ref`, and
- Inject fabricated commit statuses via `StatusHandler#process` for any `sha` in the system, which can flip `Commit` status gates used by deploy/merge checks.

Because commit statuses and sync state feed into deploy/merge decisioning across the app, this can lead to an unauthorized deploy/merge decision being unlocked on a repository the attacker never had credentials for — matching the High-severity bucket ("escalation ... unauthorized deploy, rollback or merge" adjacent impacts described in scope).

### Likelihood Explanation
Likelihood depends entirely on operational configuration: it requires at least one organization in `secrets.github` configured without a `webhook_secret` (explicitly supported and documented as "optional"), while other organizations are properly signed. Any Shipit deployment managing multiple GitHub organizations where even one skips the optional secret (e.g., during initial setup, a lower-trust org, or an oversight) exposes every other organization's repositories to unsigned writes through this path. This is a realistic and plausible misconfiguration given the docs present the secret as optional rather than mandatory.

### Recommendation
Bind the verified organization to the actual write target instead of trusting two independent unauthenticated fields:
1. After successful signature verification, re-derive the acting repository strictly from the same trusted context used for key selection (i.e., require `payload.dig('repository', 'full_name')` to belong to the organization login that was cryptographically verified, or refuse handling otherwise).
2. Do not allow `verify_webhook_signature` to silently pass when `webhook_secret` is blank for any *configured* organization that also owns tracked repositories; instead, make secret configuration mandatory for any organization used in production, or require explicit opt-in for "no-secret" organizations with a hard restriction that such organizations cannot exercise handlers that mutate repositories/stacks belonging to other organizations.
3. Add a defense-in-depth check in `Handler#stacks`/`repository_name` that cross-validates the resolved `Repository#owner` against the organization that passed signature verification, rejecting the event if they diverge.

### Proof of Concept
1. Configure Shipit with two organizations: `victim-org` (properly signed, `webhook_secret: <real-secret>`) and `attacker-org` (no `webhook_secret` configured, per the documented optional setting).
2. Attacker POSTs directly to `/webhooks` with header `X-Github-Event: status` and no valid `X-Hub-Signature` (or any junk value), with body:
```json
{
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/critical-repo"
  },
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/forged"
}
```
3. `WebhooksController#verify_signature` calls `Shipit.github(organization: "attacker-org")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally. [9](#0-8) 
4. The unmodified payload is dispatched to `StatusHandler`, which looks up `Commit.where(sha: params.sha)` — commits belonging to `victim-org/critical-repo` — and writes a forged successful status via `commit.create_status_from_github!(params)`, entirely bypassing `victim-org`'s real signature requirement. [8](#0-7)

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

**File:** docs/setup.md (L29-30)
```markdown
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
