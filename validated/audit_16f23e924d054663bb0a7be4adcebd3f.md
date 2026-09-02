### Title
Webhook signature is verified against the organization named in an attacker-controlled field, while the actual write target is resolved from a different, unvalidated field of the same payload - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/handler.rb, lib/shipit/github_app.rb)

### Finding Description
`WebhooksController#verify_signature` selects which per-organization `GitHubApp`/secret to verify the HMAC against using a value taken straight from the untrusted request body: [1](#0-0) [2](#0-1) 

`repository_owner` is computed as `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` — both fully attacker-controlled JSON fields, read before any cryptographic check is performed. This value is used only to pick *which* configured GitHub App's secret is used for `verify_webhook_signature`: [3](#0-2) 

Critically, `verify_webhook_signature` returns `true` unconditionally when that organization's `webhook_secret` is blank/unset — a state explicitly supported and documented ("Webhook secret (optional)") and shown as the literal example value (`webhook_secret: # nil`) in `docs/setup.md`, `config/secrets.development.example.yml`, and the multi-org fixture `test/dummy/config/secrets_double_github_app.yml`.

After `verify_signature` passes (or is trivially bypassed because the *selected* org has no secret), `WebhooksController#create` dispatches the **same raw payload** to event handlers: [4](#0-3) 

Handlers determine which `Stack`/`Repository` to act on using a *different* field, `repository.full_name`, via the shared base class: [5](#0-4) 

`PushHandler` then calls `stack.sync_github(expected_head_sha:)` for every non-archived stack matching that repository's branch: [6](#0-5) 

The equality that should hold but does not: `organization used to select/verify the webhook signature == organization that owns the repository actually written to`. In a multi-organization deployment (`Shipit.github(organization:)` / `TOP_LEVEL_GH_KEYS` scheme, see `lib/shipit.rb:170-200`), these two values come from two independent, both attacker-supplied, fields of the same JSON body (`repository.owner.login`/`organization.login` vs `repository.full_name`). Nothing forces `repository.full_name`'s owner segment to match `repository.owner.login`.

### Impact Explanation
If a Shipit deployment is configured with multiple GitHub organizations (a documented, supported configuration) and any one of them has no `webhook_secret` configured — the documented default/optional state — an unauthenticated internet attacker can:
1. Set `repository.owner.login` (or `organization.login`) in the JSON body to the name of the org with no secret, so `verify_signature` selects that org's `GitHubApp`, whose `verify_webhook_signature` returns `true` regardless of the `X-Hub-Signature` header content.
2. Set `repository.full_name` in the same body to any real repository/stack tracked by Shipit under a *different*, properly-secured organization.
3. Set `ref`/`after` to any branch/SHA.

The forged push event is accepted (`head(:ok)`), and `Shipit::Webhooks.for_event('push')` invokes `PushHandler`, which resolves the target stack purely from `repository.full_name` and calls `stack.sync_github(expected_head_sha: params.after)` — triggering repository sync/deploy-eligible state changes for a stack whose org's webhook secret was never checked. This is a cross-repository write triggered without ever validating a legitimate signature for the affected repository, matching the Critical class "cross-repository writes."

### Likelihood Explanation
Requires the operator to run a multi-organization Shipit deployment where at least one configured org has no `webhook_secret` (explicitly presented as the normal/optional default in the docs and example configs). No privileged credentials, session, or token are needed — only the ability to POST JSON to the public `/webhooks` endpoint, which is designed to be internet-reachable. Likelihood is contingent on this specific but documented/encouraged configuration state, so it is realistic in installations using the "Multiple GitHub Applications" feature without setting a secret on every entry.

### Recommendation
Do not let the webhook payload choose which organization's key verifies its own signature. Either:
- Require every configured GitHub App to have a non-blank `webhook_secret` before verification is considered meaningful (fail closed rather than `return true unless webhook_secret`), or
- After signature verification succeeds for organization X, additionally assert that `repository.full_name`'s owner segment (and/or `repository.owner.login`) equals X before dispatching to handlers, rejecting payloads where the two diverge.

### Proof of Concept
Given a `secrets.yml` with two orgs configured as in `test/dummy/config/secrets_double_github_app.yml` (`OrgOne` and `OrgTwo`, both showing `webhook_secret: # nil` in the example/config), an attacker can send:

```
POST /webhooks
X-Github-Event: push
X-Hub-Signature: sha1=anything-or-omitted

{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "OrgOne" },
    "full_name": "OrgTwo/some-real-stack-repo"
  }
}
```

`repository_owner` resolves to `OrgOne`; `Shipit.github(organization: 'OrgOne')` has `webhook_secret` blank, so `verify_webhook_signature` returns `true` unconditionally regardless of the signature header. `PushHandler#stacks` then looks up `OrgTwo/some-real-stack-repo` via `repository_name = payload.dig('repository', 'full_name')` and calls `stack.sync_github(expected_head_sha: 'attacker-chosen-sha')` for all matching stacks — a write performed against `OrgTwo`'s repository despite the signature check having only (trivially) validated `OrgOne`.

*Note: I was unable to fully trace `Repository.from_github_repo_name` (definition not found in the indexed content) or `Stack#sync_github`'s downstream job logic to confirm exactly how far the forged `expected_head_sha` propagates before any independent GitHub-API cross-check occurs; this may affect the precise blast radius (e.g., whether it merely queues a sync that reconciles against real GitHub state, or whether `expected_head_sha` is trusted directly). Given index size limits, some file contents may not be available — a Devin session with full repository access would be needed to verify `Repository.from_github_repo_name` and the full `GithubSyncJob`/`Stack#sync_github` implementation to confirm the exact downstream effect.*

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

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
