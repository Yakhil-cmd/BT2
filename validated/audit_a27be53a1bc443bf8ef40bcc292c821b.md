### Title
Webhook signature is verified against `repository.owner.login`, but write-side handlers key off unrelated, uncross-checked payload fields (`repository.full_name`, global `sha`) - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate a webhook against using `repository.owner.login` (or `organization.login`) from the JSON payload. However, the handlers that actually mutate state (`PushHandler`, `CheckSuiteHandler`, and especially `StatusHandler`) resolve *which stack/commit* to act on using **different, independent fields** of the same attacker-controlled payload (`repository.full_name`, or a completely unscoped `sha` lookup). Because `webhook_secret` is documented as optional, an attacker can pick any organization onboarded to the Shipit instance that has no webhook secret configured, trivially pass signature verification for that "identity," and then use unrelated payload fields to write state (in particular forge a CI status) against a totally different organization's stack/commit.

### Finding Description
`verify_signature` computes the signing organization purely from the payload itself: [1](#0-0) [2](#0-1) 

`GithubApp#verify_webhook_signature` explicitly treats an absent `webhook_secret` as "always verified": [3](#0-2) 

The setup documentation confirms a webhook secret is an optional, supported configuration, not a misconfiguration: [4](#0-3) 

Once `verify_signature` passes, `create` dispatches the *entire raw payload* to handlers: [5](#0-4) 

Handlers, however, do **not** re-derive or check the organization/owner that was used for authentication. `Handler#stacks` resolves the target repository from `repository.full_name`, a field never compared against `repository.owner.login` used in `verify_signature`: [6](#0-5) 

`PushHandler` uses that unscoped `stacks` lookup to trigger a GitHub sync on any matching stack: [7](#0-6) 

`StatusHandler` is worse: it does not even use `Handler#stacks`/`repository_name` — it looks up commits **globally by `sha` across the entire Shipit instance** and writes a CI status onto them: [8](#0-7) 

This mirrors the report's bug class exactly: the security-relevant equality that should hold is:

`organization used to authenticate the request (repository.owner.login / verified webhook_secret) == organization/repository whose state is mutated (repository.full_name / commit lookup)`

The code never enforces this equality — the two sides are computed from independent, attacker-controlled fields of the same JSON body, exactly analogous to `_compoundAccounting()` trusting a balance the caller can inflate independently of the accounting invariant it's supposed to represent.

### Impact Explanation
An attacker who has no Shipit session, no `ApiClient` token, and no legitimate `webhook_secret` for the *victim* organization can:
1. Identify (or create) any GitHub organization onboarded to the shared Shipit instance that has **no `webhook_secret` configured** (an explicitly supported, documented configuration — not a deployment error).
2. Send a POST to `/webhooks` with `X-Github-Event: status`, `repository.owner.login` set to that no-secret org (satisfying `verify_signature` trivially since `verify_webhook_signature` returns `true` when `webhook_secret` is blank), and `sha`/`state: success`/`context` set to target a commit belonging to a **victim stack in a different organization** that does have CI requirements gating deploys (`ci.require` in `shipit.yml`).
3. `StatusHandler#process` writes a fabricated "success" status onto that commit for any repository in the entire Shipit database, since the lookup is `Commit.where(sha: params.sha)` with no repository/organization scoping at all.
4. If the victim stack has `continuous_deployment` enabled or a human clicks Deploy, `Commit#deployable?`/`ci.require` checks will now pass on the forged status, resulting in an **unauthorized deploy** of a commit that never actually passed CI.

This satisfies the Critical impact bar of "an unauthorized deploy" driven purely by a cross-organization authentication/authorization binding failure, requiring no credentials for the victim organization at all.

### Likelihood Explanation
Likelihood is high wherever a Shipit instance onboards multiple GitHub organizations/apps (a documented, supported multi-tenant configuration) and at least one onboarded organization omits `webhook_secret` (explicitly documented as optional). No privileged access, session, or victim secret is needed — only the ability to send an HTTP POST to the public `/webhooks` endpoint with a crafted JSON body.

### Recommendation
Enforce the binding that the report's bug class implies is missing: after `verify_signature` succeeds, the organization/repository actually mutated by a handler must be checked against the organization that was cryptographically verified (or against the `Repository`/`Stack`'s own configured organization), not solely against payload-supplied `full_name`/`sha`. Concretely:
- In `Handler#stacks`, verify that the resolved `Repository`'s owner matches the verified `repository_owner` from the controller (pass it through explicitly rather than re-deriving from the same untrusted payload).
- In `StatusHandler#process`, scope the `Commit` lookup by the resolved/verified repository (via `stacks`/`Repository.from_github_repo_name`) instead of a global `sha` lookup across all stacks.
- Treat an organization configured without a `webhook_secret` as requiring stricter isolation (e.g., disallow it from triggering writes on stacks belonging to other organizations), or require `webhook_secret` for any multi-tenant deployment.

### Proof of Concept
1. Configure (or find) two organizations in `Shipit.github`: `attacker-org` (no `webhook_secret`) and `victim-org` (has stacks/commits with `ci.require`).
2. `POST /webhooks` with header `X-Github-Event: status`, no valid `X-Hub-Signature` needed, and body:
```json
{
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/whatever" },
  "sha": "<victim commit sha in victim-org's stack>",
  "state": "success",
  "context": "ci/required-check"
}
```
3. `verify_signature` calls `Shipit.github(organization: "attacker-org")` and `verify_webhook_signature` returns `true` unconditionally (no secret configured) — request passes.
4. `StatusHandler#process` runs `Commit.where(sha: params.sha)` — finds the victim commit (global, unscoped) and calls `create_status_from_github!`, marking required CI as passed on a commit the attacker never had access to.
5. If `victim-org`'s stack has continuous deployment enabled (or an operator now sees "CI passed"), the commit becomes deployable, producing an unauthorized deploy triggered entirely by an unprivileged third party.

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

**File:** docs/setup.md (L28-30)
```markdown
  - Setup URL: Leave it empty.
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
