### Title
Webhook signature verification keys off `repository.owner.login`, but push processing keys off `repository.full_name` — organization authenticated ≠ repository written - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App config (and webhook secret) to validate a webhook against using one field of the untrusted, unverified JSON body — `repository.owner.login` (falling back to `organization.login`) — while the handlers that actually act on the payload (e.g. `PushHandler`) resolve the target `Stack`/`Repository` using a *different* field of the same body, `repository.full_name`. Nothing ties these two fields together, so the "organization whose secret authenticated the request" and "the repository that gets written to" are never checked for equality.

### Finding Description
`verify_signature` computes `repository_owner` from the raw JSON and picks a per-organization GitHub App/secret with it: [1](#0-0) [2](#0-1) 

If that organization has no `webhook_secret` configured — which the setup docs explicitly call optional per organization — `verify_webhook_signature` short-circuits to `true` for *any* body/signature pair: [3](#0-2) [4](#0-3) 

Once verification "passes" (either legitimately for that org, or trivially because that org has no secret), the actual side effect is dispatched by `Shipit::Webhooks.for_event(event)` handlers using the same unverified body, but a completely independent field: [5](#0-4) [6](#0-5) [7](#0-6) 

`Repository.from_github_repo_name` is looked up purely from `repository.full_name`, with no cross-check against `repository.owner.login`/the organization whose secret authorized the request: [8](#0-7) 

So the equality that should hold — `organization authenticated by signature == organization that owns the repository being written to` — is never enforced. An attacker who can get a webhook delivered/signed for *any* organization configured in Shipit with a blank/optional `webhook_secret` (or any org whose secret they otherwise obtain) can set `repository.full_name` in the body to point at a *different*, victim stack (any org/repo already registered in Shipit), causing `PushHandler` to call `stack.sync_github(expected_head_sha: ...)` for that victim stack — i.e., spoof a push/status event and trigger a GitHub sync job for a repository the request was never actually authorized for.

### Impact Explanation
This breaks the binding "organization authenticated versus the repository that is written," letting an attacker who only controls a webhook signed for a low-trust/no-secret organization spoof push/status events against a different, unrelated stack registered in the same Shipit instance. `PushHandler` triggering `sync_github` (which enqueues `GithubSyncJob`) for an arbitrary stack can desynchronize commit/deploy state and interfere with deploy eligibility signals, which maps to unauthorized cross-repository state manipulation of stack data — a High-severity engine-level authorization boundary break, analogous to the "missing access control on privileged function" root cause in the source report (a field/action that's supposed to be gated by a specific authority check is not actually checked against the acting entity).

### Likelihood Explanation
Requires that at least one GitHub organization configured in the Shipit instance omits `webhook_secret` (explicitly supported as "optional" per the setup docs), or that the attacker otherwise obtains a valid signature for some organization. Given that is true, forging the `repository.full_name` field to target any other stack requires no special privilege — the attacker only needs to be able to deliver a POST to `/webhooks` with the crafted body (e.g., via their own GitHub App/organization webhook configured to point at the Shipit instance).

### Recommendation
Verify webhook signatures using an organization derived consistently with what the handlers act on, and enforce that the organization used to select the verification secret matches the owner of the repository/organization the handler ultimately mutates. Do not allow an organization with no configured secret to implicitly authorize processing of payloads referencing arbitrary other repositories — e.g., reject payloads when `webhook_secret` is unset for a given org, or bind the resolved `Repository`/`Stack` to the same `owner.login` used in `verify_signature`.

### Proof of Concept
1. Configure (or have configured) a Shipit instance with two orgs: `victim-org` (has stacks, has `webhook_secret` set) and `attacker-org` (registered in `Shipit.github_teams`/GitHub App config but with `webhook_secret` left blank, per docs/setup.md's "optional" secret).
2. As an entity that can deliver a webhook "for" `attacker-org` (e.g., install/trigger a webhook from a repo under `attacker-org`), send a POST to `/webhooks` with headers `X-Github-Event: push` and a JSON body where:
   - `repository.owner.login = "attacker-org"` (drives `verify_signature`, which passes trivially since `attacker-org` has no secret — `verify_webhook_signature` returns `true`),
   - `repository.full_name = "victim-org/victim-repo"` and `ref`, `after` set to attacker-chosen values (drives `PushHandler`, which resolves the stack via `Repository.from_github_repo_name`).
3. `WebhooksController#create` never rejects this, and `PushHandler#process` finds `victim-org/victim-repo`'s stacks and calls `stack.sync_github(expected_head_sha: <attacker-controlled sha>)`, causing a spoofed sync/deploy-eligibility action on a stack the attacker never had legitimate signed access to.

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

**File:** docs/setup.md (L30-30)
```markdown
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
