### Title
Webhook signature verification is bound to the payload's `repository.owner.login`, but stack lookup/mutation is bound to `repository.full_name` — cross-organization/cross-repository forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
This is a structural analog of the ERC20Pods "captured value diverges from acted-upon value" bug: the report shows `_removeAllPods` capturing `balance` once and then letting a rogue pod's callback act on a different, updated balance than the one checked. In Shipit, `WebhooksController` picks *which* GitHub App/organization config (and therefore which `webhook_secret`) to use for HMAC verification based on one unauthenticated field of the payload (`repository.owner.login`), while every event `Handler` subsequently looks up and mutates the target `Stack`/`Repository` using a *different* unauthenticated field (`repository.full_name`). Nothing binds these two fields together, so the identity that "authenticated" the request is not the identity that gets written to.

### Finding Description
`WebhooksController#verify_signature` selects the `GitHubApp` config to verify against using only the attacker-supplied JSON body: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` will accept *any* payload unconditionally if that organization's config has no `webhook_secret` configured: [3](#0-2) 

Multi-org configs are an explicitly supported/documented deployment shape (see `test/dummy/config/secrets_double_github_app.yml`, `docs/setup.md`), so it is normal for a Shipit instance to have several organizations configured, potentially with different `webhook_secret` values, or one org with a blank secret used for local/dev/testing purposes but still reachable in production routing.

After `verify_signature` passes (or is bypassed because the selected org's secret is blank), `WebhooksController#create` dispatches the full raw payload to handlers: [4](#0-3) 

Every handler resolves the affected `Stack` via `Handler#stacks`/`#repository_name`, which reads `payload.dig('repository', 'full_name')` — a completely different field than the one used for authentication: [5](#0-4) 

For example, `PushHandler#process` triggers `stack.sync_github(expected_head_sha: params.after)` for every stack matching that `full_name`/branch: [6](#0-5) 

The binding that should hold is:
`organization that authenticated the signature == organization that owns the repository being written to`

but the code enforces only:
`repository.owner.login (used to pick webhook_secret) ⟂ repository.full_name (used to pick/mutate the Stack)`

These are two independent, attacker-controlled JSON fields with no cross-validation. An attacker who knows (or controls) the `webhook_secret` for *any* configured organization — including one with no secret set — can compute a valid `X-Hub-Signature` for that org while setting `repository.owner.login` to that org and `repository.full_name` to an arbitrary other tracked repository (belonging to a different, properly-secured org). The signature check passes, and the handler acts on the victim repository's stacks using attacker-forged event data.

### Impact Explanation
This breaks the "organization that authenticated versus the repository that is written" trust binding named in scope. Concretely:
- `push` events can force `GithubSyncJob`/`stack.sync_github` to run against any tracked stack, using an attacker-chosen `expected_head_sha`, independent of which org's secret validated the request.
- `status`/`check_suite`/`membership` and PR handlers similarly act on data keyed by `repository.full_name` or unscoped identifiers (e.g. `Commit.where(sha: ...)` in `StatusHandler`), with no re-check that the authenticating org actually owns that data.
- Because deploy/merge/rollback flows in Shipit are driven by these events (commit sync, status updates, PR merges), this can be leveraged toward unauthorized state changes across repositories that the attacker's credentials should have no authority over — a cross-repository write, matching the "Critical" impact bucket in scope.

The severity depends on how many organizations/webhook secrets a given Shipit deployment configures and whether any of them are weak/blank, but the code path itself provides no isolation regardless of configuration — it is a missing binding, not a misconfiguration-only issue.

### Likelihood Explanation
Requires no privileged Shipit credentials, no GitHub App private key, and no session — only knowledge of one configured organization's webhook secret (or the ability to target a configured org whose secret is blank, which the shipped example/dummy configs and docs show as an easy administrator oversight). This satisfies the "unprivileged attacker" bar in the rules. The main uncertainty is deployment-specific: exploitability requires the target instance to have multiple `Shipit.github` organizations configured (per `lib/shipit.rb#github_app_config`) with at least one weak/known secret; single-org deployments are not affected by the cross-org variant, though the blank-secret bypass (`return true unless webhook_secret`) still applies to any org lacking a secret.

### Recommendation
Cross-check that the organization whose config verified the signature actually owns the repository referenced by the event payload before dispatching to handlers — e.g., resolve the `Stack`/`Repository` by `full_name`, then confirm its configured GitHub organization matches `repository_owner` (or `Shipit.github(organization: repository_owner)`), rejecting the event otherwise. Additionally, treat a missing `webhook_secret` for a *reachable* organization as a hard configuration error rather than an automatic pass in `GitHubApp#verify_webhook_signature`.

### Proof of Concept
1. Deploy Shipit with two configured organizations, e.g. `OrgWeak` (no `webhook_secret`, or a leaked one) and `OrgStrong` (strong secret), both with stacks tracked (as in `test/dummy/config/secrets_double_github_app.yml`).
2. Attacker crafts a `push` webhook JSON body:
   ```json
   {
     "repository": { "owner": { "login": "OrgWeak" }, "full_name": "OrgStrong/victim-repo" },
     "ref": "refs/heads/master",
     "after": "<attacker-chosen sha>"
   }
   ```
3. Attacker sends `POST /github` with `X-Github-Event: push` and either no valid signature (if `OrgWeak` has a blank secret) or a signature computed with `OrgWeak`'s known secret.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: 'OrgWeak')` and `verify_webhook_signature` returns `true` (blank secret) — the request is accepted.
5. `PushHandler#process` resolves stacks via `Repository.from_github_repo_name('OrgStrong/victim-repo')` and calls `stack.sync_github(expected_head_sha: '<attacker-chosen sha>')`, causing the victim org's stack to sync to an attacker-chosen commit despite the request never being authenticated by `OrgStrong`'s webhook secret.

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
