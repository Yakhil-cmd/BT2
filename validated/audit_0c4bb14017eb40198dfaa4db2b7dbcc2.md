### Title
Webhook signature is validated against the organization from the payload but repository actions are routed by a separate, unvalidated `repository.full_name` field, enabling cross-organization writes - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to use for HMAC verification from `params.dig('repository', 'owner', 'login')`, then verifies the raw request body against that secret. Once verification passes, the same raw payload is dispatched to handlers that instead resolve the target `Repository`/`Stack` using a *different* field, `payload.dig('repository', 'full_name')`. Because the signature only proves "this body was signed with organization X's secret," not "this body's `repository.full_name` belongs to organization X," any entity that legitimately holds the `webhook_secret` for one configured organization can forge a payload whose `repository.owner.login` matches their own org (satisfying `verify_signature`) while `repository.full_name` references a completely different tracked repository/stack.

### Finding Description
- `verify_signature` in [1](#0-0)  picks the app config via `repository_owner` and calls `github_app.verify_webhook_signature(signature, raw_post)`.
- `repository_owner` is read straight out of the untrusted, attacker-suppliable body: [2](#0-1) .
- `verify_webhook_signature` simply HMACs the raw body with the `webhook_secret` configured for that one organization: [3](#0-2) . It does not assert anything about which repository the payload claims to affect.
- Once verification passes, `Webhooks.for_event(event)` handlers run against the same `params`, but they select the target repository/stack from a *different* JSON field, `repository.full_name`, via the shared `Handler#repository_name`/`#stacks` helpers: [4](#0-3) .
- `PushHandler`, for example, uses `stacks` (i.e. `Repository.from_github_repo_name(repository_name)`) to find every non-archived stack on the target branch and calls `stack.sync_github(expected_head_sha: params.after)`: [5](#0-4) .

Because Shipit is designed to be multi-tenant across independently configured GitHub organizations (each with its own `webhook_secret`, as shown in the sample multi-org secrets file), the binding that should hold is: **organization authenticated (secret used to verify the signature) == organization owning the repository actually written to**. Nothing in `WebhooksController` or `Handler` enforces that `repository.owner.login` (used to pick the secret) matches `repository.full_name` (used to pick the repository/stack). An organization admin who legitimately possesses one org's `webhook_secret` can therefore forge a signed payload that sets `repository.owner.login` to their own org and `repository.full_name` to any other org/repo tracked by this Shipit instance, causing the push/status/check_suite/membership handlers to act on that unrelated repository's stacks.

### Impact Explanation
This breaks the "organization that authenticated versus the repository that is written" binding explicitly called out as in-scope. Concretely, an attacker with a valid `webhook_secret` for Org A (their own GitHub App installation registered in this Shipit instance) can:
- Force `PushHandler` to invoke `stack.sync_github(expected_head_sha: ...)` on Org B's stacks, effectively puppeteering GitHub sync state for a repository they don't own [5](#0-4) .
- Similarly abuse `status`/`check_suite`/`membership` handlers, all of which inherit the same repository-resolution helper and therefore the same missing cross-org check [4](#0-3) .

This is a cross-repository write achieved purely by crafting a webhook payload whose internal fields disagree, satisfying the "cross-repository writes" critical impact bucket, since it lets a party outside Org B's trust boundary manipulate Org B's stack state (sync state, CI-derived deployability signals) without ever having Org B's own webhook secret.

### Likelihood Explanation
Requires the attacker to already control a legitimate `webhook_secret` for at least one organization configured in this Shipit instance (i.e., they must be a valid tenant/org admin, not the target org). Given Shipit's documented multi-tenant configuration model (multiple independent orgs each with their own App/webhook secret in the same instance), this is a low-privilege boundary crossing from the perspective of the *victim* organization's repositories, even though it requires legitimate tenancy in *some* org.

### Recommendation
In `Handler#repository_name`/`#stacks`, or centrally in `WebhooksController#verify_signature`, require that the resolved `repository.full_name`'s owner matches the `repository_owner` (or `organization.login`) that was used to select the verifying `webhook_secret`, rejecting (422) any payload where these disagree.

### Proof of Concept
1. Configure Shipit with two organizations, `orgA` and `orgB`, each with distinct `webhook_secret`s (as in the multi-tenant sample config) [6](#0-5) .
2. As an attacker who is a legitimate admin of `orgA` (and thus knows `orgA`'s `webhook_secret`), craft a `push` event JSON body:
   ```json
   { "ref": "refs/heads/master", "after": "<attacker-chosen sha>",
     "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/victim-repo" } }
   ```
3. Compute `X-Hub-Signature` using `orgA`'s `webhook_secret` over this exact raw body (same HMAC scheme as `DeliverySigner`/`verify_webhook_signature`) [3](#0-2) .
4. POST to `/github/webhooks` (or engine-mounted webhook path). `verify_signature` looks up `orgA`'s app via `repository_owner == "orgA"` and the signature matches, so it passes [1](#0-0) .
5. `PushHandler` then resolves `Repository.from_github_repo_name("orgB/victim-repo")` and calls `sync_github` on `orgB`'s stacks, even though `orgB`'s webhook secret was never used or known to the attacker [5](#0-4) [4](#0-3) .

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

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
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
```
