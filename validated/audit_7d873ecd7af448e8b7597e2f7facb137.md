### Title
Webhook Signature Verified Against a Different Organization Than the Repository Whose Stack Is Actually Acted Upon - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to verify the HMAC signature against using a payload field (`repository.owner.login` or `organization.login`) that is fully attacker-controlled, since the endpoint is unauthenticated prior to signature verification. The event handler that subsequently acts on the payload (e.g. `PushHandler`) resolves the target `Stack` using a *different* payload field, `repository.full_name`, without cross-checking that it belongs to the same organization whose secret validated the request.

### Finding Description
`verify_signature` computes:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 
and uses it to pick the org config for verification:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
``` [2](#0-1) 

The verification itself simply HMACs the raw body with the secret configured for that org: [3](#0-2) 

Once verified, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the same JSON payload to handlers such as `PushHandler`, which resolves the target repository/stack via a **separate** field:
```ruby
def repository_name
  payload.dig('repository', 'full_name')
end

def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end
``` [4](#0-3) 
`PushHandler#process` then triggers `stack.sync_github(expected_head_sha: params.after)` for every matching, non-archived stack: [5](#0-4) 

Because `repository.owner.login` (used for signature selection) and `repository.full_name` (used for stack resolution) are independent JSON keys inside the same attacker-supplied body, an attacker who knows/derives a valid webhook secret for **Organization A** (e.g., because it is unset — `verify_webhook_signature` returns `true` unconditionally when no secret is configured: `return true unless webhook_secret`, [6](#0-5) ) — or otherwise obtains Org A's secret — can set `repository.owner.login = "orgA"` while setting `repository.full_name = "orgB/some-repo"`. The signature check passes (verified against Org A), but the handler acts on a stack belonging to Org B, an organization the attacker was never authenticated for.

This breaks the binding: **organization authenticated (via HMAC/secret selected by `repository.owner.login`) ≠ organization whose repository is actually written/acted upon (`repository.full_name` used to resolve `Stack`)**.

### Impact Explanation
This allows an attacker who controls (or exploits a misconfigured/unset secret of) one onboarded GitHub organization to forge webhook events that act on stacks belonging to an entirely different organization hosted on the same Shipit instance. Via `PushHandler`, this triggers `Stack#sync_github`, which fetches commit/ref data using the app's GitHub credentials and can advance the stack's HEAD, refresh CI/check statuses, and — combined with `continuous_deployment`/merge-queue features — precipitate an unauthorized deploy for a repository the attacker does not control. This is a cross-organization/cross-repository write achieved without possessing that organization's own webhook secret, satisfying the "unauthorized deploy" / "cross-repository writes" High/Critical impact bar.

### Likelihood Explanation
Exploitability depends on the attacker being able to produce a signature that verifies for *some* configured organization on the instance — trivially true if any onboarded org has `webhook_secret` unset (the code explicitly short-circuits to `true` in that case), and otherwise requires only leaking/guessing that one org's secret rather than the target org's. Multi-tenant Shipit deployments (multiple orgs configured in `secrets.yml`, as documented in `docs/setup.md`) are the intended and supported use case, making this a realistic configuration rather than a hypothetical one. [7](#0-6) 

### Recommendation
Bind the identity used for signature verification to the identity used for repository resolution: after selecting `github_app` via `repository_owner`, re-derive the acted-upon repository owner from the same field (not `repository.full_name` alone) and reject the webhook if the owner segment of `repository.full_name` (or `organization.login`) does not match `repository_owner`. Alternatively, key `Shipit.github(organization:)` lookup and stack resolution off a single canonical field, and enforce that `Repository.from_github_repo_name`'s owner segment equals the verified `repository_owner` before dispatching to handlers.

### Proof of Concept
1. Instance is configured with two orgs in `secrets.yml`: `orgA` (no `webhook_secret` set) and `orgB` (has a stack for `orgB/target-repo`).
2. Attacker POSTs to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha-that-exists-on-orgB/target-repo>",
  "repository": {
    "owner": { "login": "orgA" },
    "full_name": "orgB/target-repo"
  }
}
```
3. `verify_signature` calls `Shipit.github(organization: "orgA")` and, since `orgA` has no webhook secret, `verify_webhook_signature` returns `true` unconditionally regardless of the (even absent) `X-Hub-Signature` header. [3](#0-2) 
4. `PushHandler` resolves stacks via `Repository.from_github_repo_name("orgB/target-repo")` and calls `stack.sync_github(expected_head_sha: ...)` for `orgB`'s stack — an organization the attacker never authenticated against. [4](#0-3) [5](#0-4)

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
