### Title
Webhook signature verification is keyed on `repository.owner.login`/`organization.login` while every event handler acts on the independent `repository.full_name` field, allowing cross-organization webhook forgery when any configured GitHub App has no `webhook_secret` set - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which `GitHubApp` (and therefore which HMAC secret) to validate a webhook against using `repository_owner`, computed from the attacker-influenced JSON body (`repository.owner.login` or `organization.login`) [1](#0-0) . Every actual event handler, however, resolves the target `Repository`/`Stack` from a *different* field in the same body: `repository.full_name` [2](#0-1) , and handlers such as `PushHandler` use it to trigger real side effects (`stack.sync_github(expected_head_sha: params.after)`) [3](#0-2) . Because the field used for authentication (`repository.owner.login`) and the field used for authorization/target-selection (`repository.full_name`) are independent, unauthenticated attacker-controlled values in the same request body, and because `verify_webhook_signature` trivially returns `true` when no `webhook_secret` is configured for the selected organization [4](#0-3) , a signature "verified" for one (low-value/no-secret) organization can carry a payload whose `repository.full_name` targets a completely different organization's stack.

### Finding Description
Shipit supports multiple GitHub Apps/organizations configured under `github:` in secrets, each with its own optional `webhook_secret` (documented as optional in `docs/setup.md` and shown for multi-org setups in `config/secrets.development.shopify.yml`) [5](#0-4) [6](#0-5) .

The controller resolves the verifying organization purely from the JSON body, *before* any signature check has occurred:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

`Shipit.github(organization: repository_owner)` then loads that organization's `GitHubApp`, and `verify_webhook_signature` is invoked [7](#0-6) . Inside `GitHubApp`, if that organization has no `webhook_secret` configured, verification is skipped entirely:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [4](#0-3) 

Once "verified" (`head(422) unless verified` is the only gate) [8](#0-7) , `create` dispatches the raw, attacker-controlled body to every registered handler for the event: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [9](#0-8) . All handlers resolve their target repository not from `repository.owner.login` (the field that gated authentication) but from `repository.full_name`:
```ruby
def repository_name
  payload.dig('repository', 'full_name')
end
``` [10](#0-9) 

This is the exact binding break called out in the report's bug class: the equality `organization authenticated == repository written` does not hold. The engine authenticates on `owner.login` but writes/acts on `full_name`, and these two JSON fields can be set independently by whoever controls the raw POST body.

### Impact Explanation
This crosses the "unauthenticated read/write of stack state" and potentially "unauthorized deploy" boundary called out in scope: an attacker who can reach the public `/webhooks` endpoint and knows (or controls) any organization in the Shipit config whose `webhook_secret` is unset can submit a completely forged, unsigned event whose `repository.full_name` names a victim stack belonging to a *different*, properly-secured organization. For `push` events this directly invokes `stack.sync_github(expected_head_sha: params.after)` with an attacker-chosen `after` SHA [3](#0-2) , letting the attacker dictate what Shipit believes is the expected HEAD for a stack it does not control, which can drive the sync/build/merge pipeline for that stack (e.g., manipulating which commit is considered "new" for deploy candidacy) without ever presenting a valid signature for that organization. This satisfies the "unauthenticated read of stack state ... or an unauthorized deploy" High-impact bar, since the write happens against a stack outside the trust boundary that was actually authenticated.

### Likelihood Explanation
Exploitability depends on the deployment having at least one configured GitHub organization without a `webhook_secret` — which the engine's own setup docs explicitly present as optional and its multi-org example config leaves blank by default [5](#0-4) [11](#0-10) . In any multi-tenant Shipit instance where one org's App was created without a webhook secret (a documented "optional" step, easy to skip), this is directly exploitable by an unauthenticated network attacker with zero credentials — they only need to know that org's login string, which is often public.

### Recommendation
- Do not derive the authentication key from the same untrusted body field(s) that authorization/target-resolution later relies on; instead bind the verified organization to the resolved repository's owner and re-validate that `repository.full_name`'s owner matches `repository_owner` before dispatching to handlers.
- Make `webhook_secret` mandatory (fail closed) rather than silently returning `true` when absent in `GitHubApp#verify_webhook_signature`.
- Alternatively, verify the signature using a per-installation secret resolved independently of any request body field (e.g., via GitHub's App/installation ID mapping) rather than a client-suppliable organization name.

### Proof of Concept
Assume Shipit is configured with two organizations: `no-secret-org` (webhook secret left blank, per documented "optional" setup) and `victim-org` (properly configured, has a stack tracking `victim-org/victim-repo`).

```
POST /webhooks HTTP/1.1
X-Github-Event: push
Content-Type: application/json

{
  "ref": "refs/heads/master",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "owner": { "login": "no-secret-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
- `WebhooksController#verify_signature` computes `repository_owner` = `"no-secret-org"` [1](#0-0) , loads that org's `GitHubApp`, and since it has no `webhook_secret`, `verify_webhook_signature` returns `true` unconditionally regardless of the (absent/garbage) `X-Hub-Signature` header [4](#0-3) .
- `create` then dispatches to `PushHandler`, which resolves the target stack via `payload.dig('repository', 'full_name')` = `"victim-org/victim-repo"` [10](#0-9)  and calls `stack.sync_github(expected_head_sha: "deadbeef...")` on the victim's stack [3](#0-2)  — an action that should only be triggerable by a signed webhook from `victim-org`'s own GitHub App installation.

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
