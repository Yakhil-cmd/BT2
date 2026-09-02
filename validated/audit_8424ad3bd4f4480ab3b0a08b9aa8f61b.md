### Title
Webhook signature verification keys off `repository.owner.login` while the event is dispatched using `repository.full_name` - Organization authenticated ≠ repository written (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to validate the `X-Hub-Signature` against using the attacker-controlled field `repository.owner.login` (or `organization.login`) taken from the still-unauthenticated JSON body. Once "verified", the same raw, attacker-controlled payload is handed to `Shipit::Webhooks::Handlers::Handler`, which resolves the actual `Stack`/`Repository` to act on using a *different* attacker-controlled field, `repository.full_name`. Nothing binds these two fields together, so the organization whose secret is used to authenticate the request can differ from the repository that ends up being written to.

### Finding Description
Verification path: [1](#0-0) 
uses: [2](#0-1) 
`repository_owner` is read straight out of `request.raw_post` (`params`) before any signature check occurs, and is used only to pick the `Shipit.github(organization:)` config (and thus the `webhook_secret` to HMAC-check against).

Dispatch path, once `verify_signature` passes, executes handlers on the raw parsed body: [3](#0-2) 

Handlers (e.g. `PushHandler`) resolve the target `Stack` using a *different* JSON field: [4](#0-3) [5](#0-4) 

The actual signature check treats a missing/blank `webhook_secret` as automatically verified: [6](#0-5) 

Shipit explicitly supports multi-organization configurations where different orgs can have different (or no) `webhook_secret`, as shown in the shipped templates/fixtures: [7](#0-6) [8](#0-7) 

Because `repository.owner.login` (used for auth) and `repository.full_name` (used for dispatch/target resolution) are two independently attacker-controlled JSON fields in the same unauthenticated POST body, an attacker can set them to point at different organizations. If any org configured on the instance has no `webhook_secret` (a state the project's own templates ship with — `webhook_secret: # nil`), the attacker can:
1. Set `repository.owner.login` (or `organization.login`) to that no-secret org, making `verify_signature` pass trivially regardless of the `X-Hub-Signature` header (`return true unless webhook_secret`).
2. Set `repository.full_name` to `victim-org/victim-repo`, an entirely different, properly-secured org/repo that hosts a real `Stack`.

The `create` action then runs `PushHandler`/other handlers against the victim repository/stack with no valid signature ever having been checked for that org, breaking the equality that should hold: `org verified via webhook_secret == org whose repository state is mutated`.

### Impact Explanation
This is an authentication-bypass class issue: it allows an unauthenticated attacker (no GitHub App credentials, no Shipit session, no `ApiClient` token) to make the engine believe a legitimate, signed webhook event was received for a repository/org it was never signed for. For `push` events this drives `PushHandler#process` → `stack.sync_github(expected_head_sha: ...)` → `GithubSyncJob`, which fetches commits from the real GitHub repo and can trigger the stack's continuous-delivery pipeline for an attacker-chosen branch/SHA state, i.e. an unauthorized deploy trigger against a stack the attacker has no legitimate access to. Other handlers (status, check_suite, membership, pull_request family) are reachable the same way, letting an attacker forge CI status, team membership, or PR state for a repository/org whose webhook secret they never possessed. This matches the "unauthorized deploy" / "authentication bypass" impact tier.

### Likelihood Explanation
Requires no privileged access whatsoever — only that the Shipit instance is configured with more than one GitHub organization and at least one of them has no `webhook_secret` set (a state explicitly present in the project's own configuration templates and test fixtures, suggesting it is a realistic/likely operational configuration, e.g. a dev/staging org added without a secret). Given that, exploitation is a single crafted HTTP POST to `/webhooks` with mismatched `repository.owner.login` / `repository.full_name` fields — no signature guessing, brute force, or timing attack needed.

### Recommendation
Bind the two identities together before trusting the payload: derive the organization used for signature verification from the *same* field used for dispatch (`repository.full_name`'s owner segment), and/or reject the request if `repository.owner.login`/`organization.login` does not match the owner segment of `repository.full_name`. Additionally, treat a missing `webhook_secret` as "reject all webhooks for this org" rather than "auto-verify", or at minimum require every configured organization to have a non-blank `webhook_secret` before the app boots/accepts webhooks.

### Proof of Concept
Assume `Shipit.github` is configured with two orgs: `NoSecretOrg` (no `webhook_secret`, as in `config/secrets.development.shopify.yml`) and `VictimOrg` (has `webhook_secret` and hosts a real `Stack` for `VictimOrg/app`).

```http
POST /webhooks HTTP/1.1
X-Github-Event: push
X-Hub-Signature: sha1=deadbeef   (arbitrary/invalid)
Content-Type: application/json

{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-but-real-upstream-sha>",
  "repository": {
    "owner": { "login": "NoSecretOrg" },
    "full_name": "VictimOrg/app"
  }
}
```

- `WebhooksController#repository_owner` returns `"NoSecretOrg"`.
- `Shipit.github(organization: "NoSecretOrg").verify_webhook_signature(...)` returns `true` immediately because `webhook_secret` is blank (`lib/shipit/github_app.rb:76-77`), regardless of the bogus `X-Hub-Signature`.
- `verify_signature` passes; `create` proceeds and calls `PushHandler.call(params)`.
- `PushHandler#stacks` resolves via `Repository.from_github_repo_name("VictimOrg/app")` (from `repository.full_name`), locating the real `VictimOrg` stack and enqueuing `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` — all without ever validating a signature against `VictimOrg`'s actual `webhook_secret`.

Note: I was not able to execute this against a running instance from this environment; the PoC is derived directly from the cited source and would need to be validated end-to-end (e.g. via a background Devin session) against an actual multi-org Shipit deployment to confirm the downstream `GithubSyncJob`/continuous-delivery effects.

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

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```
