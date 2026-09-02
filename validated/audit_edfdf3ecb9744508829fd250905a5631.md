### Title
Webhook signature verification is bound to `repository.owner.login` while event handling is bound to `repository.full_name`, allowing signature bypass for a secured stack via a sibling unsecured organization — ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which `GitHubApp`/`webhook_secret` to verify the HMAC signature against using the `repository.owner.login` (or `organization.login`) field taken directly from the unauthenticated JSON body, while the actual event handlers select the target `Stack`/`Repository` using a *different* field of the same body, `repository.full_name`. Because Shipit supports independently-configured, per-organization `webhook_secret`s, and `verify_webhook_signature` treats a blank secret as automatically valid, an attacker can pick any organization in the install that has no `webhook_secret` configured to satisfy signature verification, while pointing `repository.full_name` at a stack belonging to a different, properly-secured organization.

### Finding Description
`verify_signature` resolves the verifying app before checking the signature: [1](#0-0) 

`repository_owner` is derived entirely from attacker-controlled JSON, with no relation to the signature yet: [2](#0-1) 

`GitHubApp#verify_webhook_signature` short-circuits to `true` whenever that organization's `webhook_secret` is blank: [3](#0-2) 

Per-organization configuration with an optional/blank `webhook_secret` is a documented, first-class Shipit deployment shape: [4](#0-3) 

Once verification passes (against the attacker-chosen, secret-less organization), the raw payload is dispatched to handlers, which resolve the target stack using a **different** field, `repository.full_name`, never bound to the signature check that just occurred: [5](#0-4) [6](#0-5) 

This breaks the binding: `organization authenticated by verify_signature` ≠ `repository/stack acted upon by the handler`. Before the attack, an org's webhook secret only authorizes events for that org's own repositories. After the attacker's crafted request, the same "verified" request is accepted as a legitimate event for a completely different, secured organization's stack, because the field used to pick the verifying secret (`repository.owner.login`/`organization.login`) is decoupled from the field used to pick the affected stack (`repository.full_name`).

### Impact Explanation
An attacker with no credentials can forge `push`, `status`, or `check_suite` events for any stack belonging to a properly-secured organization, as long as any other organization configured in the same Shipit instance has no `webhook_secret` set (an explicitly supported, documented configuration). This can inject a fabricated `push` event to trigger `GithubSyncJob` for an arbitrary `expected_head_sha`, or a fabricated `status` event to create fake commit `Status` records used by deploy gating, which can defeat CI-status-based deploy checks and lead to an unauthorized deploy of unvetted code — one of the explicitly listed Critical impacts.

### Likelihood Explanation
The prerequisite (one organization among several configured without a `webhook_secret`) is explicitly presented as an optional setting in the setup documentation and example config, making this realistic in multi-organization Shipit deployments. No credentials, sessions, or repository access are required — only knowledge of a target stack's repository full name, which is public information.

### Proof of Concept
1. Shipit is configured for two GitHub organizations: `victim-org` (has `webhook_secret` set, hosts a real Stack) and `unsecured-org` (no `webhook_secret`, per the documented optional setting).
2. Attacker sends `POST /webhooks` with header `X-Github-Event: push` and body:
```json
{
  "repository": {
    "owner": { "login": "unsecured-org" },
    "full_name": "victim-org/victim-repo"
  },
  "after": "<attacker-chosen-sha>"
}
```
3. `verify_signature` calls `Shipit.github(organization: "unsecured-org")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` regardless of the (missing/garbage) `X-Hub-Signature` header.
4. `create` proceeds and dispatches to `Handlers::PushHandler`, which resolves stacks via `repository.dig('repository','full_name')` → `victim-org/victim-repo`, processing the forged event against the victim's real stack.

### Recommendation
Bind signature verification to the same repository identity used for event dispatch: derive the verifying organization/secret strictly from the target `Stack`/`Repository` record resolved from `repository.full_name` (or require that the resolved repository's owner matches the org used for verification), rather than trusting `repository.owner.login`/`organization.login` from the unauthenticated payload in isolation. Additionally, do not allow a blank `webhook_secret` to implicitly authorize events for stacks owned by other, secured organizations in the same installation.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```
