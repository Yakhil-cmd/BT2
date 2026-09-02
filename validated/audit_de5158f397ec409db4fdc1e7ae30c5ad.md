### Title
Webhook signature verification is keyed on an attacker-controlled organization field that differs from the repository the event actually acts upon, allowing signature-bypass forgery of GitHub webhooks for any tracked stack - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
Shipit resolves which GitHub App/organization's `webhook_secret` to use for HMAC verification from a payload field (`repository.owner.login`, or `organization.login`) that is read *before* the signature is checked, while the handlers that actually act on the webhook (e.g. sync a stack, apply a commit status) key off a *different* payload field (`repository.full_name`). Because these two fields are never cross-checked, and because verification is a no-op when the resolved organization has no `webhook_secret` configured, an attacker can pick any unprotected organization to satisfy the "authenticated organization" check while pointing the actually-processed `repository.full_name` at a genuinely protected, tracked repository.

### Finding Description
`WebhooksController#verify_signature` selects the app config using a payload-controlled value: [1](#0-0) 

`repository_owner` is read directly from the unverified JSON body: [2](#0-1) 

`GithubApp#verify_webhook_signature` unconditionally returns `true` when no `webhook_secret` is configured for that resolved organization: [3](#0-2) 

Shipit explicitly supports multiple GitHub organizations, each with its own independent `webhook_secret`: [4](#0-3) 

Once the signature check "passes" (either genuinely, or vacuously because the chosen org has no secret), `WebhooksController#create` dispatches to the registered handlers using the raw, attacker-supplied payload: [5](#0-4) 

Handlers, however, resolve the target `Stack`/`Repository` from a completely different field of the same payload - `repository.full_name` - not `repository.owner.login`: [6](#0-5) 

For example, `PushHandler` uses that repository lookup to find real stacks and trigger a GitHub sync with an attacker-chosen `after` SHA: [7](#0-6) 

This is the broken binding: **the organization authenticated (`repository.owner.login`, used to pick the HMAC secret) is not required to equal the repository actually written to (`repository.full_name`, used by the handler)**. An attacker who has no `webhook_secret` for the real target org, but knows (or guesses) the name of *any* organization configured in Shipit without a `webhook_secret` (a common state for a low-traffic or newly onboarded org, or the default single-org install where `webhook_secret` is left blank per the setup docs' "(optional)" note), can forge `repository.owner.login` to that unprotected org while setting `repository.full_name` to the real, protected target repository.

### Impact Explanation
This is an authentication-bypass of the GitHub webhook trust boundary: normally only GitHub (holder of the shared `webhook_secret`) can produce events Shipit will act on for a given repository. With this flaw, an unauthenticated attacker can submit arbitrary, unsigned `push`, `status`, `check_suite`, `deployable_status`, `pull_request`, or `membership` events (any handler in `Shipit::Webhooks::DEFAULT_HANDLERS`) that are processed as if genuinely delivered by GitHub for the *real* target repository, as long as they can name any org in the same Shipit instance whose `webhook_secret` is unset. Demonstrated concretely via `PushHandler`, this lets the attacker force a `GithubSyncJob` (with an attacker-chosen `expected_head_sha`) against any tracked stack, and more broadly opens every other webhook handler (status updates, membership/team creation, pull request state changes) to unauthenticated forgery for repositories the attacker does not control the secret for. Because Shipit's continuous-delivery pipeline is gated by commit statuses/CI signals ingested through these same handlers, this class of forgery can influence which commits look deployable, moving the confidentiality/integrity boundary that the per-organization webhook secret is meant to enforce.

### Likelihood Explanation
Exploitation requires only network access to the public `/webhooks` endpoint (no authentication, no repository access) and knowledge of one organization name configured in the Shipit instance without a `webhook_secret` — a state explicitly supported and even shown as the default/optional configuration in the docs and secrets templates. No GitHub credentials, session, or `ApiClient` token are required, matching the "unprivileged attacker" constraint.

### Recommendation
Verify the HMAC signature using a secret bound to the same repository/organization that the payload will actually be applied to (derived consistently, e.g. always from `repository.full_name`'s owner, never from a value used only for secret selection when it can diverge from the acted-upon field). Additionally, do not treat a missing `webhook_secret` as an implicit "verified" state when other organizations in the same installation do have secrets configured; require an explicit `Shipit.disable_webhook_authentication`-style opt-in analogous to `Shipit.disable_api_authentication` rather than a per-org fallback that silently disables verification.

### Proof of Concept
1. Deploy Shipit configured with two organizations as in `config/secrets.development.shopify.yml`: `someorg` (no `webhook_secret` set) and `protectedorg` (a `webhook_secret` configured), where `protectedorg/real-app` is a tracked `Stack`.
2. Send:
```
POST /webhooks
X-Github-Event: push
Content-Type: application/json

{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "full_name": "protectedorg/real-app",
    "owner": { "login": "someorg" }
  }
}
```
No `X-Hub-Signature` header is required.
3. `verify_signature` resolves `repository_owner` = `"someorg"`, fetches its `GithubApp`, and since `webhook_secret` is blank, `verify_webhook_signature` returns `true` unconditionally (`lib/shipit/github_app.rb:76-77`).
4. `create` dispatches to `PushHandler`, which resolves the stack via `payload.dig('repository', 'full_name')` = `"protectedorg/real-app"` (`app/models/shipit/webhooks/handlers/handler.rb:36-38`) and calls `stack.sync_github(expected_head_sha: params.after)` for the real, protected stack — despite the request never being signed by `protectedorg`'s secret.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
