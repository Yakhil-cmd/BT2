### Title
Webhook signature verification is bypassed per-organization, allowing forged payloads to trigger syncs/deploys on unrelated stacks - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which organization's HMAC secret to check against using one field of the attacker-supplied JSON body (`repository.owner.login`/`organization.login`), while the handler that actually acts on the payload resolves the target repository/stack from a *different* field of the same body (`repository.full_name`). Because `GithubApp#verify_webhook_signature` unconditionally returns `true` when the selected organization has no `webhook_secret` configured, an attacker can pick, as the "verifying" organization, any org on the instance that has no secret set, while pointing `repository.full_name` at a completely different, secured organization's tracked repository — bypassing signature verification for that target stack entirely.

### Finding Description
`WebhooksController#repository_owner` derives the organization used for signature verification directly from the untrusted body: [1](#0-0) 

That organization is used to fetch the corresponding `GithubApp` config and check the signature: [2](#0-1) 

`GithubApp#verify_webhook_signature` short-circuits to `true` whenever the resolved organization has no `webhook_secret` configured, regardless of the signature header content: [3](#0-2) 

The instance-level config explicitly supports organizations with `webhook_secret: nil`, as shown in both the example/dev config and the test fixture, confirming this is a supported operating mode rather than a misconfiguration: [4](#0-3) [5](#0-4) 

Once `verify_signature` passes, `WebhooksController#create` dispatches the full attacker-controlled JSON to the registered handlers: [6](#0-5) 

The base `Handler` class, however, resolves the *repository/stack to act on* from an entirely different field of the same payload — `repository.full_name` — independent of whatever organization was used to authenticate the request: [7](#0-6) 

`PushHandler#process` uses that repository/stack resolution to trigger a GitHub sync for the branch and attacker-supplied `after` (target SHA) on every matching, non-archived stack: [8](#0-7) 

This breaks the equality that should hold: `organization verified via signature == organization owning the repository/stack that gets acted upon`. The verification key (`repository.owner.login` / `organization.login`) and the authorization key (`repository.full_name`) are read independently from the same forgeable JSON body, so an attacker can make them diverge.

### Impact Explanation
An unauthenticated, unprivileged attacker (no GitHub App key, no `webhook_secret`, no `ApiClient` token, no repository write access) can `POST` a crafted JSON body directly to the public webhooks endpoint. If the Shipit instance is configured to serve multiple GitHub organizations (as the engine's own config format supports via `github: { org1: {...}, org2: {...} }`) and even one such organization has no `webhook_secret` set — a state the codebase and its own example/test configs treat as valid — the attacker can:
1. Set `repository.owner.login` (or `organization.login`) to that unsecured organization's name to force `verify_signature` to unconditionally pass.
2. Set `repository.full_name` to point at any other organization's tracked repository that does have a real, secret-protected Stack.
3. Set `ref`/`after` to an arbitrary branch and commit SHA.

This forges a `push` event that reaches `PushHandler`, causing `Stack#sync_github` to run with an attacker-chosen `expected_head_sha` against a stack the attacker has no legitimate access to, without ever needing to know that stack's real webhook secret. Depending on downstream sync/deploy automation this can trigger unauthorized syncs and downstream deploy pipeline actions on a repository/stack the attacker does not control — an authentication-bypass style compromise of the deploy trust boundary the signature check exists to enforce.

### Likelihood Explanation
Likelihood is moderate-to-high for any multi-tenant Shipit deployment: the engine itself ships example configuration (`config/secrets.development.shopify.yml`) and test fixtures with `webhook_secret: nil`, and the code path explicitly special-cases "no secret configured" as an intentional bypass rather than a hard failure. Any deployment hosting several organizations where at least one intentionally or accidentally omits `webhook_secret` (e.g., a lower-priority or newly-added org) exposes every other organization's stacks to forged push events, with zero credentials required from the attacker.

### Recommendation
Bind the resolved-repository check to the same trust anchor used for verification: require that `repository.full_name`'s owner match the `repository_owner`/`organization` value used to select the webhook secret, and reject (422) on mismatch. Additionally, do not allow `verify_webhook_signature` to silently return `true` when `webhook_secret` is blank in any organization that also owns actionable stacks — either require a secret for all configured organizations or explicitly disable webhook processing for repositories belonging to unsecured organizations.

### Proof of Concept
1. Shipit is configured with two organizations, e.g. `unsecured-org` (no `webhook_secret`) and `secured-org` (real stacks, real `webhook_secret`).
2. Attacker sends:
```
POST /github/webhooks
X-Github-Event: push
X-Hub-Signature: sha1=deadbeef   (arbitrary/invalid)

{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "unsecured-org" },
    "full_name": "secured-org/production-app"
  }
}
```
3. `repository_owner` resolves to `unsecured-org`; `Shipit.github(organization: 'unsecured-org').verify_webhook_signature` returns `true` unconditionally because that org has no `webhook_secret` — see `lib/shipit/github_app.rb:76-77`.
4. `create` dispatches the payload to `PushHandler`, which resolves the stack via `repository.full_name` (`secured-org/production-app`) — see `app/models/shipit/webhooks/handlers/handler.rb:32-38` — and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on the `secured-org` stack, despite the attacker never possessing `secured-org`'s webhook secret.

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

**File:** test/dummy/config/secrets.test.json (L7-18)
```json
  "github": {
    "domain": null,
    "app_id": 42,
    "installation_id": 43,
    "bot_login": "shipit[bot]",
    "webhook_secret": null,
    "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA7iUQC2uUq/gtQg0gxtyaccuicYgmq1LUr1mOWbmwM1Cv63+S\n73qo8h87FX+YyclY5fZF6SMXIys02JOkImGgbnvEOLcHnImCYrWs03msOzEIO/pG\nM0YedAPtQ2MEiLIu4y8htosVxeqfEOPiq9kQgFxNKyETzjdIA9q1md8sofuJUmPv\nibacW1PecuAMnn+P8qf0XIDp7uh6noB751KvhCaCNTAPtVE9NZ18OmNG9GOyX/pu\npQHIrPgTpTG6KlAe3r6LWvemzwsMtuRGU+K+KhK9dFIlSE+v9rA32KScO8efOh6s\nGu3rWorV4iDu14U62rzEfdzzc63YL94sUbZxbwIDAQABAoIBADLJ8r8MxZtbhYN1\nu0zOFZ45WL6v09dsBfITvnlCUeLPzYUDIzoxxcBFittN6C744x3ARS6wjimw+EdM\nTZALlCSb/sA9wMDQzt7wchhz9Zh2H5RzDu+2f54sjDh38KqancdT8PO2fAFGxX/b\nqicOVyeZB9gv6MJtJc20olBbuXAeBNfcDABF9oxF+0i+Ssg7B4VXiqgcjtGbr/Og\nqRll7AqyTArVx2xEcVfZxeZ4zGnigzcJq4te7yYpxzwk+RxblkPh54Yt4WxZ+8DI\nRsn3r6ajlpwzpwvsJFU2Txq7xBTzGQMFmy/Pnjk83kP2cogxB2+tRyjITGqTwD8b\ngg9PFCkCgYEA+7u8A0l0C ... (truncated)
    "oauth": {
      "id": "Iv1.bf2c2c45b449bfd9",
      "secret": "ef694cd6e45223075d78d138ef014049052665f1",
      "teams": null
    }
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-23)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
```
