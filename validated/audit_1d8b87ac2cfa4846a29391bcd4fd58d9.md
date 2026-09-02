### Title
Webhook signature verification uses an unverified `repository.owner.login` field to pick the signing secret, while handlers act on the unverified `repository.full_name` field — confused-deputy bypass of webhook authentication in multi-org setups - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to validate a webhook against using `repository_owner`, a value read directly out of the *unverified* JSON body. `GithubApp#verify_webhook_signature` trivially returns `true` when the selected app has no `webhook_secret` configured. Meanwhile, all the webhook handlers (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, via `Handler#repository_name`) locate the target `Stack`/`Commit` using a *different* field of the same unverified body: `repository.full_name`. In a multi-organization Shipit deployment where at least one configured GitHub organization has no `webhook_secret` set, an attacker can forge a webhook whose `repository.owner.login`/`organization.login` names the secret-less org (to skip signature verification entirely) while `repository.full_name` names an entirely different, real, secret-protected target repository/stack. This breaks the intended binding "organization that authenticated == repository that is written".

### Finding Description
`verify_signature` picks the app config to verify against based on an unverified field: [1](#0-0) [2](#0-1) 

The signature check for the chosen app skips verification entirely when that app has no secret configured: [3](#0-2) 

Once the before_action passes, the raw JSON is dispatched unchanged to the handlers: [4](#0-3) 

But every handler determines the actual target repository from a *separate* field — `repository.full_name` — not from `repository.owner.login`: [5](#0-4) 

`PushHandler` uses that repository lookup to enqueue a sync against real stacks: [6](#0-5) 

`StatusHandler` writes commit statuses for any commit matching the given SHA, again independent of `repository_owner`: [7](#0-6) 

The application explicitly documents/supports configuring per-organization secrets, some of which can legitimately be left blank (`webhook_secret: # nil`), confirming this is a realistic deployment configuration, not a hypothetical: [8](#0-7) 

Root cause: the field used to select/verify the cryptographic binding (`repository_owner`, driving which `webhook_secret` is checked) is not the same field the business logic subsequently trusts to select the repository being mutated (`repository.full_name`). An attacker fully controls both fields in the unauthenticated raw POST body, since no HMAC covers the *relationship* between them — only whichever secret happens to get selected for the (attacker-chosen) `repository_owner`.

### Impact Explanation
This crosses the "unauthenticated write" boundary the rules define as High/Critical: an unprivileged attacker can submit webhook events (`push`, `status`, `check_suite`) that appear to originate from GitHub for a real, secret-protected stack, without ever knowing that stack's `webhook_secret`, as long as any other configured organization in the same Shipit instance has no secret set. Consequences:
- `push` events falsely trigger `GithubSyncJob` for a real stack (`stacks.not_archived.where(branch:).find_each { |stack| stack.sync_github(expected_head_sha:) }`), which can drive Shipit's normal continuous-delivery pipeline to pick up an attacker-claimed head SHA/state.
- `status` events let an attacker fabricate CI status for a real commit (`commit.create_status_from_github!(params)`), which `ci.require` checks rely on to gate automatic deploys — i.e., this can be used to force a commit past CI-status guardrails, contributing to an unauthorized deploy.

This matches the required impact bar: "an unauthorized deploy" / "unauthenticated ... write" via a broken repository-authentication binding.

### Likelihood Explanation
Requires only that the Shipit instance is configured for multiple GitHub organizations and that at least one configured org lacks a `webhook_secret` (a state the project's own example configs show as valid/expected, and something the project documents as optional per-org config). No credentials, tokens, or GitHub App keys are needed by the attacker — only knowledge of the target repository's `full_name` and any org name in the multi-org config that has no secret. This is a plausible, not merely theoretical, misconfiguration in real deployments supporting several GitHub orgs with differing security postures (e.g., a sandbox/staging org left unsecured).

### Recommendation
- Verify the webhook signature using the secret associated with the repository actually referenced by `repository.full_name`, not a separately-controlled `repository.owner.login`/`organization.login` field, or require that both resolve to the same organization before trusting either.
- Do not allow `verify_webhook_signature` to unconditionally pass (`return true unless webhook_secret`) for any organization that hosts stacks; require every configured GitHub App used to receive webhooks to have a non-blank `webhook_secret`, and refuse to process events for orgs without one.
- Cross check that the resolved `Repository`'s owner matches the same GitHub App configuration entry that was used for signature verification before dispatching handlers.

### Proof of Concept
1. Configure Shipit for two organizations: `secure-org` (has stacks, `webhook_secret: <real-secret>`) and `sandbox-org` (no `webhook_secret` configured).
2. As an unauthenticated attacker, POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeef000000000000000000000000000000",
  "repository": {
    "owner": { "login": "sandbox-org" },
    "full_name": "secure-org/production-service"
  }
}
```
No `X-Hub-Signature` header (or an arbitrary one) is needed.
3. `verify_signature` calls `Shipit.github(organization: "sandbox-org")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally — the request passes.
4. `PushHandler#process` resolves the target via `payload.dig('repository', 'full_name')` = `"secure-org/production-service"`, finds the real stack, and enqueues `GithubSyncJob` with the attacker-supplied `expected_head_sha`, even though the attacker never had `secure-org`'s webhook secret.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
