### Title
Webhook signature verification silently bypassed when an attacker-selected organization has no `webhook_secret` configured - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks *which* GitHub App/secret to verify a webhook against using a field (`repository.owner.login` / `organization.login`) taken directly from the unauthenticated, attacker-controlled JSON body. If the organization named in that body has no `webhook_secret` configured (an explicitly documented, supported configuration state), `GitHubApp#verify_webhook_signature` trivially returns `true` for any payload, and the same attacker-controlled payload is then dispatched to webhook handlers that mutate Shipit state (create teams/users, update PR/commit status, trigger merges, etc.) for whatever repository the attacker names in that payload.

### Finding Description
The controller resolves the verifying `GitHubApp` from the payload itself: [1](#0-0) [2](#0-1) 

`repository_owner` is read straight out of `request.raw_post`/`params`, with no verification performed yet — it is exactly the datum that is later trusted to decide which secret should have authenticated the request. `Shipit.github(organization: repository_owner)` looks up that organization's configured `GitHubApp`, and the actual cryptographic check is: [3](#0-2) 

Note line 77: `return true unless webhook_secret`. If the organization selected by the attacker-controlled `repository_owner` field has no `webhook_secret` set, verification is skipped entirely and `verified` is `true` regardless of any signature header.

This is not a hypothetical misconfiguration — `webhook_secret` being absent is a first-class, documented configuration option, shown as `webhook_secret: # nil` in both the single-org and multi-org example secrets files: [4](#0-3) [5](#0-4) 

The setup docs likewise document multi-organization deployments where each org gets its own independent `github.<org>.webhook_secret` entry: [6](#0-5) 

Putting this together: in any multi-org deployment where at least one configured organization has `webhook_secret` unset (a documented, valid state), an attacker with no credentials can submit a raw HTTP POST to `/github/webhooks` with `repository.owner.login` set to that org's name, and any `repository.name`/branch/etc. they like. `verify_signature` will resolve to that org's `GitHubApp`, `verify_webhook_signature` returns `true` unconditionally (no secret to check against), and the payload is passed unmodified to `Shipit::Webhooks.for_event(event)` handlers: [7](#0-6) 

The binding that should hold is: `organization whose secret gates verification == organization that actually authenticated the request cryptographically`. It breaks because the "verification" step for a secret-less org degenerates to a no-op — the field chosen out of the untrusted payload effectively becomes its own attestation.

### Impact Explanation
Handlers dispatched via `Shipit::Webhooks.for_event` operate on stacks/repositories/users identified from this same forged payload — e.g. `membership_handler.rb` creates `Team`/`User` records on the fly, `push_handler.rb`/`status_handler.rb`/`pull_request/*_handler.rb` mutate commit and PR status which feeds Shipit's merge queue and continuous-deployment logic. An attacker can therefore inject arbitrary, unauthenticated cross-repository state changes (fake CI status making a commit deployable, fake `pull_request` merged/labeled events, fake team membership) for any stack belonging to an org whose `webhook_secret` happens to be unset, which is an explicitly supported configuration in this engine — satisfying the "cross-repository writes" / "unauthorized deploy" impact bar.

### Likelihood Explanation
Requires only that the deployment be a multi-organization Shipit instance (documented and supported) with at least one org configured without a `webhook_secret` (documented as a valid, non-error configuration: `webhook_secret: # nil`). No credentials, tokens, or prior access are needed — a single unauthenticated HTTP POST suffices. This is a realistic, in-scope condition rather than a "host app not mounting the engine as documented" scenario.

### Recommendation
Do not let `verify_webhook_signature` silently return `true` when `webhook_secret` is blank; either require a `webhook_secret` for every configured organization at boot (fail closed) or reject (422) webhooks for organizations lacking a secret instead of treating them as automatically verified. Additionally, do not trust `repository_owner`/`organization` extracted from the unauthenticated payload to select the verification secret before any cryptographic check has occurred — validate against the set of known, secret-bearing organizations only.

### Proof of Concept
1. Configure Shipit with `github.OrgA.webhook_secret: <real secret>` and `github.OrgB.webhook_secret:` left blank (per `docs/setup.md`'s multi-org example).
2. As an unauthenticated attacker, POST to `/github/webhooks` with header `X-Github-Event: membership` and body:
```json
{
  "action": "added",
  "team": { "id": 1, "name": "Attacker", "slug": "attacker", "url": "https://example.com" },
  "member": { "login": "attacker" },
  "organization": { "login": "OrgB" }
}
```
No `X-Hub-Signature` header, or any arbitrary value, is required.
3. `verify_signature` resolves `Shipit.github(organization: "OrgB")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` per `lib/shipit/github_app.rb:77`, and the forged `membership` event is processed, creating a `Team`/`User` in Shipit without any valid GitHub signature.

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

**File:** config/secrets.development.example.yml (L8-16)
```yaml
github:
  app_id:
  installation_id:
  webhook_secret: # nil
  private_key:
  oauth:
    id:
    secret:
    teams: # Optional
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

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
```
