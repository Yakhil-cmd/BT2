### Title
Webhook signature bypass via attacker-chosen, unconfigured GitHub organization allows forged events against any repository - (File: `app/controllers/shipit/webhooks_controller.rb`, `lib/shipit/github_app.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's webhook secret to verify against using a field taken directly from the *unauthenticated* request body, and `GithubApp#verify_webhook_signature` fails open (returns `true`) whenever that organization has no `webhook_secret` configured. Because the organization used to pick the verification key is attacker-controlled while the actual target of the event (the repository/stack acted upon) is a separate field in the same attacker-controlled body, an attacker can choose an organization with no configured secret to sail through signature verification, then supply a `repository.full_name` pointing at any stack managed by the Shipit instance, including ones belonging to organizations that *do* have a properly configured secret.

### Finding Description
`verify_signature` computes the organization to verify against purely from the incoming JSON, before any authentication has occurred: [1](#0-0) [2](#0-1) 

`repository_owner` is read straight from `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`), both of which are attacker-supplied JSON fields, not anything cryptographically bound to the request. This value is then used to look up which `GithubApp` (and therefore which `webhook_secret`) will validate the request: [3](#0-2) 

Critically, `verify_webhook_signature` returns `true unless webhook_secret` — i.e., if the organization selected by the attacker has *no* webhook secret configured, the signature check is skipped entirely, regardless of what `X-Hub-Signature` header value was supplied. Shipit's own setup docs and config templates confirm `webhook_secret` is optional and commonly left blank for one or more configured organizations: [4](#0-3) [5](#0-4) 

Once verification is bypassed, the same fully attacker-controlled JSON body is dispatched to event handlers, which independently determine which `Stack`/repository to act on via a *different* field, `repository.full_name`: [6](#0-5) 

This breaks the binding: `repository_owner used to select the verifying organization == repository/stack that the event actually writes to`. The attacker controls both sides of this equality independently in the same request, so they can satisfy authentication with an org that has no secret while writing state changes to any other repository/stack tracked by the instance (e.g., another org that does have a properly configured secret), because the webhook route/config is instance-wide, not scoped per organization once the request is processed by `WebhooksController#create`: [7](#0-6) 

### Impact Explanation
This crosses "unauthorized deploy, rollback, or merge" territory (Critical) because Shipit's webhook handlers drive core deployment-trust state: commit `status` events affect deployability, `check_suite` events trigger `RefreshCheckRunsJob`, `push` events sync branch state, and `pull_request`/`merge_status`/`merge` events participate in the merge queue. All of these are dispatched through the same `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` call once `verify_signature` passes, with the target determined purely by attacker-supplied `repository.full_name`. An attacker who can reach the public `/webhooks` endpoint (no GitHub App private key, no `webhook_secret`, no repository write access required) can inject forged status/push/check_suite events against arbitrary stacks, and thereby manipulate deploy-readiness, merge queue, or lock state for repositories they have no access to — a direct cross-repository write/unauthorized state change.

### Likelihood Explanation
Likelihood is Medium-to-High in realistic multi-organization deployments: the webhook secret is explicitly documented as optional, and the shipped example configs (`test/dummy/config/secrets_double_github_app.yml`, `config/secrets.development.shopify.yml`) show organizations configured with `webhook_secret: # nil`. Any Shipit instance that manages multiple GitHub orgs/apps and leaves even one of them without a secret (a supported, documented configuration) exposes every stack on the instance to forged events, not just the stacks belonging to the unsecured org.

### Recommendation
- Do not select the verification key from unauthenticated payload content. Verify the signature against every configured organization's secret (or minimally, do not allow `verify_webhook_signature` to return `true` when `webhook_secret` is blank — treat a missing secret as "reject all webhooks for that org" rather than "accept all").
- After choosing a verification key, ensure the same organization/repository identity used for verification is the one whose data is subsequently trusted; do not let handlers resolve an independent, attacker-controlled `repository.full_name` to route to arbitrary stacks once verification has passed for a different org.
- Make `webhook_secret` mandatory, or fail closed by rejecting requests when no secret is configured for the resolved organization.

### Proof of Concept
1. Configure Shipit with two GitHub orgs per `test/dummy/config/secrets_double_github_app.yml`-style setup: `OrgA` has `webhook_secret` set, `OrgB` has `webhook_secret: nil` (a documented, supported configuration).
2. Attacker (no credentials, no GitHub App key) sends `POST /webhooks` with header `X-Github-Event: status` and any `X-Hub-Signature` value (or none), and a JSON body:
```json
{
  "repository": { "owner": { "login": "OrgB" }, "full_name": "OrgA/secured-repo" },
  "sha": "<commit sha belonging to OrgA/secured-repo>",
  "state": "success",
  "target_url": "https://attacker.example/fake-ci"
}
```
3. `repository_owner` resolves to `"OrgB"`; `Shipit.github(organization: "OrgB")` has no `webhook_secret`, so `verify_webhook_signature` returns `true` unconditionally.
4. `create` proceeds and dispatches the `status` handler using `payload.dig('repository', 'full_name') == "OrgA/secured-repo"`, updating commit status for a commit in `OrgA`'s repository despite the request never being signed by `OrgA`'s secret.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end
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

**File:** docs/setup.md (L29-30)
```markdown
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
```

**File:** test/dummy/config/secrets_double_github_app.yml (L1-9)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
      # Randomly generated
      private_key: |
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
