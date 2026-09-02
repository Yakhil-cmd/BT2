### Title
Webhook signature is verified against the organization derived from `repository.owner.login`/`organization.login`, but the handlers act on the repository from `repository.full_name` — allowing cross-repository/cross-tenant webhook forgery in multi-org deployments - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In a multi-organization Shipit deployment, `WebhooksController#verify_signature` selects which organization's HMAC secret to validate the incoming payload against using `repository_owner`, taken directly from the untrusted payload (`repository.owner.login`, falling back to `organization.login`). Once the signature check passes, `create` dispatches the *entire, attacker-controlled* JSON payload to the event handlers, which independently resolve the target `Repository`/`Stack` using a different, also attacker-controlled, field: `repository.full_name`. Because these two fields are never cross-checked, a valid signature for organization A's webhook secret can be replayed with a payload whose `full_name` points at organization B's repository, letting the handler act on a stack the attacker does not control.

### Finding Description
`Shipit.github(organization: repository_owner)` picks the `GitHubApp` (and its `webhook_secret`) using: [1](#0-0) 

That app instance is then used to verify the signature over the raw request body: [2](#0-1) [3](#0-2) 

Shipit explicitly supports configuring multiple, independent GitHub organizations, each with its own `webhook_secret`: [4](#0-3) 

Once `verify_signature` passes, the full raw payload is parsed and dispatched to handlers unmodified: [5](#0-4) 

Handlers resolve the target `Stack`/`Repository` using a *separate* payload field — `repository.full_name` — with no relationship enforced to the `repository_owner`/organization used for signature verification: [6](#0-5) 

`PushHandler`, for example, uses this resolved repository to select stacks and trigger a GitHub sync for them: [7](#0-6) 

**The equality that should hold but doesn't:** the organization whose secret authenticated the request (`repository_owner` → `Shipit.github(organization:)`) must equal the organization that owns the repository the handler acts on (`repository.full_name`'s owner). The controller only checks the former; the handler only trusts the latter. Both come from the same attacker-supplied JSON body, so an attacker who legitimately controls a GitHub App/organization configured on the shared Shipit instance (and therefore knows that organization's `webhook_secret`) can sign a payload with `repository.owner.login`/`organization.login` set to their own org (to pass `verify_signature`), while setting `repository.full_name` to `otherorg/other-repo` — a stack belonging to a different tenant on the same Shipit instance. The forged, validly-signed request is then processed against the victim's stack.

### Impact Explanation
This breaks the tenant/organization isolation that per-organization `webhook_secret`s are meant to provide: a party who is authorized to send webhooks for organization A can forge events that act on organization B's repositories/stacks in a shared Shipit installation. Depending on handler (`push`, `status`, `check_suite`, `pull_request`), this causes cross-repository side effects — e.g., `PushHandler` triggers `stack.sync_github`, and other handlers create commit statuses or manage review stacks/merge requests for a repository the attacker's credentials were never scoped to. This is a cross-repository write performed by presenting a signature that authenticates a different repository owner than the one being written — matching the required "Critical: cross-repository writes" impact bucket, and is a direct structural analog of the Pyth bug class: a field that is trusted/acted upon (`repository.full_name`) is never bound by the same verification (`webhook_secret`/`repository_owner`) that is supposed to authorize the request.

### Likelihood Explanation
Requires the operator to run a multi-organization Shipit instance (explicitly documented/supported configuration) and requires the attacker to control a legitimate GitHub App installation (and thus its `webhook_secret`) for at least one of the configured organizations — this is realistic in shared/hosted Shipit deployments serving multiple orgs, where a "low-trust" org's own admins are the attackers targeting a "high-trust" org's stacks on the same instance. No repository write access, session, or `ApiClient` token is needed — only knowledge of one org's webhook secret, which the attacker legitimately possesses.

### Recommendation
When resolving the target stack/repository in `Shipit::Webhooks::Handlers::Handler#repository_name`/`#stacks`, verify that the repository's owning organization matches the `repository_owner` (or `GitHubApp organization`) that was used to authenticate the webhook signature in `WebhooksController#verify_signature`. Reject (422) any payload where these two organization identifiers diverge, so a signature valid for org A can never be used to act on org B's repositories.

### Proof of Concept
1. Shipit is configured with two organizations, `orga` and `orgb`, each with its own `webhook_secret` (per `config/secrets.development.shopify.yml` multi-org format).
2. Attacker controls the GitHub App / webhook secret for `orga` (their own legitimate org on the shared instance).
3. Attacker crafts a `push` payload body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker chosen sha>",
  "repository": {
    "owner": { "login": "orga" },
    "full_name": "orgb/victim-repo"
  }
}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(orga_webhook_secret, raw_body)` and POSTs to `/webhooks` with `X-Github-Event: push`.
5. `WebhooksController#verify_signature` calls `Shipit.github(organization: 'orga')` (from `repository.owner.login`) and validates successfully against `orga`'s secret [2](#0-1) .
6. `create` dispatches the full payload to `PushHandler`, which resolves the stack via `payload.dig('repository','full_name')` = `orgb/victim-repo` [8](#0-7) , and triggers `stack.sync_github(expected_head_sha: ...)` for `orgb`'s stack [7](#0-6)  — a stack the attacker was never authorized to send webhooks for.

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
