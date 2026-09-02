### Title
Webhook organization-authentication does not bind to the repository/stack the event mutates - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App (and therefore which `webhook_secret`) to validate a webhook against using the **unverified** `repository.owner.login` (or `organization.login`) field of the JSON body, while every event handler subsequently determines *which Shipit `Repository`/`Stack` to mutate* using an entirely different, equally unverified field: `repository.full_name` [1](#0-0) . Nothing ties "the organization whose secret validated this delivery" to "the repository the handler acts on."

### Finding Description
`verify_signature` does:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
```
where `repository_owner` is read straight from the attacker-supplied body [2](#0-1) [3](#0-2) .

`GitHubApp#verify_webhook_signature` explicitly no-ops when no secret is configured for that org:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
``` [4](#0-3) 

`webhook_secret` is documented as **optional** per organization [5](#0-4) , and the shipped config templates ship it as `nil` by default (e.g. `test/dummy/config/secrets_double_github_app.yml`, `config/secrets.development.shopify.yml`) [6](#0-5) .

Once `verified` is true (or a valid signature is produced with a known secret for *any* one configured organization), `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` runs with the raw, attacker-controlled `params` [7](#0-6) . Every handler (`PushHandler`, `StatusHandler`, etc.) resolves its target purely from `payload.dig('repository', 'full_name')`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [8](#0-7) 

`PushHandler#process` then triggers a real state mutation, `stack.sync_github(expected_head_sha: params.after)`, for whatever stack matches that field [9](#0-8) .

**Equality that should hold but does not:** `organization used to select/pass the signature check == organization owning the repository the handler subsequently writes to`. Both sides are read from the same unauthenticated payload, but from two different keys (`repository.owner.login`/`organization.login` vs `repository.full_name`), and the authentication step never cross-checks them.

### Impact Explanation
If **any single** GitHub App configured in the Shipit deployment (a common multi-org setup, see `test/dummy/config/secrets_double_github_app.yml`) has no `webhook_secret` set — which the docs call an optional field — the signature check becomes a no-op for requests claiming that organization. An attacker can then submit a `push` (or `status`/`check_suite`) webhook with `repository.owner.login` set to that unprotected organization but `repository.full_name` set to any *other* tracked repository (belonging to an organization that does enforce webhook secrets). The request sails through `verify_signature`, and the handler blindly acts on the forged `repository.full_name`, causing `GithubSyncJob`/`stack.sync_github` to run with an attacker-chosen `expected_head_sha` for a stack the attacker has no relationship to. This is a cross-repository write (Critical) — Shipit's tracked commit/stack state for a repo can be manipulated by anyone able to guess or discover a single loosely-configured organization login, without holding that organization's credentials or webhook secret at all.

### Likelihood Explanation
Requires only: (1) knowledge that Shipit tracks a repository under `Org/Repo`, and (2) that at least one configured GitHub App in that Shipit instance has no `webhook_secret` (an officially "optional" setting, and the norm in the shipped example/dummy configs). No token, no repository write access, no GitHub App key is needed — an outsider only needs to POST to the public `/webhooks` endpoint. This does not require compromising `webhook_secret`, `api_clients_secret`, or any session; the vulnerability is precisely that one org's *absence* of a secret undermines authentication for unrelated, attacker-named repositories.

### Recommendation
Bind the two fields together before trusting the payload:
- After selecting `github_app` via `repository_owner`, require that `payload.dig('repository', 'owner', 'login')` (or `organization.login`) equals `payload.dig('repository', 'full_name').split('/').first` before dispatching to handlers, rejecting mismatches with 422.
- Do not allow `verify_webhook_signature` to silently return `true` when `webhook_secret` is blank for a repository that is otherwise tracked with a signature-enforcing sibling organization; consider requiring a non-blank `webhook_secret` for every configured organization, or at minimum failing closed instead of open when unset.

### Proof of Concept
1. Shipit instance configures two GitHub Apps: `orgA` (no `webhook_secret`, e.g. left blank as in `config/secrets.development.shopify.yml`) and `orgB` (`webhook_secret` set, and Shipit tracks `orgB/critical-repo`).
2. Attacker (no credentials) POSTs to `/webhooks`:
```
X-Github-Event: push
Body:
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen existing sha>",
  "repository": {
    "owner": { "login": "orgA" },
    "full_name": "orgB/critical-repo"
  }
}
```
3. `WebhooksController#verify_signature` calls `Shipit.github(organization: "orgA")`, whose `verify_webhook_signature` returns `true` unconditionally because `orgA` has no `webhook_secret` [10](#0-9) .
4. `PushHandler` resolves `repository_name` as `orgB/critical-repo` [11](#0-10)  and calls `stack.sync_github(expected_head_sha: "<attacker-chosen sha>")` on `orgB`'s protected stack [9](#0-8) , an unauthorized cross-repository state mutation performed by an attacker who never authenticated to `orgB` at all.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

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

**File:** docs/setup.md (L26-30)
```markdown
  - Homepage URL: The URL where Shipit will be deployed, e.g. `https://example.com`.
  - User authorization callback URL: It must be set to `<homepage>/github/auth/github/callback`, e.g. `https://example.com/github/auth/github/callback`.
  - Setup URL: Leave it empty.
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

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
