### Title
Signature verification keyed on `repository.owner.login` while stack lookup is keyed on `repository.full_name` allows cross-organization forged webhooks to trigger writes on unrelated repositories - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization config (and therefore which `webhook_secret`) to use for HMAC verification based on `repository.owner.login` read straight out of the unauthenticated JSON body, then verifies the signature against the *entire* raw body using that org's secret. [1](#0-0)  Once the signature check passes, the same body is handed to event handlers that instead resolve the target `Stack`/`Repository` using a *different* payload field, `repository.full_name`. [2](#0-1)  Nothing binds these two fields together, so an attacker who controls a GitHub organization/App configured in this Shipit instance (and therefore legitimately knows that org's `webhook_secret`) can set `repository.owner.login` to their own org (to pass signature verification with a secret they know) while setting `repository.full_name` to point at a completely unrelated, victim-owned repository tracked by this Shipit instance.

### Finding Description
This is the direct analog of the Mellow report's root cause: a value used to authorize an action (`amount`/staking-module intent) is not the same value actually acted upon at execution time, so the binding between "what was authorized" and "what was executed" is broken. Here the equality that must hold is:

`organization used to select/verify webhook_secret == owner of the repository the handler will write to`

Concretely:
- `WebhooksController#repository_owner` reads `params.dig('repository', 'owner', 'login')` (or `organization.login`) from the still-unverified JSON body to decide which `Shipit.github(organization:)` config (and its `webhook_secret`) to verify the signature with. [3](#0-2) 
- `verify_webhook_signature` then HMACs the *raw* request body against that chosen secret. [4](#0-3) 
- Once verified, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the whole, attacker-authored body to handlers. [5](#0-4) 
- `Handler#stacks` resolves the target stacks via `Repository.from_github_repo_name(repository_name)`, where `repository_name` comes from `payload.dig('repository', 'full_name')` - a completely separate JSON field from the one used for org/secret selection. [2](#0-1) 
- `PushHandler#process` then calls `stack.sync_github(expected_head_sha: params.after)` on every matching, non-archived stack for the resolved repository/branch. [6](#0-5) 

Shipit explicitly supports multiple GitHub organizations each with its own independent `webhook_secret` in the same instance (documented in `config/secrets.development.shopify.yml` and `docs/setup.md`), [7](#0-6)  so it is architecturally expected that distinct orgs have distinct, mutually-unknown secrets - yet nothing stops a payload claiming org A's ownership (to pass verification with A's known secret) from naming org B's repository as the actual write target.

Before the attacker's request: stack state for the victim repository reflects only pushes verified via the victim org's own `webhook_secret`.
After the attacker's request: a signature computed with organization A's secret (known to the attacker, since they administer/own org A's GitHub App configuration in this Shipit instance) authorizes a `GithubSyncJob`/status/check-run write against a stack belonging to organization B's repository, because `repository.full_name` was never checked against `repository.owner.login`.

### Impact Explanation
This breaks the binding "organization that authenticated versus the repository that is written" called out in scope - the closest match to the Critical category "cross-repository writes." An attacker with legitimate access to one configured organization/App (and thus its own real `webhook_secret`) can forge signed-but-cross-repo events (`push`, `status`, `check_suite`, etc.) that cause Shipit to re-sync commits, create commit statuses, or refresh check runs for a stack/repository they do not control, without ever needing that repository's own webhook secret. Depending on which handler is targeted, this can inject attacker-controlled commit metadata/status into a victim's deploy pipeline or trigger unwanted `GithubSyncJob` executions against a victim stack, undermining the deployment-trust boundary between tenants of a shared Shipit instance.

### Likelihood Explanation
Requires the attacker to control (or have credentials for) at least one GitHub organization/App configured in the same Shipit instance - i.e., a legitimate but limited-scope credential, not a privileged Shipit account, `ApiClient` token, or the private GitHub App key. This matches the "unprivileged attacker" framing: they are unprivileged with respect to the victim's repository, yet the app-level design (per-organization `webhook_secret`, no cross-field validation between `repository.owner.login` and `repository.full_name`) lets that limited credential reach into another tenant's data.

### Recommendation
In `WebhooksController#verify_signature`/`#repository_owner`, and in `Handler#repository_name`, derive both the organization used for secret lookup and the repository used for stack resolution from the same, single trusted field (e.g. always take the owner from `repository.full_name`, or require `repository.owner.login` to match the owner segment of `repository.full_name` before dispatching to handlers), and reject the webhook if they disagree.

### Proof of Concept
1. Shipit is configured with two organizations, `attacker-org` and `victim-org`, each with its own `webhook_secret` (as in the documented multi-org config).
2. Attacker crafts a JSON body:
```json
{
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" },
  "ref": "refs/heads/main",
  "after": "deadbeef...attacker-chosen-sha"
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(attacker-org's webhook_secret, body)` - a secret they legitimately possess.
4. `POST /github/webhooks` with `X-Github-Event: push`.
5. `WebhooksController#repository_owner` returns `"attacker-org"`, `Shipit.github(organization: "attacker-org")` looks up attacker's own app config, and `verify_webhook_signature` succeeds because the attacker signed with their own known secret. [1](#0-0) 
6. `PushHandler` resolves stacks via `repository.full_name = "victim-org/victim-repo"` and calls `stack.sync_github(expected_head_sha: "deadbeef...")` on victim's stack, entirely bypassing victim-org's own webhook secret. [2](#0-1) [6](#0-5)

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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
