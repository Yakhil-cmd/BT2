### Title
Webhook signature verification is keyed off an attacker-controlled field that is unrelated to the repository the payload actually mutates - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App (and thus which `webhook_secret`) to validate the HMAC signature against using `repository_owner`, a value read straight from the untrusted, not-yet-verified JSON body. All webhook `Handler` subclasses, however, resolve the stack/repository they act on using a *different* attacker-controlled field, `repository.full_name`, from that same body. Because these two fields are never cross-checked, and because `GithubApp#verify_webhook_signature` trivially returns `true` whenever the selected organization has no `webhook_secret` configured, an attacker can pick an organization without a secret to satisfy signature verification while pointing `repository.full_name` at a stack that belongs to an entirely different (secured) organization.

### Finding Description
`verify_signature` computes the org used to pick the verifying `GithubApp` purely from the request body: [1](#0-0) [2](#0-1) 

`GithubApp#verify_webhook_signature` bypasses HMAC checking entirely when no secret is configured for that org: [3](#0-2) 

Multi-org configuration is a documented, first-class feature, and the example/sample secrets files explicitly show `webhook_secret` as optional/nil per organization: [4](#0-3) [5](#0-4) 

Once signature verification passes (or is bypassed via the unsecured org), the raw, unauthenticated body is handed to the event handlers unchanged: [6](#0-5) 

Every `Handler` subclass then determines the target repository from a completely different payload field, `repository.full_name`, with no relation enforced to the `repository_owner` value used earlier for signature-organization selection: [7](#0-6) 

For example, `PushHandler` uses this to load and act on stacks (`stack.sync_github`): [8](#0-7) 

This breaks the intended binding: **organization whose credentials authenticated the request == organization/repository the payload is permitted to mutate**. Before the bug, this binding is implicitly assumed to hold because signature verification is thought to authenticate "this payload for this repo." After exploitation, an attacker sends one payload where `repository.owner.login` names an unsecured org (satisfying/bypassing verification) while `repository.full_name` names a repository under a different, secured org — so the signature check authenticates nothing about the repository actually acted upon.

### Impact Explanation
An unprivileged, unauthenticated attacker (anyone who can POST to `/webhooks`, which this controller explicitly does not require a session or API token for — it is designed for GitHub, but it does not otherwise bind the caller identity) can forge events against stacks belonging to a fully secured organization, as long as the Shipit deployment configures at least one other organization without a `webhook_secret` (an explicitly supported/documented configuration). This can trigger `GithubSyncJob`/`stack.sync_github`, fabricate commit `status` events consumed by deploy/merge gating logic, and drive `pull_request` handlers (open/close/label/review-stack), all without possessing any real GitHub webhook secret for the targeted organization. Depending on which handler is abused, this can influence merge/lock/status state that downstream deploy logic relies on, which is why this maps to the "unauthorized deploy/rollback/merge" or "authentication bypass" impact tiers described in scope.

### Likelihood Explanation
Requires: (a) a Shipit instance configured with multiple GitHub organizations, and (b) at least one of those organizations having no `webhook_secret` set — a state the shipped example/sample config files present as normal and optional. No credentials, sessions, or API tokens are needed; the attacker only needs network access to the public `/webhooks` endpoint that GitHub itself is expected to call. This is a realistic, low-effort exploitation path for any Shipit deployment following the documented multi-org setup without setting a secret on every entry.

### Recommendation
Bind the signature-verification organization decision to the same trusted source used for acting on the payload, and refuse to treat "no secret configured" as an automatic pass once any other configured organization has a secret. Concretely: verify the signature using the `GithubApp` that corresponds to the repository actually resolved via `Repository.from_github_repo_name(payload.dig('repository','full_name'))` (or equivalently require the resolved `Repository`'s owning organization to match `repository_owner`), and require this to happen before any handler runs. Additionally, consider making `webhook_secret` mandatory for every configured organization, since an org without a secret bypasses HMAC entirely (`GithubApp#verify_webhook_signature` returning `true`).

### Proof of Concept
1. Configure Shipit with two GitHub orgs: `SecuredOrg` (has `webhook_secret` set, owns repo `SecuredOrg/target-repo` with an existing Shipit stack) and `OpenOrg` (no `webhook_secret` configured), matching the documented multi-org config shape (`config/secrets.development.shopify.yml`).
2. POST to `/webhooks` with header `X-Github-Event: push` and a body such as:
```json
{
  "repository": {
    "full_name": "SecuredOrg/target-repo",
    "owner": { "login": "OpenOrg" }
  },
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>"
}
```
3. `verify_signature` computes `repository_owner == "OpenOrg"`, calls `Shipit.github(organization: "OpenOrg")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` regardless of the (even absent) `X-Hub-Signature` header.
4. `PushHandler` then resolves the target using `payload.dig('repository', 'full_name')` == `"SecuredOrg/target-repo"`, loads that stack, and calls `stack.sync_github(expected_head_sha: "<attacker-chosen sha>")` — a stack the attacker has no legitimate GitHub-verified relationship to.

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
