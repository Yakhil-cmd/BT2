### Title
Webhook signature is verified against `repository.owner.login`/`organization.login`, but handlers act on the independent `repository.full_name` field, allowing a forged push across organizations - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/handler.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to validate the HMAC signature with based on `params.dig('repository','owner','login')` (falling back to `params.dig('organization','login')`), while the actual repository/stack the webhook payload acts upon is selected in `Handler#repository_name` using the completely independent `payload.dig('repository','full_name')` field. Because both fields live in the same attacker-controlled JSON body and are read independently, whoever holds the `webhook_secret` for *any one* organization configured on a shared Shipit instance can sign an arbitrary payload with that secret while setting `repository.full_name` to point at a stack that belongs to a *different* organization tracked by the same instance.

### Finding Description
`verify_signature` looks up the signing key via the organization named in the payload: [1](#0-0) 
and the fallback for that lookup: [2](#0-1) 

Once the signature passes, the raw parsed payload is dispatched unmodified to handlers: [3](#0-2) 

Handlers, however, resolve the target `Stack`/`Repository` using a different field of the same payload: [4](#0-3) 

This is used e.g. by `PushHandler`, which fetches all stacks matching the (attacker-chosen) `full_name` and branch and triggers a GitHub sync: [5](#0-4) 

Shipit natively supports multiple GitHub organizations configured on a single instance, each with its own independent `webhook_secret`: [6](#0-5) [7](#0-6) 

**The broken binding**: `organization authenticated (via repository.owner.login/organization.login + webhook_secret)` should equal `organization that owns the repository being acted upon (repository.full_name)`. Nothing enforces this equality — an attacker who legitimately controls the GitHub App/webhook configuration for **their own** organization (Organization A, onboarded on the same Shipit instance) knows Organization A's `webhook_secret`. They can then POST a JSON body where:
- `repository.owner.login` (or `organization.login`) = `"organization-a"` → passes `verify_signature` using A's secret.
- `repository.full_name` = `"organization-b/victim-repo"` → routes the event to Organization B's stack in `Handler#repository_name`.

The controller and the handler each look at a different sub-tree of the same payload for two different purposes (authentication key selection vs. resource selection), and the signature covers only the raw bytes, not the semantic consistency between those two fields.

### Impact Explanation
On a Shipit instance hosting more than one organization (a documented, supported configuration — see `config/secrets.development.shopify.yml` and `lib/shipit/github_app.rb`), an actor who is unprivileged with respect to Organization B (no Shipit account, no repository write access to B, no `ApiClient` token) but who legitimately administers Organization A's GitHub App/webhook can forge signed webhook deliveries that make Shipit act on Organization B's stacks: e.g. force `PushHandler` to trigger `sync_github`/`GithubSyncJob` for an arbitrary tracked stack in another organization, or drive other handlers (`status`, `check_suite`, `membership`, `pull_request`) against victim repositories/organizations whose secret the attacker never possessed. Depending on stack configuration (`continuous_deployment`), a forced sync can lead to an out-of-schedule/unauthorized deploy of the real latest commit for that stack — this is an unauthorized deploy triggered via a cross-organization/cross-repository trust bypass, matching the "unauthorized deploy" and "cross-repository writes" impact classes in scope.

### Likelihood Explanation
Requires the attacker to already know one organization's `webhook_secret` configured on the same shared Shipit deployment (e.g. as an administrator of their own, otherwise legitimate, onboarded organization) — this is not a fully anonymous/unauthenticated attack, but it crosses a real trust boundary: knowledge of Org A's secret should never let you act on Org B's resources. This is directly analogous to the reported bug class ("value checked" ≠ "value used to compute effect") and is concretely reachable through this engine's own code, not a third-party gem defect.

### Recommendation
After verifying the HMAC signature for organization X, the handler dispatch must also confirm that the repository/organization actually referenced in the payload (`repository.full_name`'s owner, or `organization.login`) equals the organization X whose secret was used to verify the signature, before resolving stacks by `full_name`. Concretely, `Handler#stacks`/`#repository_name` in `app/models/shipit/webhooks/handlers/handler.rb` should reject (or the controller should pass along and enforce) that the owner segment of `repository.full_name` matches `repository_owner`/`organization.login` used in `verify_signature`.

### Proof of Concept
1. Shipit instance is configured with two organizations, `org-a` and `org-b`, each with distinct `webhook_secret`s (as shown in `config/secrets.development.shopify.yml`), each tracking their own repositories/stacks.
2. Attacker administers `org-a`'s GitHub App and therefore knows `org-a`'s `webhook_secret` (a value they are entitled to know for their own org, but not for `org-b`).
3. Attacker crafts a `push` payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<current head sha of org-b/victim-repo>",
  "repository": {
    "full_name": "org-b/victim-repo",
    "owner": { "login": "org-a" }
  }
}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC(org-a-secret, raw_body)` and POSTs to `/webhooks`.
5. `WebhooksController#verify_signature` calls `Shipit.github(organization: "org-a")` (from `repository.owner.login`) and the signature validates successfully.
6. `PushHandler#process` calls `Handler#repository_name`, which reads `payload.dig('repository','full_name')` = `"org-b/victim-repo"`, resolves `org-b`'s stack(s), and triggers `stack.sync_github(expected_head_sha: ...)` — an action the attacker was never authorized to trigger for `org-b`.

Note: I was unable to fully inspect `app/jobs/shipit/github_sync_job.rb` before running out of tool iterations, so I cannot fully confirm every downstream side effect of a forced sync (e.g., exact conditions under which `continuous_deployment` would auto-trigger a real deploy from this forced sync). This should be verified in a live/dynamic test against a Shipit instance to confirm the full deploy-triggering chain.

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

**File:** lib/shipit/github_app.rb (L44-57)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]

      oauth = (@config[:oauth] || {}).with_indifferent_access
      @oauth_id = oauth[:id]
      @oauth_secret = oauth[:secret]
      @oauth_teams = Array.wrap(oauth[:teams])
    end
```
