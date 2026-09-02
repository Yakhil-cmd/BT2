### Title
Webhook signature verification uses the payload's own `organization`/`repository.owner` to select the secret, letting one onboarded organization forge signed webhooks acting on another organization's repository - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which GitHub App/organization's `webhook_secret` to validate a signature against by reading `repository.owner.login` / `organization.login` directly from the *unverified* JSON body, while the handlers that actually act on the payload identify the target stack via a separate field, `repository.full_name`. These two fields are never cross-checked, so the organization whose secret authenticates the request can differ from the repository the request ends up mutating.

### Finding Description
`verify_signature` resolves the signing organization purely from attacker-controlled JSON: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` returns the `GitHubApp` config (and its `webhook_secret`) keyed to whatever organization name the attacker put in the payload, per the multi-tenant `github:` config that supports several distinct organizations each with their own secret: [3](#0-2) 

Once the signature check passes, the `create` action re-parses the *same* raw JSON and dispatches it to handlers unmodified: [4](#0-3) 

Every handler resolves the stack to act on via a completely different field, `repository.full_name`, with no relation enforced to `repository.owner.login`/`organization.login` used earlier for signing: [5](#0-4) 

For example, `PushHandler` looks up stacks by `repository_name` and triggers a GitHub sync for any matching stack: [6](#0-5) 

**Binding broken:** `organization authenticated by verify_signature` ≠ `repository/stack written by the handler via repository.full_name`.

An attacker who administers **any** organization already onboarded to the shared Shipit instance (a normal, documented multi-org deployment, as shown by the `github:` config supporting multiple orgs each with independent secrets) knows their own organization's `webhook_secret` because they configured it themselves when wiring up their org's GitHub App/webhook. They can then craft a payload where:
- `repository.owner.login` (or `organization.login`) = their own organization (used only to pick the signing secret)
- `repository.full_name` = a victim organization's repository, already tracked as a Shipit stack

Because `verify_signature` computes the signature over the raw body using the attacker's own known secret, the signature check succeeds even though the payload semantically targets a different organization's repository.

### Impact Explanation
Passing this check lets the attacker drive any registered handler against a victim repository's stacks without ever possessing that organization's credentials:
- `push` events invoke `stack.sync_github(expected_head_sha: ...)`, which queues `GithubSyncJob` to pull and record new commits for the victim stack; on stacks with `continuous_deployment` enabled (a supported and common configuration, cf. fixture `continuous_deployment: true`), this can trigger an automatic, unauthorized deploy of attacker-chosen commits.
- `status`/`check_suite` events can inject fabricated CI state for the victim's commits, which factors into merge/deploy gating logic (`ci.blocking`, `merge.require`, etc.), enabling bypass of required-checks before merges/deploys.

This crosses the "an organization that authenticated versus the repository that is written" trust boundary and can result in an unauthorized deploy on a repository the attacker does not control — a Critical-tier outcome per the defined impact categories.

### Likelihood Explanation
Requires only that the attacker control (or be granted) one organization already integrated with the shared Shipit deployment — no privileged Shipit account, no `ApiClient` token, and no access to the victim organization's actual `webhook_secret` is needed. Any tenant on a multi-org Shipit instance can mount this against any other tenant's tracked repositories, making this readily reachable in the documented multi-organization setup.

### Recommendation
After `verify_webhook_signature` succeeds, cross-validate that the organization used to select the `webhook_secret` matches the owner of `repository.full_name` (or `organization.login`) actually referenced by the payload body being processed, rejecting the request if they diverge, rather than trusting `repository_name` independently in each handler.

### Proof of Concept
1. Attacker administers `attacker-org`, onboarded to the shared Shipit instance with `webhook_secret = S`.
2. Attacker crafts a `push` payload:
   ```json
   {
     "ref": "refs/heads/master",
     "after": "<attacker-chosen sha already present on victim repo>",
     "repository": {
       "full_name": "victim-org/victim-repo",
       "owner": { "login": "attacker-org" }
     }
   }
   ```
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(S, payload)`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "attacker-org")` (from `repository.owner.login`), which uses secret `S`, and the signature validates.
5. `create` dispatches the payload to `PushHandler`, which resolves stacks via `payload.dig('repository','full_name') == "victim-org/victim-repo"` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen sha>")` on the victim's stack, triggering sync (and potentially an automatic deploy if continuous deployment is enabled) — all authenticated only by the attacker's own organization's secret.

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
