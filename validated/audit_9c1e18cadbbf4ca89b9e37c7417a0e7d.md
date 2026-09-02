### Title
Unauthenticated cross-organization commit-status forgery via unscoped `sha` lookup enables unauthorized deploys - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` binds a webhook's HMAC signature to the *organization* named in the payload (`repository.owner.login` / `organization.login`), but `StatusHandler` — which processes the `status` GitHub event — never re-checks that binding when deciding **which** commit/stack/repository to mutate. It looks up the target commit purely by `sha`, globally across the entire Shipit instance. An attacker who legitimately controls one organization onboarded into a shared Shipit deployment (and therefore knows/can generate that organization's own `webhook_secret`) can forge a `status` webhook that authenticates as *their* organization but writes a fabricated CI status onto a commit that belongs to a completely different organization's stack, because the two checks use different, uncorrelated fields of the same attacker-supplied JSON body.

### Finding Description
Signature verification selects the GitHub App / secret to check against using only the payload's own `repository`/`organization` field: [1](#0-0) [2](#0-1) 

Once the signature is accepted, the raw parsed JSON is dispatched to the event handler with no further correlation between the organization that produced a valid signature and the data that handler is about to act on: [3](#0-2) 

`StatusHandler`, unlike other handlers (`Handler#stacks`, which scopes via `Repository.from_github_repo_name(payload.dig('repository','full_name'))`), does not use the `repository` field at all — it matches purely by commit `sha` across the whole database: [4](#0-3) [5](#0-4) 

Creating a `Status` record triggers continuous delivery scheduling for the affected commit: [6](#0-5) [7](#0-6) [8](#0-7) 

The trust binding that breaks is: **organization that authenticated the webhook signature == repository/stack that gets mutated by the handler**. `repository_owner` (signature side) and the sha-only lookup (write side) are independent fields inside the same attacker-controlled JSON body, so they can be made inconsistent: sign as organization A, but target a commit belonging to organization B's stack (Shipit instances commonly host multiple orgs, as shown by the multi-org secrets template): [9](#0-8) 

### Impact Explanation
If the victim stack has `continuous_deployment` enabled, a forged "success" status on a required CI context can make an otherwise-pending commit `deployable?`, causing `ContinuousDeliveryJob` to trigger a real deploy of that stack — an unauthorized deploy driven entirely by a signature that was only ever valid for an unrelated organization. This matches the "Critical: unauthorized deploy" impact band, since it lets one organization's webhook credential falsify build/CI state and drive deployment decisions for a stack it has no authority over.

### Likelihood Explanation
Likelihood is Low/Unlikely-to-Medium: it requires the attacker to already control at least one GitHub organization (and its App webhook secret) that is legitimately configured in the same shared Shipit instance as the victim organization — a realistic scenario for shared/internal Shipit deployments serving multiple teams/orgs, since only knowledge of one's own org's secret is required, not the victim's. The victim commit `sha` is public information (visible via GitHub), and continuous deployment is a commonly enabled feature.

### Recommendation
`StatusHandler` (and any other handler that doesn't scope through `Handler#repository_name`) must verify that the commit(s) matched by `sha` actually belong to the `repository.full_name`/organization asserted in the same payload, and that this value matches the organization that produced the valid signature (`repository_owner` in `WebhooksController`). Concretely, scope the `Commit.where(sha: ...)` lookup by the stack's repository derived from `payload.dig('repository','full_name')`, consistent with how `PushHandler`/`Handler#stacks` operate, and reject events whose `repository`/`organization` field doesn't match the organization used to verify the signature.

### Proof of Concept
1. Attacker operates GitHub organization `attacker-org`, which is configured in the shared Shipit instance (has its own GitHub App / `webhook_secret`).
2. Attacker obtains a public commit `sha` from `victim-org/victim-repo` (any repo tracked by the same Shipit instance with `continuous_deployment` enabled).
3. Attacker crafts a `status` event payload:
   ```json
   {
     "repository": {"owner": {"login": "attacker-org"}, "full_name": "attacker-org/decoy-repo"},
     "sha": "<victim commit sha>",
     "state": "success",
     "context": "ci/required-check"
   }
   ```
4. Attacker computes `X-Hub-Signature` with `attacker-org`'s own `webhook_secret` and POSTs to `/webhooks` with `X-Github-Event: status`.
5. `WebhooksController#verify_signature` resolves `repository_owner` as `attacker-org`, validates successfully against `attacker-org`'s secret.
6. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, finds the victim's commit (unrelated to `attacker-org`), and creates a fabricated `success` Status on it, ignoring that the signature was only valid for `attacker-org`.
7. `Status#schedule_continuous_delivery` → `Commit#schedule_continuous_delivery` fires; if this makes the victim commit deployable, `ContinuousDeliveryJob` deploys the victim stack — an unauthorized deploy triggered by a credential belonging to a different organization.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```

**File:** app/models/shipit/status.rb (L42-44)
```ruby
    def schedule_continuous_delivery
      commit.schedule_continuous_delivery
    end
```

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
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
