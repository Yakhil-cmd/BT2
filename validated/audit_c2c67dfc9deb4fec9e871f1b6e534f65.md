### Title
Cross-organization webhook forgery via unbounded commit lookup triggers unauthorized deploys - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`WebhooksController#verify_signature` authenticates an inbound GitHub webhook by picking a per-organization `webhook_secret` based on `repository.owner.login`/`organization.login` in the payload, then HMAC-verifying the raw body against that secret. Once verified, the event is dispatched to a handler that never re-checks which organization/repository was actually authenticated. `Shipit::Webhooks::Handlers::StatusHandler` looks up the target `Commit` purely by `sha`, globally across the entire Shipit installation, with no scoping to the organization whose secret produced the valid signature. This breaks the binding "organization that authenticated == repository that is written," letting an attacker who controls (and knows the webhook secret of) one onboarded GitHub organization forge a `status` event that mutates state for a completely different organization's stack, up to triggering an unauthorized continuous-deployment deploy.

### Finding Description
`WebhooksController#verify_signature` resolves which GitHub App config (and therefore which `webhook_secret`) to verify the signature against solely from the payload itself: [1](#0-0) [2](#0-1) 

This only proves "the sender knows organization X's webhook secret." It never establishes that the rest of the payload (in particular, which commit/repository is acted upon) actually belongs to organization X. The dispatch itself is generic and passes the full JSON straight to registered handlers with no additional binding: [3](#0-2) 

Most handlers at least re-derive the target `Repository`/`Stack` from `payload.dig('repository', 'full_name')` via `Shipit::Webhooks::Handlers::Handler#stacks`: [4](#0-3) 

But `StatusHandler`, registered for the `status` event, does not use `repository_name`/`stacks` at all — it resolves the affected records purely by commit SHA across the whole database: [5](#0-4) [6](#0-5) 

Creating a `Status` record has real side effects unconditioned on which organization was authenticated: [7](#0-6) [8](#0-7) 

If the target stack has continuous deployment enabled, this schedules a real deploy: [9](#0-8) 

Shipit explicitly supports multiple independently-configured GitHub organizations/Apps on one instance, each with its own `webhook_secret`, as shown in the setup docs/sample secrets file: [10](#0-9) 

So the equality that should hold is: `organization authenticated by verify_signature (via repository_owner)` == `organization/repository whose commit is mutated by the handler`. In `StatusHandler`, this equality is never enforced — the handler binds only on `sha`, a field with no server-side link back to the verified organization.

### Impact Explanation
An attacker who is a legitimate admin/owner of one GitHub organization onboarded to a shared, multi-tenant Shipit instance (and therefore knows that organization's own `webhook_secret`, which they configured themselves when creating their GitHub App) can forge a `status` webhook whose HMAC is valid for their own organization, but whose `sha` targets a commit belonging to a completely different, victim organization's stack. Because `StatusHandler` performs a global, unscoped `Commit.where(sha: ...)` lookup, this forged event creates a `success` `Status` for the victim's commit. If that victim stack has `continuous_deployment` enabled, this results in an unauthorized `Deploy` being scheduled and run for a repository/organization the attacker has no legitimate access to — matching the Critical "unauthorized deploy" impact category.

### Likelihood Explanation
Exploitability requires the attacker to know a valid `webhook_secret` for at least one organization configured on the shared Shipit instance (which is normal/expected knowledge for that organization's own administrator, not a privilege over the victim organization) and the target commit's SHA (trivially available for public repositories, or leakable via other Shipit-exposed surfaces such as commit/task pages). No `ApiClient` token, GitHub session, or `Shipit.github_teams` membership is required — only the ability to send an HTTP POST to `/webhooks` with a validly-signed payload for the attacker's own org. Given Shipit's documented multi-organization deployment model, this is a realistic misuse of an intra-instance trust boundary.

### Recommendation
Bind the authenticated organization to the record being mutated before any handler runs, not just at the point of choosing a secret to verify against. Concretely:
- In `WebhooksController`, resolve the target `Repository`/`Stack` the same way `Handler#stacks` does (from `repository.full_name`), and confirm that its owning organization matches `repository_owner` (the same value used to select the webhook secret) before dispatching.
- Fix `StatusHandler#process` specifically to scope `Commit.where(sha: params.sha)` by the stack(s)/repository resolved from `payload.dig('repository', 'full_name')`, consistent with the base `Handler` class, instead of searching commits globally.
- More generally, treat "which secret verified the request" as authorization only for the exact organization/repository named in the same payload, and reject/ignore events where the two disagree.

### Proof of Concept
1. Shipit instance configured with two organizations, `org-attacker` and `org-victim`, each with distinct `webhook_secret`s (per `config/secrets.*.yml` model).
2. Attacker, who administers `org-attacker`'s GitHub App and thus knows `org-attacker`'s `webhook_secret`, obtains the SHA of a commit `S` on `org-victim`'s tracked repository (e.g. from the public repo, or Shipit's own UI/API for that stack if visible).
3. Attacker builds a `status` event body:
   ```json
   {
     "sha": "S",
     "state": "success",
     "context": "ci/forced",
     "repository": { "owner": { "login": "org-attacker" } }
   }
   ```
4. Attacker computes `sha1=HMAC-SHA1(org-attacker_webhook_secret, body)` and POSTs to `/webhooks` with `X-Github-Event: status` and `X-Hub-Signature: sha1=...`.
5. `verify_signature` resolves `Shipit.github(organization: "org-attacker")` and validates successfully (attacker's own secret matches).
6. `Shipit::Webhooks.for_event('status')` dispatches to `StatusHandler`, which runs `Commit.where(sha: "S").each { |commit| commit.create_status_from_github!(params) }` — matching `org-victim`'s commit regardless of the authenticated organization.
7. A new `success` `Status` is created for `org-victim`'s commit; if `org-victim`'s stack has `continuous_deployment: true` and the commit is otherwise deployable, `ContinuousDeliveryJob`/`trigger_continuous_delivery` schedules and runs an unauthorized deploy for `org-victim`.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-25)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
      end
```

**File:** app/models/shipit/webhooks.rb (L6-23)
```ruby
      def default_handlers
        {
          'push' => [Handlers::PushHandler],
          'pull_request' => [
            Handlers::PullRequest::OpenedHandler,
            Handlers::PullRequest::ClosedHandler,
            Handlers::PullRequest::ReopenedHandler,
            Handlers::PullRequest::EditedHandler,
            Handlers::PullRequest::AssignedHandler,
            Handlers::PullRequest::LabeledHandler,
            Handlers::PullRequest::UnlabeledHandler,
            Handlers::PullRequest::LabelCapturingHandler
          ],
          'status' => [Handlers::StatusHandler],
          'membership' => [Handlers::MembershipHandler],
          'check_suite' => [Handlers::CheckSuiteHandler]
        }
      end
```

**File:** app/models/shipit/status.rb (L18-21)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

    delegate :broadcast_update, to: :commit
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

**File:** app/models/shipit/stack.rb (L210-229)
```ruby
    def trigger_continuous_delivery
      return if cached_deploy_spec.blank?

      commit = next_commit_to_deploy

      if should_resume_continuous_delivery?(commit)
        continuous_delivery_resumed!
        return
      end

      if should_delay_continuous_delivery?(commit)
        continuous_delivery_delayed!
        return
      end

      begin
        trigger_deploy(commit, Shipit.user, env: cached_deploy_spec.default_deploy_env)
      rescue Task::ConcurrentTaskRunning
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
