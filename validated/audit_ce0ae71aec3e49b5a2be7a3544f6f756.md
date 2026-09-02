### Title
Cross-organization CI status forgery via signature-organization/commit-scope mismatch in `StatusHandler` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to verify a webhook against using an *unauthenticated* field taken straight from the JSON body (`repository.owner.login` or `organization.login`), while `Shipit::Webhooks::Handlers::StatusHandler` never checks that field at all when applying the event: it looks up commits globally by SHA across every stack in the Shipit instance. This breaks the binding "the organization whose secret verified the request == the organization/stack the event is applied to," letting a webhook correctly signed for one organization mutate CI state on a completely unrelated stack.

### Finding Description
`WebhooksController#verify_signature` picks the verification key based on `repository_owner`, itself derived from the untrusted body before the signature is checked: [1](#0-0) [2](#0-1) 

Once verified, `WebhooksController#create` simply dispatches the parsed JSON to all registered handlers for the event type, with no further org/repo binding: [3](#0-2) 

For the `status` event, `StatusHandler` only requires `sha`/`state`/etc. — it does **not** require or check any `repository` field — and then applies the update globally: [4](#0-3) 

`Commit.where(sha: params.sha)` is unscoped by stack/repository, so any commit sharing that SHA in *any* stack tracked by the Shipit instance is updated: [5](#0-4) 

Creating a `Status` record automatically enables CI and schedules continuous delivery evaluation for the commit's actual stack: [6](#0-5) [7](#0-6) [8](#0-7) 

And `ContinuousDeliveryJob`/`Stack#trigger_continuous_delivery` will build and run an actual deploy if the targeted stack has continuous deployment enabled and the commit becomes "deployable" (state success + no blocking CI): [9](#0-8) [10](#0-9) 

**Binding broken (as an equality):**
`verified_organization(payload.repository.owner.login used to select the HMAC secret) == owning_organization(stack that Commit.where(sha:) mutates)`

Before the fix this equality is never enforced — the webhook controller authenticates *an* organization, but `StatusHandler` writes to *whatever stack happens to contain a commit with that SHA*, independent of which organization's key produced the valid signature.

### Impact Explanation
An attacker who legitimately controls (or administers) any single organization/repository configured on a shared, multi-tenant Shipit instance (i.e., possesses a valid `webhook_secret`/App credentials for *their own* org, which is not privileged with respect to the victim's stack) can forge a `status` webhook event whose `sha` matches a public commit on a victim's stack tracked by the same Shipit instance. Because the signature is validated against the attacker's own organization key (selected via `repository.owner.login`, which the attacker controls) and the handler never re-validates that the commit actually belongs to that organization, the attacker can inject a fabricated "success" status onto the victim's commit. This can flip the commit's derived CI state to deployable and, if the victim stack has continuous deployment enabled, trigger `ContinuousDeliveryJob`/`Stack#trigger_deploy`, resulting in an unauthorized deploy of the victim's stack — matching the Critical "unauthorized deploy" impact criterion.

### Likelihood Explanation
Requires: (1) a Shipit deployment configured for more than one GitHub organization (multi-tenant), (2) attacker controls credentials for at least one of those organizations (their own, non-victim org), and (3) knowledge of a target commit SHA on the victim stack (trivially obtainable from public GitHub history or from the Shipit UI itself, which is often browsable). No access to the victim's secrets, GitHub App keys, or Shipit accounts is required. This is a realistic scenario for any Shipit installation serving multiple organizations/teams.

### Recommendation
Bind the verified organization to the record being mutated:
- Require and validate a `repository` field in every webhook handler's params (as already done in `PushHandler`/`PullRequest` handlers), and scope lookups by `Repository.from_github_repo_name` / `stack_id` rather than global SHA lookup.
- In `StatusHandler#process`, restrict `Commit.where(sha:)` to commits belonging to stacks whose repository matches `payload.dig('repository','full_name')`, and reject/ignore the event if it doesn't match the same organization that produced the verified signature.
- Optionally, have `WebhooksController` pass the already-verified `repository_owner` down to handlers and have every handler assert equality between it and the repository actually mutated, rather than trusting the JSON body's per-field organization/repo claims implicitly.

### Proof of Concept
1. Configure Shipit with two organizations, `attacker-org` and `victim-org`, each with its own GitHub App / `webhook_secret` (multi-tenant setup as documented in `docs/setup.md`).
2. Attacker (an admin of `attacker-org`, with no access to `victim-org`) observes a public commit SHA `abcd1234` that exists in a stack owned by `victim-org` (e.g., from GitHub's public commit history or the Shipit dashboard).
3. Attacker crafts a `status` webhook payload:
   ```json
   { "sha": "abcd1234", "state": "success", "context": "ci/forged",
     "repository": { "owner": { "login": "attacker-org" } } }
   ```
4. Attacker signs the payload with `attacker-org`'s own legitimate `webhook_secret` and POSTs it to `/webhooks` with header `X-Github-Event: status`.
5. `WebhooksController#verify_signature` resolves `repository_owner` as `attacker-org`, fetches `attacker-org`'s GitHub App, and verifies the signature successfully (their own secret, their own signature).
6. `StatusHandler#process` executes `Commit.where(sha: "abcd1234")`, which matches the commit in `victim-org`'s stack (unscoped by organization), creates a `success` `Status` on it, and schedules `ContinuousDeliveryJob` for `victim-org`'s stack.
7. If `victim-org`'s stack has `continuous_deployment: true` and the commit becomes the new deployable head, an unauthorized deploy is triggered on `victim-org`'s infrastructure — entirely outside `victim-org`'s control or knowledge.

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

**File:** app/jobs/shipit/continuous_delivery_job.rb (L1-22)
```ruby
# frozen_string_literal: true

module Shipit
  class ContinuousDeliveryJob < BackgroundJob
    include BackgroundJob::Unique

    queue_as :deploys
    on_duplicate :drop

    def perform(stack)
      return unless stack.continuous_deployment?

      # If there is a schedule defined for this stack, make sure we are within a
      # deployment window before proceeding.
      return if stack.continuous_delivery_schedule && !stack.continuous_delivery_schedule.can_deploy?

      # checks if there are any tasks running, including concurrent tasks
      return if stack.occupied?

      stack.trigger_continuous_delivery
    end
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
