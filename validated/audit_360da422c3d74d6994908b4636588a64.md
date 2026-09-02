### Title
`StatusHandler#process` matches commits globally by `sha` without scoping to the webhook's `repository`, allowing one signed status webhook to trigger `ContinuousDeliveryJob` across unrelated stacks - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`, which is not filtered by the repository that sent the webhook. Any commit row in any stack across the entire Shipit instance sharing that `sha` receives a new `Status`, and via `Status`'s `after_commit :schedule_continuous_delivery` → `Commit#schedule_continuous_delivery` → `ContinuousDeliveryJob`, each matching stack can be pushed toward an actual deploy if it independently has `continuous_deployment?` enabled and is otherwise deployable.

### Finding Description
The broken binding: the number of stacks affected by one incoming `status` webhook should equal 1 (only the stack(s) belonging to the repository named in `payload['repository']['full_name']`), but the actual code produces `N` = however many stacks/tenants happen to have a `commits` row with the same `sha`.

Code path:
1. `Shipit::WebhooksController#create` parses the payload and, after `verify_signature` (scoped to `repository_owner` only, used purely to check the org's HMAC), dispatches to `Shipit::Webhooks.for_event('status')` → `StatusHandler`. [1](#0-0) [2](#0-1) 
2. `Shipit::Webhooks::Handlers::Handler` base class exposes a `stacks` helper that *does* scope to `repository_name` via `Repository.from_github_repo_name(repository_name)&.stacks`, but `StatusHandler` never calls it. [3](#0-2) 
3. Instead, `StatusHandler#process` does an unscoped, instance-wide lookup: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`. [4](#0-3) 
4. `Commit#create_status_from_github!` calls `add_status { statuses.replicate_from_github!(stack_id, github_status) }`, creating a `Status` row for whichever stack that commit row happens to belong to. [5](#0-4) 
5. `Status` has `after_commit :schedule_continuous_delivery, :broadcast_update, on: :create`, which calls `commit.schedule_continuous_delivery`. [6](#0-5) [7](#0-6) 
6. `Commit#schedule_continuous_delivery` checks only per-commit/per-stack state (`deployable?`, `stack.continuous_deployment?`, `stack.deployable?`) — none of which involve the webhook's originating repository — and enqueues `ContinuousDeliveryJob.set(wait: ...).perform_later(stack)`. [8](#0-7) 
7. `ContinuousDeliveryJob#perform` re-checks `stack.continuous_deployment?`, schedule windows, and occupancy, then calls `stack.trigger_continuous_delivery`, which can create and run a real `Deploy`. [9](#0-8) [10](#0-9) 

Existing guards do not prevent this: `verify_signature` only confirms the payload is legitimately signed for the org named in the payload — it says nothing about which `commits` rows the handler is permitted to touch. [11](#0-10)  The `StatusHandler` params schema (`ExplicitParameters`) only validates the shape of `sha`/`state`/etc., not repository ownership. [12](#0-11)  No model validation ties a `Status`'s webhook origin to the commit's `stack_id`; `Commit.where(sha:)` is a raw, unscoped ActiveRecord query across the whole `commits` table. [13](#0-12) 

Exploit flow: attacker owns/controls a repository that is registered as a Shipit stack (a normal, unprivileged capability — e.g., contributing to any tracked repo). They push a commit whose `sha` is identical to a commit that also exists, byte-for-byte, in other tracked stacks (plausible for vendored dependency-bump commits copied verbatim into multiple downstream repos, as stated in the preconditions). GitHub then sends a genuinely, validly signed `status` webhook for the attacker's own repository/org referencing that `sha`. Because `verify_signature` only checks the org named in the payload (the attacker's own org, which is legitimate), the request passes. `StatusHandler` then updates statuses — and can enqueue `ContinuousDeliveryJob` — for every stack in the whole instance that has a `commits` row with that same `sha`, regardless of which repository or org they belong to.

### Impact Explanation
A single, correctly-signed webhook for one repository can cause `Status` records to be written for, and `ContinuousDeliveryJob`/real deploys to be triggered on, an arbitrary number of unrelated stacks belonging to different tenants/orgs that the attacker never authenticated against. This is a cross-tenant write (a `Status` row and potentially a `Deploy` created for a repository that did not authenticate the request) and an unauthorized deploy trigger, matching the "payload for one repository mutating another's stack/commit" and "unauthorized deploy" Critical impact categories. Blast radius scales with `N`, the number of distinct stacks sharing that commit sha, and is repeatable on demand by the attacker pushing/re-triggering CI on their own repo.

### Likelihood Explanation
Requires: (a) the attacker controls a repository tracked by the same Shipit instance (a normal, low-privilege prerequisite, not an operator/maintainer role); (b) at least one other victim stack has a `commits` row with an identical `sha` — plausible for shared vendor/dependency-bump commits cherry-picked or synced verbatim across repos, as stated in the question's preconditions; (c) the victim stack has `continuous_deployment?` enabled and is otherwise deployable (no active task, in schedule window, etc.). No secrets, forged signatures, or elevated roles are needed — the webhook signature is genuinely valid for the attacker's own org. Feasibility is high in any Shipit deployment tracking forks/vendored copies of shared code with CD enabled on victim stacks.

### Recommendation
Scope the `Commit` lookup in `StatusHandler#process` to the repository that emitted the webhook, mirroring the `stacks` helper already defined in the base `Handler` class, e.g. `stacks.flat_map(&:commits)... .where(sha: params.sha)` or `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`, so that only commits belonging to stacks of `Repository.from_github_repo_name(repository_name)` can receive the status/trigger continuous delivery.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
require 'test_helper'

module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerCrossTenantTest < ActiveSupport::TestCase
        test "a status webhook for one repository must not trigger continuous delivery on unrelated stacks sharing a sha" do
          shared_sha = 'deadbeef' * 5

          attacker_stack = shipit_stacks(:shipit) # attacker's own tracked repo/org
          victim_stacks = 3.times.map do |i|
            stack = Shipit::Stack.create!(repository: Shipit::Repository.create!(owner: "victim-org-#{i}", name: 'repo'),
                                           environment: 'production', branch: 'master', continuous_deployment: true)
            Shipit::Commit.create!(stack: stack, sha: shared_sha, message: 'vendor bump',
                                    author: AnonymousUser.new, committer: AnonymousUser.new,
                                    authored_at: Time.now, committed_at: Time.now)
            stack
          end

          attacker_commit = Shipit::Commit.create!(stack: attacker_stack, sha: shared_sha, message: 'vendor bump',
                                                     author: AnonymousUser.new, committer: AnonymousUser.new,
                                                     authored_at: Time.now, committed_at: Time.now)

          payload = {
            'sha' => shared_sha, 'state' => 'success', 'context' => 'ci/travis',
            'created_at' => Time.now.to_s,
            'repository' => { 'full_name' => attacker_stack.github_repo_name, 'owner' => { 'login' => attacker_stack.repository.owner } }
          }

          # BINDING: stacks_triggered_count == 1 (attacker_stack only) expected;
          # actual code triggers ContinuousDeliveryJob for attacker_stack + N victim_stacks.
          assert_enqueued_jobs 1, only: Shipit::ContinuousDeliveryJob do
            Shipit::Webhooks::Handlers::StatusHandler.call(payload)
          end
          # This assertion FAILS today: 1 + victim_stacks.size jobs are enqueued instead of 1.
        end
      end
    end
  end
end
```

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L7-18)
```ruby
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
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
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

**File:** app/models/shipit/status.rb (L18-21)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

    delegate :broadcast_update, to: :commit
```

**File:** app/models/shipit/status.rb (L42-44)
```ruby
    def schedule_continuous_delivery
      commit.schedule_continuous_delivery
    end
```

**File:** app/jobs/shipit/continuous_delivery_job.rb (L10-21)
```ruby
    def perform(stack)
      return unless stack.continuous_deployment?

      # If there is a schedule defined for this stack, make sure we are within a
      # deployment window before proceeding.
      return if stack.continuous_delivery_schedule && !stack.continuous_delivery_schedule.can_deploy?

      # checks if there are any tasks running, including concurrent tasks
      return if stack.occupied?

      stack.trigger_continuous_delivery
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
