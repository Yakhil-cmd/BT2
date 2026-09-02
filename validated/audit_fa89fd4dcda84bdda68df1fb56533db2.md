### Title
Cross-tenant CI status forgery via unscoped SHA lookup enables unauthorized deploy trigger on victim stack - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` resolves the target commit purely by `sha`, with no check that the commit belongs to the same repository/stack that the webhook signature was verified for. An attacker who controls repository B can push a commit whose sha is identical to (copied from) victim stack A's head commit and then emit a legitimately-signed `status: success` webhook for repository B; that webhook updates the status of stack A's commit and triggers `Shipit::ContinuousDeliveryJob`, causing an unauthorized deploy of stack A.

### Finding Description
The broken binding: `Shipit.github(organization: repository_owner_of_B).verify_webhook_signature(...) == true` should imply "the mutated commit/stack belongs to repository B", but instead the handler applies to **any** commit row across **all** stacks that happens to share the sha.

Path:
1. `WebhooksController#verify_signature` (app/controllers/shipit/webhooks_controller.rb:24-38) only checks that the payload's HMAC matches the webhook secret for `repository_owner` derived from `params['repository']['owner']['login']` — i.e., it authenticates *who sent the payload* (repo B's org), not *which commit/stack the payload is allowed to affect*. [1](#0-0) 

2. `StatusHandler#process` then does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
```
This is a global lookup with no `stack_id`/`repository` filter at all. [2](#0-1) 

3. `Commit#create_status_from_github!` persists a `Status` scoped to `commit.stack_id` (the commit's *own* stack — stack A, not B), and a resulting `success` transition schedules `ContinuousDeliveryJob` for that stack via `Commit#schedule_continuous_delivery`:
```ruby
def schedule_continuous_delivery
  return unless deployable? && stack.continuous_deployment? && stack.deployable?
  ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
end
``` [3](#0-2) [4](#0-3) 

This exact create-status → enqueue-ContinuousDeliveryJob-for-that-commit's-stack behavior is already asserted in the test suite for the legitimate case: [5](#0-4) 

4. `Commit#deployable?` flips to true once the forged `success` status lands and no blocking condition exists:
```ruby
def deployable?
  !locked? && (stack.ignore_ci? || (success? && !blocked?))
end
``` [6](#0-5) 

5. `ContinuousDeliveryJob#perform` checks only `stack.continuous_deployment?`, schedule window, and occupancy — none of which reference the webhook's origin — then calls `stack.trigger_continuous_delivery`, which deploys the next deployable commit on stack A: [7](#0-6) [8](#0-7) 

Root cause: git commit shas are content-addressed and repository-independent. Any public commit's sha can be reproduced by an attacker copying (or engineering, given SHA-1's demonstrated weaknesses) an identical git object into a repository they control. `StatusHandler` conflates "a commit row with this sha exists somewhere in Shipit's DB" with "this webhook is authorized to mutate that commit," because it never cross-checks the payload's `repository.full_name` against `commit.stack.repository`.

Why existing guards fail: `verify_signature` correctly proves the payload was signed for repo B's org, but that is the only authorization check performed; `drop_unhandled_event`, `ExplicitParameters` schema (`params.sha`/`params.state` are just format-validated strings), and model validations on `Repository`/`Stack` do nothing to constrain which stack's commit the status update targets.

### Impact Explanation
An attacker with no relationship to stack A can force a real deploy (or block/unblock deploys, since arbitrary `state` values are attacker-controlled) on stack A merely by copying its head commit's sha into a repository they own and firing one CI status webhook they fully control. This is a payload for one repository (B) mutating another repository's stack/commit/deploy state (A) — matching the Critical category "unauthorized deploy... a payload for one repository mutating another's stack, commit, task or team." It is repeatable against any stack whose head/undeployed commit sha the attacker can reproduce in a repo they control, and scales across all tenants sharing the same Shipit instance (multi-repo, multi-team installations are the common deployment model for this engine).

### Likelihood Explanation
Preconditions: stack A must be `continuous_deployment?` with an undeployed commit; the attacker must be able to register/onboard repository B into the same Shipit instance and know (or copy) the sha of stack A's head/undeployed commit, which is trivial since git shas of public commits are public and reproducible by copying the git object into another repo (no secret required). No Shipit session, API token, or webhook secret for stack A is needed — only the ability to own repository B and its own legitimate webhook secret. The attack costs a single webhook `POST` and requires no interaction with GitHub's private signing infrastructure. This is fully repeatable at will.

### Recommendation
`StatusHandler#process` must scope the commit lookup to the repository that was authenticated, not sha alone, e.g. join through `Stack -> Repository` and filter `Commit.where(sha: params.sha, stack: repository.stacks)` (or equivalent), using the same `repository_owner`/`repository.full_name` that `verify_signature` authenticated. Apply the analogous fix to `PushHandler` and `CheckSuiteHandler` if they perform similar unscoped sha lookups.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_cross_tenant_test.rb
require 'test_helper'

module Shipit
  class StatusHandlerCrossTenantTest < ActiveSupport::TestCase
    test "a status webhook legitimately signed for repo B triggers a deploy on unrelated stack A" do
      stack_a = shipit_stacks(:shipit)              # victim stack, continuous_deployment: true
      stack_a.update!(continuous_deployment: true)
      stack_a.tasks.delete_all
      commit_a = stack_a.commits.last               # undeployed head commit of stack A

      # Attacker copies the exact git object (same sha) into repo B, entirely disjoint from stack A.
      colliding_sha = commit_a.sha

      # Binding under test: the stack whose webhook_secret verified this payload (B) should equal
      # the stack whose trigger_continuous_delivery is called. Assert they differ before the exploit,
      # and are violated after.
      payload = {
        'sha' => colliding_sha,
        'state' => 'success',
        'context' => 'attacker-ci',
        'repository' => { 'full_name' => 'attacker/repo-b', 'owner' => { 'login' => 'attacker-org' } }
      }

      github_app = mock
      github_app.stubs(:verify_webhook_signature).returns(true) # legit signature for repo B only
      Shipit.stubs(:github).with(organization: 'attacker-org').returns(github_app)

      assert_enqueued_with(job: ContinuousDeliveryJob, args: [stack_a]) do
        Shipit::Webhooks::Handlers::StatusHandler.new.call(payload)
      end

      perform_enqueued_jobs(only: ContinuousDeliveryJob)

      commit_a.reload
      assert_predicate commit_a, :deployable?
      assert stack_a.deploys.where(until_commit_id: commit_a.id).exists?,
             "stack A deployed a commit authorized only by repo B's webhook"
    end
  end
end
```

### Citations

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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
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

**File:** test/models/commits_test.rb (L233-243)
```ruby
    test "updating state to success triggers new deploy when stack has continuous deployment" do
      @stack.reload.update(continuous_deployment: true)
      @stack.deploys.destroy_all

      assert_difference "Deploy.count" do
        assert_enqueued_with(job: ContinuousDeliveryJob, args: [@stack]) do
          @stack.commits.last.statuses.create!(stack_id: @stack.id, state: 'success', context: 'ci/travis')
        end
        ContinuousDeliveryJob.new.perform(@stack)
      end
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
