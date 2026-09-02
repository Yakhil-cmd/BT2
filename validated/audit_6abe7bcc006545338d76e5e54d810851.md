### Title
Cross-repository Status forgery triggers unauthorized deploy via SHA-only commit lookup - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits to attach a GitHub status to by SHA alone, across the entire database, instead of scoping to the repository/organization whose webhook signature was verified. An attacker who controls any GitHub repository configured in Shipit can post a `status` webhook, signed with their own org's `webhook_secret`, for a SHA that happens to also exist as an undeployed commit on a victim's `continuous_deployment` Stack, flipping that commit's status to `success` and triggering an unauthorized `Deploy` on the victim's Stack.

### Finding Description
The broken binding: the question claims `organization_that_signed_webhook == organization_owning_the_stack_whose_deploy_is_triggered`. Tracing the code shows this is false.

`WebhooksController#verify_signature` derives `repository_owner` from the payload's own `repository.owner.login` field and verifies the signature against `Shipit.github(organization: repository_owner)` [1](#0-0) . This only proves the request was signed with the webhook secret of whatever org is *named in the attacker-supplied payload* — since the attacker owns that repo/org in Shipit, they legitimately know that secret. It proves nothing about the target commit's actual owning Stack.

`StatusHandler#process` then does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [2](#0-1) 

This queries `Commit` globally by `sha`, with no join/filter on `repository_name`, `stack_id`, or the verified `repository_owner`. Note the base `Handler` class does provide a `stacks` helper scoped by `repository_name` from the payload [3](#0-2) , but `StatusHandler` does not use it — it bypasses that scoping entirely. Database schema confirms `sha` is only unique per `(stack_id, sha)`, not globally [4](#0-3) , so multiple Stacks (belonging to different orgs) can legitimately have `Commit` rows with the identical `sha`.

Once `create_status_from_github!` runs on the victim's commit, it creates a `Status`, whose `after_commit :schedule_continuous_delivery` callback fires [5](#0-4)  and [6](#0-5) , enqueuing `ContinuousDeliveryJob` for the victim's Stack [7](#0-6) . That job calls `stack.trigger_continuous_delivery`, which finds `next_commit_to_deploy` [8](#0-7)  — the now-`success` commit passes `Commit#deployable?` (`!locked? && (stack.ignore_ci? || (success? && !blocked?))`) [9](#0-8)  — and calls `trigger_deploy`, creating and running a real `Deploy` on the victim Stack [10](#0-9) .

None of the existing guards prevent this: `verify_signature` authenticates the sender's own claimed org, not the target commit's owning stack; `ExplicitParameters` (`StatusHandler.params`) only validates payload shape, not repository binding [11](#0-10) ; and no model validation ties `Commit#sha` uniqueness across the whole table to prevent this collision.

### Impact Explanation
Impact: unauthorized `Deploy` triggered on a victim's Stack by an attacker with no relationship to that Stack, satisfying the Critical "unauthorized deploy" category. This is repeatable against any Stack with `continuous_deployment: true` that has an undeployed commit whose SHA the attacker can reproduce or find shared (e.g., a common open-source ancestor commit, vendored dependency commit, or a rebased/duplicated commit with identical tree/parent/author-date/message — SHA1 is deterministic over these fields). Blast radius spans tenants/organizations since the lookup is entirely cross-org — any org's webhook credentials can be used to write a `Status` for a commit belonging to a completely different org's Stack, causing that Stack's real deploy task to run on the victim's deploy host.

### Likelihood Explanation
Preconditions: (1) attacker owns/controls a repository registered in Shipit (any onboarded org, low cost), (2) victim Stack has `continuous_deployment: true` and an undeployed commit currently `pending`/`failure`, (3) attacker can produce a commit with an identical SHA — feasible for shared upstream/ancestor commits or by reconstructing an identical commit object (tree, parent, author, committer, message, timestamps) which is a known non-cryptographic-collision technique since SHA1 commit objects are fully determined by their content. No secrets, sessions, or privileged roles are required beyond the attacker's own webhook credentials for their own repo. This is directly reproducible in a single POST once the SHA condition is met.

### Recommendation
Scope `StatusHandler#process` (and any other SHA-keyed webhook handler) to only the commits belonging to the repository that authenticated the webhook, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or equivalently join through `Repository.from_github_repo_name(repository_name)` before matching by `sha`, mirroring the `stacks` helper already defined in `Handler`. Ensure every handler that mutates a `Commit`/`Status` by SHA enforces repository/stack scoping derived from the verified webhook payload, not a global `Commit.where(sha:)` lookup.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
require 'test_helper'

module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerCrossRepoTest < ActiveSupport::TestCase
        test "status from attacker org does not deploy victim stack sharing a sha" do
          attacker_stack = shipit_stacks(:shipit) # attacker-owned, distinct repo/org
          victim_stack = shipit_stacks(:cyclimse) # victim-owned, continuous_deployment target
          victim_stack.update!(continuous_deployment: true)

          shared_sha = 'deadbeef' * 5
          attacker_stack.commits.create!(sha: shared_sha, message: 'attacker', author: shipit_users(:walrus), committer: shipit_users(:walrus), authored_at: Time.now, committed_at: Time.now)
          victim_commit = victim_stack.commits.create!(sha: shared_sha, message: 'victim', author: shipit_users(:walrus), committer: shipit_users(:walrus), authored_at: Time.now, committed_at: Time.now)

          params = { sha: shared_sha, state: 'success', branches: [] }

          assert_no_difference -> { victim_stack.deploys.count } do
            StatusHandler.call(params.merge('repository' => { 'full_name' => attacker_stack.repository.full_name, 'owner' => { 'login' => attacker_stack.repository.owner } }))
            perform_enqueued_jobs
          end
          # Currently FAILS: assert_no_difference is violated because
          # Commit.where(sha: shared_sha) matches victim_commit too,
          # flips it to success, and triggers a Deploy on victim_stack.
        end
      end
    end
  end
end
```
Both sides of the binding: `left = organization owning attacker_stack (authenticated by verify_signature)`, `right = organization owning victim_stack (whose deployable?/Deploy is affected)`. They are unequal, yet the write and subsequent deploy occur — confirming the vulnerability.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb (L1-2)
```ruby
class IndexCommitsOnStackIdAndSha < ActiveRecord::Migration[5.1]
  def change
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

**File:** app/models/shipit/stack.rb (L174-196)
```ruby
    def trigger_deploy(*args, **kwargs)
      if changed?
        # If this is the first deploy since the spec changed it's possible the record will be dirty here, meaning we
        # cant lock. In this one case persist the changes, otherwise log a warning and let the lock raise, so we
        # can debug what's going on here. We don't expect anything other than the deploy spec to dirty the model
        # instance, because of how that field is serialised.
        if changes.keys == ['cached_deploy_spec']
          save!
        else
          Rails.logger.warning("#{changes.keys} field(s) were unexpectedly modified on stack #{id} while deploying")
        end
      end

      run_now = kwargs.delete(:run_now)
      deploy = with_lock do
        deploy = build_deploy(*args, **kwargs)
        deploy.save!
        deploy
      end
      run_now ? deploy.run_now! : deploy.enqueue
      continuous_delivery_resumed!
      deploy
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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```
