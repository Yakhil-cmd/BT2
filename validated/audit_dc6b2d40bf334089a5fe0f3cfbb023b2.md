### Title
Cross-repository commit status forgery bypasses stack/repository binding in webhook processing - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler` applies GitHub `status` webhook events to **any** `Commit` in the entire database that matches the payload `sha`, without ever checking which repository the webhook actually belongs to. This breaks the trust binding that `WebhooksController#verify_signature` is supposed to establish: the signature only proves the payload came from *some* organization/repository known to Shipit, but `StatusHandler` never re-checks that the commit being mutated belongs to that same repository.

### Finding Description
`WebhooksController#verify_signature` selects the HMAC secret to validate against using an attacker-influenced field taken straight from the JSON body: [1](#0-0) [2](#0-1) 

This only proves the request was HMAC-signed for *the organization named in the payload* — it says nothing about which specific repository within that organization's installation the event concerns. Other handlers correctly re-derive and scope by the repository named in the payload, using the `Handler#stacks` helper which resolves `Repository.from_github_repo_name(payload.dig('repository', 'full_name'))`: [3](#0-2) 
For example `PushHandler` and `CheckSuiteHandler` both scope their writes through `stacks`: [4](#0-3) [5](#0-4) 

`StatusHandler`, however, never requires or reads the `repository` field at all, and looks the target commit up **globally**: [6](#0-5) 

Because `Commit.sha` is only unique per-stack (`add_index :commits, %i(sha stack_id), unique: true`) and not globally unique, an identical `sha` value can legitimately exist for commits belonging to completely different stacks/repositories (e.g. via a fork, which preserves commit SHA1s exactly, or any repository sharing history/commits with the target). `StatusHandler#process` will update **every** `Commit` row across the whole installation whose `sha` matches, regardless of the repository the signed webhook was actually sent for.

This is exactly the "organization authenticated vs. repository written" binding break: the equality that should hold is
`repository_owner(payload) == repository(commit written)`,
but the code only enforces `repository_owner(payload) == organization(signature verified)`, and never enforces `repository(payload) == repository(commit written)`.

### Impact Explanation
Applying an attacker-chosen status to a commit triggers real side effects on the target stack, none of which re-validate that the status genuinely came from CI for that repository:
- `Commit#create_status_from_github!` → `Commit#add_status` fires `Hook.emit(:deployable_status, ...)` and calls `stack.schedule_merges` (enqueuing `ProcessMergeRequestsJob`) whenever the new status is `pending` or `success`: [7](#0-6) 
- `Status#schedule_continuous_delivery` (`after_commit` on create) calls `commit.schedule_continuous_delivery`, and if the target stack has `continuous_deployment: true`, this enqueues `ContinuousDeliveryJob`, which will pick the next deployable commit and trigger a deploy: [8](#0-7) [9](#0-8) 

This is confirmed by existing tests showing that simply creating a `success` status directly enqueues a real deploy when continuous deployment is on: [10](#0-9) [11](#0-10) 

So an attacker who can get one legitimately-signed webhook accepted (for any repository within an organization Shipit trusts) can force an unrelated, unmodified target stack in a different repository past its CI gate and trigger an unauthorized deploy — satisfying the "unauthorized deploy" Critical-impact criterion.

### Likelihood Explanation
Exploitation requires:
1. Legitimate push/CI access to *some* repository whose organization is configured in Shipit (this can be an unrelated, low-sensitivity repository — the attacker does not need any access to the victim stack's repository).
2. Ability to produce a commit whose SHA1 matches an existing commit tracked on the victim stack. This is trivially achievable by forking the victim repository (fork keeps identical commit SHAs) into a repo the attacker controls within the same trusted organization, then using the GitHub Statuses API (with only `repo:status` write access on the fork) to post an arbitrary `state`/`sha` — GitHub will sign this webhook exactly like any other event for that org.

Because `verify_signature` only validates that the org-level secret matches, and never re-checks the repository, the crafted webhook passes verification and is routed straight into the globally-scoped `Commit.where(sha:)` lookup. No `ApiClient` token, GitHub App private key, or webhook secret needs to be known/stolen — only ordinary write access to one repo under a trusted org, which is a comparatively low, plausible bar and does not require privileged Shipit access.

### Recommendation
`StatusHandler` (and any other handler that does not already scope through `Handler#stacks`) must require and validate the `repository` field from the payload and constrain the commit lookup to that repository's stacks, e.g.:
```ruby
params do
  requires :sha, String
  requires :state, String
  requires :repository do
    requires :full_name, String
  end
  ...
end

def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }
  end
end
```
This enforces `repository(payload) == repository(commit written)`, restoring the binding that the webhook signature is meant to guarantee.

### Proof of Concept
1. Attacker has write/CI-token access to `org/attacker-fork`, a fork of the victim repository `org/victim-repo` (same organization installed with Shipit's GitHub App, so signature verification will succeed for either repo).
2. Because it's a fork, `org/attacker-fork` shares an identical commit object (and thus SHA1) with a commit `C` that exists in `org/victim-repo`'s Shipit-tracked stack, which currently has a `pending`/`failure` CI status and `continuous_deployment: true`.
3. Attacker calls the GitHub Statuses API on `org/attacker-fork` for that shared sha: `POST /repos/org/attacker-fork/statuses/<sha>` with `state: "success"`.
4. GitHub sends a `status` webhook to Shipit, HMAC-signed with the org's real webhook secret; `verify_signature` succeeds because `repository_owner` resolves to `org` (the trusted, configured organization) — [1](#0-0) .
5. `StatusHandler#process` executes `Commit.where(sha: <sha>)`, which matches commit `C` in the **victim** stack (a different repository than the one that was actually verified against), and calls `commit.create_status_from_github!(params)` — [12](#0-11) .
6. This creates a `success` `Status` on `C`, which (per `Commit#add_status` and `Status#schedule_continuous_delivery`) enqueues `ProcessMergeRequestsJob` and/or `ContinuousDeliveryJob`, causing an unauthorized deploy of the victim stack — [13](#0-12) [14](#0-13) .

**Note on verification limits:** I was not able to fully confirm from the available index whether `webhook_secret` is guaranteed to be identical across all repositories/organizations in every deployment, or whether some deployments configure a distinct secret per organization only (in which case the attack is confined to repositories within the *same* trusted organization as the victim stack, which is still sufficient for the PoC above since the attack only requires org-level, not repo-level, trust). A full confirmation of multi-org secret configuration options would require reviewing `docs/setup.md` and deployment-specific `secrets.yml` files in more detail than the indexed context allowed.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
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

**File:** app/models/shipit/commit.rb (L366-386)
```ruby
    def add_status
      already_deployed = deployed?

      previous_status = status
      yield
      reload # to get the statuses into the right order (since sorted :desc)
      new_status = status

      unless already_deployed
        payload = { commit: self, stack:, status: new_status.state }
        Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
      end

      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
      new_status
    end
```

**File:** app/models/shipit/status.rb (L18-44)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

    delegate :broadcast_update, to: :commit

    class << self
      def replicate_from_github!(stack_id, github_status)
        find_or_create_by!(
          stack_id:,
          state: github_status.state,
          description: github_status.description,
          target_url: github_status.target_url,
          context: github_status.context,
          created_at: github_status.created_at
        )
      end
    end

    private

    def enable_ci_on_stack
      commit.stack.enable_ci!
    end

    def schedule_continuous_delivery
      commit.schedule_continuous_delivery
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

**File:** test/models/commits_test.rb (L763-777)
```ruby
    test "#add_status schedule a MergeMergeRequests job if the commit transition to `pending` or `success`" do
      commit = shipit_commits(:second)
      github_status = OpenStruct.new(
        state: 'success',
        description: 'Cool',
        context: 'metrics/coveralls',
        created_at: 1.day.ago.to_formatted_s(:db)
      )

      assert_equal 'failure', commit.state
      assert_enqueued_with(job: ProcessMergeRequestsJob, args: [@commit.stack]) do
        commit.create_status_from_github!(github_status)
        assert_equal 'success', commit.state
      end
    end
```
