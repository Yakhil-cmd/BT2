### Title
Cross-repository status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` applies an inbound GitHub `status` webhook to **every** `Commit` row that matches the given `sha`, with no check that the commit's owning `Stack`/repository matches the repository that authenticated the webhook. Because `WebhooksController#verify_signature` only verifies that the request was validly signed for *some* org (`repository_owner` taken from the attacker-supplied payload), and never re-validates that this org/repo owns the target `Commit`, an attacker who controls any repository whose webhooks reach this Shipit instance can push a status onto a same-SHA commit belonging to a completely different `victim` stack, and thereby unblock a queued `MergeRequest`.

### Finding Description
The broken binding, stated as an equality that must hold but doesn't:

`repository_owner_that_authenticated_the_webhook (params.dig('repository','owner','login'), verified against Shipit.github(organization: repository_owner))` == `commit.stack.repository.full_name (the repo/org owning the Commit rows mutated by the handler)`

Trace:
1. `WebhooksController#verify_signature` computes `repository_owner` purely from the untrusted JSON payload and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)` [1](#0-0) . This only proves the request was signed with the secret configured for *that org's* GitHub App — it says nothing about which `Stack`/`Commit` the payload's `sha` should apply to.
2. `StatusHandler#process` then does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [2](#0-1) 
This query is **global** — `sha` is not unique per stack/repo in the `commits` table, and no filter on `params.dig('repository','full_name')` or stack ownership is applied.
3. `Commit#create_status_from_github!` creates a `Status` unconditionally via `statuses.replicate_from_github!(stack_id, github_status)` [3](#0-2) .
4. `Status` has `after_commit :schedule_continuous_delivery` which calls `commit.schedule_continuous_delivery`, enqueuing `ContinuousDeliveryJob` for `commit.stack` if deployable [4](#0-3) [5](#0-4) . `#add_status` (invoked transitively) additionally enqueues `ProcessMergeRequestsJob` for `commit.stack` on relevant transitions, as shown by the existing test `"#add_status schedule a MergeMergeRequests job if the commit transition to pending or success"` [6](#0-5) .
5. `ProcessMergeRequestsJob#perform(stack)` calls `merge_request.refresh!`, `reject_unless_mergeable!`, and `all_status_checks_passed?` on `victim`'s pending merge requests [7](#0-6) . `all_status_checks_passed?` reads `head.statuses_and_check_runs` [8](#0-7)  — the exact `Status` row the attacker just injected via the unscoped lookup — so a merge request previously stuck in `rejection_reason: 'ci_missing'` can now pass CI checks and progress toward `merge!`.

Attacker's exact request: any correctly-signed GitHub `status` webhook (`X-Github-Event: status`) whose JSON body contains `sha` equal to the SHA of the commit that is `victim`'s pending `MergeRequest#head`, and `state: 'success'`. The attacker obtains a validly signed webhook not by knowing any Shipit secret, but simply by having GitHub itself deliver it — e.g. by pushing/re-creating (via `git commit-tree`/cherry-pick preserving identical content) the exact same commit object (same SHA, since a git commit hash is a pure function of its content: tree, parents, author/committer identity and timestamps, and message) into a repository they control that is covered by the same GitHub App installation, and having their own CI system post a `success` status for that SHA on their own repo. GitHub computes and sends the signature honestly using the real webhook secret for that installation; Shipit's `verify_signature` therefore passes.

Why existing guards fail:
- `verify_signature` authenticates the *sender org*, not the *target commit's owning repository/stack* — there is no cross-check.
- `drop_unhandled_event`/`check_if_ping` are irrelevant to this path.
- `ExplicitParameters` schema on `StatusHandler` only validates types (`sha`, `state`, etc.), not repository ownership [9](#0-8) .
- No model validation on `Status`/`Commit` restricts status creation by originating repository; `Status.replicate_from_github!` only takes `stack_id` from the loop variable's `commit.stack_id`, which is derived purely from the pre-existing DB row, not from the webhook payload's repository.

### Impact Explanation
An attacker who controls (or can trigger CI on) any repository whose webhooks are delivered to this Shipit instance can inject a forged CI `success` status onto an arbitrary commit in a **different** repository's stack, provided that commit's SHA is known/reproducible (trivially true for any public open-source PR head commit, since PR contents and hence the exact commit object are public). This directly matches the listed Critical category: "a payload for one repository mutating another's stack, commit, task or team," and can further cause "an unauthorized deploy, rollback or merge" since it can unblock `ProcessMergeRequestsJob#perform` to call `merge_request.merge!`, causing Shipit to merge a pull request in `victim`'s repository that the attacker never authored or was granted access to. The action is repeatable against any stack/commit combination sharing this Shipit deployment, and is not limited to a single tenant if the GitHub App installation, or webhook secret, spans multiple orgs/repos (multi-org config in `lib/shipit/github_app.rb` shows per-org secrets, but the flaw is not org-verification per se — it's the total absence of stack/repo scoping in `Commit.where(sha:)`).

### Likelihood Explanation
Preconditions required: `victim` stack has `merge_queue_enabled: true` and a pending `MergeRequest` currently rejected for `ci_missing` (or simply pending and awaiting CI); attacker needs any repository under the same Shipit-configured GitHub App/org whose webhooks reach this instance, and the ability to reproduce the exact same commit object (trivial for public PRs — fetch and re-push the identical commit) plus trigger a status webhook on it (e.g., via their own CI integration on their own repo, or a personal access token they use to call GitHub's Status API on a repo they control). No Shipit session, API token, or secret is required — GitHub itself signs and delivers the payload. This is a straightforward, repeatable attack requiring no privilege escalation, git SHA collision, or secret compromise.

### Recommendation
Scope the `Commit` lookup in `StatusHandler#process` (and analogously in `CheckSuiteHandler`/other sha-keyed handlers) to the repository named in the payload, e.g.:
```ruby
def process
  repo_full_name = params.dig('repository', 'full_name') # or via a required param
  Commit.joins(:stack).merge(Stack.where(repository: Repository.from_github_repo_name(repo_full_name)))
        .where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
More generally, add a shared guard in `Webhooks::Handler` that validates `params.dig('repository','full_name')` equals `commit.stack.repository.full_name` (or, for handlers keyed by SHA only, that the commit's stack's repository owner matches `repository_owner` used in `verify_signature`) before applying any mutation.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (new test)
test ":status webhook does not update commits belonging to a different repository's stack" do
  request.headers['X-Github-Event'] = 'status'
  GithubHook.any_instance.stubs(:verify_signature).returns(true)

  victim_stack = shipit_stacks(:shipit) # repository shopify/shipit-engine
  victim_commit = shipit_commits(:first) # belongs to victim_stack
  # simulate an attacker-owned repo reproducing the identical commit object (same sha)
  attacker_repo_payload = JSON.parse(payload(:status_master)).merge(
    'sha' => victim_commit.sha,
    'state' => 'success'
  )
  attacker_repo_payload['repository'] = {
    'full_name' => 'attacker/evil-fork',
    'owner' => { 'login' => 'attacker-org' }
  }

  assert_no_difference -> { victim_commit.statuses.count } do
    post :create, body: attacker_repo_payload.to_json, as: :json
  end
end

# test/jobs/process_merge_requests_job_test.rb (proof of downstream effect)
test "forged status from unrelated repo must not enqueue ProcessMergeRequestsJob for victim stack" do
  victim_stack = shipit_stacks(:shipit)
  merge_request = shipit_merge_requests(:shipit_pending_unmergeable) # rejection_reason: ci_missing
  head_commit = merge_request.head

  assert_no_enqueued_jobs only: ProcessMergeRequestsJob do
    # forged, cross-repo status write reusing head_commit.sha
    head_commit.create_status_from_github!(
      OpenStruct.new(state: 'success', description: 'forged', context: 'ci/forged', created_at: Time.now)
    )
  end
end
```
Both assertions should fail against current code (the status is created and `ProcessMergeRequestsJob` is enqueued with `args: [victim_stack]`), demonstrating the missing repository/stack binding.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L6-18)
```ruby
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

**File:** app/jobs/shipit/process_merge_requests_job.rb (L10-32)
```ruby
    def perform(stack)
      merge_requests = stack.merge_requests.to_be_merged.to_a
      merge_requests.each do |merge_request|
        merge_request.refresh!
        merge_request.reject_unless_mergeable!
        merge_request.cancel! if merge_request.closed?
        merge_request.revalidate! if merge_request.need_revalidation?
      end

      return false unless stack.allows_merges?

      merge_requests.select(&:pending?).each do |merge_request|
        merge_request.refresh!
        next unless merge_request.all_status_checks_passed?

        begin
          merge_request.merge!
        rescue MergeRequest::NotReady
          ProcessMergeRequestsJob.set(wait: 10.seconds).perform_later(stack)
          return false
        end
      end
    end
```

**File:** app/models/shipit/merge_request.rb (L193-197)
```ruby
    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end
```
