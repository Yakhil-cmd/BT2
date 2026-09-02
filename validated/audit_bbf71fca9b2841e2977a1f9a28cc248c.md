### Title
Cross-tenant status webhook processes merge queue for any stack sharing a commit sha - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves target commits by a global `Commit.where(sha: params.sha)` query instead of scoping to the stacks belonging to the repository named in the verified webhook payload, unlike `PushHandler` which correctly scopes via `stacks.not_archived.where(branch:)`. Because any commit whose `sha` matches — belonging to any stack, in any repository/organization — is updated and passed into `Commit#create_status_from_github!` → `add_status` → `ProcessMergeRequestsJob.perform_later(stack)`, a webhook that is only cryptographically verified for organization A's repository can trigger merge-queue processing (and potential merge) for a completely unrelated stack B.

### Finding Description
The intended binding is: `stack acted upon == Repository.from_github_repo_name(payload['repository']['full_name']).stacks` (the stack(s) owned by the repository whose organization signed the webhook, as enforced by `verify_signature` in `app/controllers/shipit/webhooks_controller.rb:24-38` and exposed via the `Handler#stacks` helper at `app/models/shipit/webhooks/handlers/handler.rb:32-34`).

`StatusHandler#process` violates this binding:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [1](#0-0) 

It never calls `stacks` (the repository-scoped helper) or filters by `commit.stack.repository`; it queries the entire `commits` table by `sha` only. Contrast with `PushHandler`, which correctly restricts to the requesting repository's stacks:
```ruby
def process
  stacks
    .not_archived
    .where(branch:)
    .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
end
``` [2](#0-1) 

`Commit#create_status_from_github!` calls `add_status`, which (per the state-machine-style `expected_webhook_transitions` behavior exercised in tests) fires `deployable_status`/schedules continuous delivery and enqueues `ProcessMergeRequestsJob.perform_later(stack)` on `pending`/`success` transitions: [3](#0-2) [4](#0-3) 

`verify_signature` in the controller only validates that the request is authentically signed by the organization owning `params.dig('repository','owner','login')` — it says nothing about which commits or stacks the handler is permitted to touch: [5](#0-4) 

Exploit flow: an attacker who owns/controls repository A (any org, any unprivileged GitHub account) can emit a validly-signed `status` webhook for repo A referencing a `sha` that happens to also exist as a commit in stack B (e.g., a shared upstream commit, a cherry-pick, or a commit merged into both a public repo and a forked/downstream Shipit-tracked repo — no cryptographic hash collision required, just sha reuse across repos tracked by different stacks). `StatusHandler` finds `Commit` rows across *all* stacks with that sha, including stack B's commit, and calls `create_status_from_github!` on it, causing stack B's `add_status` transition to fire and `ProcessMergeRequestsJob.perform_later(stack_b)` to enqueue — all while the webhook was signed only for org A.

### Impact Explanation
Enqueuing `ProcessMergeRequestsJob` for stack B causes `merge_request.refresh!`, `all_status_checks_passed?` and `merge_request.merge!` to run against stack B's merge queue [6](#0-5) . If stack B's PR was stalled purely awaiting a status update, this forged/misdirected trigger can force an out-of-band merge evaluation and merge of code the attacker never authenticated against tenant B's organization. This is a "payload for one repository mutating another's stack/commit" scenario and unauthorized merge-queue processing — matching the Critical category "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy, rollback or merge." It is repeatable against any tenant stack sharing a sha with an attacker-controlled repo's commit history.

### Likelihood Explanation
Preconditions: attacker needs a GitHub repo they control (any unprivileged account) and the ability to post a `status` webhook payload naming a `sha` that also exists as a `Commit` row for a target Shipit stack B — realistic when shas are shared across forks/upstream mirrors/cherry-picks tracked by multiple Shipit stacks. No Shipit secrets, sessions, or GitHub App keys are required beyond the attacker's own repo's normal webhook signing (which they control). This is a low-cost, repeatable attack requiring only a shared commit sha, not an actual SHA-1 collision.

### Recommendation
Scope `StatusHandler#process` to only the commits belonging to the stacks of the repository named in the verified payload, mirroring `PushHandler`:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
This ensures the stack passed into downstream jobs equals the stack(s) actually owned by the authenticated repository.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`, no live GitHub):
```ruby
test "status webhook for repo A cannot enqueue ProcessMergeRequestsJob for stack B" do
  stack_a = shipit_stacks(:shipit)                 # repo owned by org A
  stack_b = shipit_stacks(:cyclimse)                # unrelated tenant, different repo/org
  shared_sha = "deadbeef" * 5
  commit_b = stack_b.commits.create!(sha: shared_sha, ...)

  payload = {
    'sha' => shared_sha,
    'state' => 'success',
    'context' => 'ci/travis',
    'repository' => { 'full_name' => stack_a.repository.full_name, 'owner' => { 'login' => stack_a.repository.owner } }
  }

  assert_no_enqueued_jobs only: ProcessMergeRequestsJob do
    Shipit::Webhooks::Handlers::StatusHandler.call(payload)
  end
  # Fails today: ProcessMergeRequestsJob IS enqueued with args: [stack_b],
  # even though the webhook was only signed/verified for stack_a's organization.
end
```
Assert on both sides of the binding: `enqueued_job.stack == payload-derived stack (stack_a)` should hold, but current code produces `enqueued_job.stack == stack_b` (the stack owning the matching-sha commit), proving the divergence.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
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
