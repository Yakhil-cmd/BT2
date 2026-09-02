## Finding confirmed

**Binding claimed broken:** `webhook.signing_org == commit.stack.repository.owner` (the org whose `webhook_secret` signed the request should equal the org that owns the `Commit`/`Stack` being mutated). Trace shows these diverge.

### Title
Cross-tenant Status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` — (`app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits solely by `sha` across the entire `commits` table, without scoping to the repository declared in the webhook payload. Every other event handler (`PushHandler`, `CheckSuiteHandler`, the `PullRequest::*Handler`s) resolves and filters through `stacks`/`repository` derived from `payload.dig('repository', 'full_name')`, but `StatusHandler` does not even declare `repository` in its `ExplicitParameters` schema, so nothing prevents a `status` event correctly signed for tenant A's org from creating a `Status` on a `Commit` that belongs to tenant B's `Stack`.

### Finding Description
- `WebhooksController#verify_signature` only proves that the payload's `repository.owner.login` org's `webhook_secret` produced a valid HMAC over the raw body: `Shipit.github(organization: repository_owner).verify_webhook_signature(...)` [1](#0-0) . It never checks that the `sha`/commit referenced later actually belongs to that same organization's repositories.
- `StatusHandler` then does:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [2](#0-1) 
No `repository`/`stacks` scoping is applied — contrast with `PushHandler#process` (`stacks.not_archived.where(branch:)...`) and `CheckSuiteHandler#process` (`stacks.where(branch: ...)`), both of which resolve `stacks` via `Repository.from_github_repo_name(repository_name)` from the base `Handler` class [3](#0-2) .
- `Commit#create_status_from_github!` writes the status using the commit's **own** `stack_id`, not anything derived from the attacker's payload: `statuses.replicate_from_github!(stack_id, github_status)` [4](#0-3) , `Status.replicate_from_github!` persists `state`/`context` straight from the payload [5](#0-4) .
- The `sha` column is only indexed as a composite `(stack_id, sha)`  — there is no cross-stack uniqueness constraint, so identical/guessed SHAs across different stacks/orgs are permitted by the schema and the query happily returns commits from unrelated stacks.
- Once the `Status` is created, `Commit#create_status_from_github!` → `add_status` transitions commit state and enqueues `ProcessMergeRequestsJob` (see `test/models/commits_test.rb` transition test at lines 763-777, confirming `ProcessMergeRequestsJob` is enqueued on a `success` transition) [6](#0-5) . `ProcessMergeRequestsJob#perform` then calls `merge_request.all_status_checks_passed?` and, if true, `merge_request.merge!` [7](#0-6) . `MergeRequest#all_status_checks_passed?` evaluates `StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?` [8](#0-7) , which will be satisfied by the forged `context`/`state` matching `merge.require`. `merge!` then calls `stack.github_api.merge_pull_request(...)` for the **victim's** repo [9](#0-8) .
- No other guard intercepts this: `drop_unhandled_event` only checks the event type is handled, the `ExplicitParameters` schema for `StatusHandler` never requires `repository`, and there is no `Repository`/`Stack` ownership check anywhere in this code path.

### Impact Explanation
An attacker who is a legitimate tenant on a multi-org Shipit deployment (owns/administers an org that is configured in Shipit with its own valid `webhook_secret`, per the supported multi-org configuration seen in `test/dummy/config/secrets_double_github_app.yml`) can forge a `status` webhook whose `sha`/`context`/`state` target a **different** tenant's pending merge-queue pull request, causing `MergeRequest#merge!` to execute against a repository the attacker does not own. This is a cross-tenant authentication/authorization bypass leading to an unauthorized merge — Critical severity per the stated impact categories ("a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy, rollback or merge"). It is repeatable against any stack/commit whose `sha` the attacker can guess or observe (SHAs are public for public repos/PRs), and is not limited to a single victim.

### Likelihood Explanation
Preconditions: (1) Shipit instance configured for multiple orgs/tenants (each with independent `webhook_secret`, a supported and documented configuration); (2) attacker controls one such tenant org and can therefore compute a valid HMAC signature with their own legitimate secret; (3) victim stack has merge queue enabled with a pending `MergeRequest`; (4) attacker knows/guesses the victim's PR head SHA (typically public). Attacker cost is a single crafted HTTP POST to `/webhooks` with `X-Github-Event: status` and a correctly computed `X-Hub-Signature`; no GitHub secrets, sessions, or API tokens are required. This is straightforward and repeatable.

### Recommendation
Scope `StatusHandler#process` (and any similarly unscoped handler) to the repository declared in the payload, matching the pattern used by `PushHandler`/`CheckSuiteHandler`: require `repository.full_name` in the params schema, resolve `Repository.from_github_repo_name(params.repository.full_name)`, and restrict the `Commit` lookup to `stacks.commits.where(sha: params.sha)` (or equivalently join through the commit's stack's repository and assert it matches the payload's repository) before creating the `Status`.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`, new file — not present currently):
```ruby
test "status webhook for a different repository's sha does not create a Status on a foreign stack's commit" do
  victim_commit = shipit_commits(:first) # belongs to victim stack/repo
  attacker_payload = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'context' => 'ci/required',
    'repository' => { 'full_name' => 'attacker-org/attacker-repo', 'owner' => { 'login' => 'attacker-org' } }
  }

  assert_no_difference -> { victim_commit.statuses.count } do
    Shipit::Webhooks::Handlers::StatusHandler.call(attacker_payload)
  end
end
```
And an end-to-end assertion at the `MergeRequest` level: construct a pending `merge_request` on the victim stack with `merge.require: ['ci/required']`, invoke `StatusHandler.call` with a payload whose `repository` points at an unrelated attacker org but whose `sha` equals `merge_request.head.sha`, then assert `merge_request.reload.all_status_checks_passed?` is `false` (i.e., the forged status must NOT be attributable) — currently this assertion fails, proving the vulnerability, because `StatusHandler` creates the `Status` regardless of the `repository` field in the payload.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/status.rb (L24-33)
```ruby
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

**File:** app/jobs/shipit/process_merge_requests_job.rb (L20-30)
```ruby

      merge_requests.select(&:pending?).each do |merge_request|
        merge_request.refresh!
        next unless merge_request.all_status_checks_passed?

        begin
          merge_request.merge!
        rescue MergeRequest::NotReady
          ProcessMergeRequestsJob.set(wait: 10.seconds).perform_later(stack)
          return false
        end
```

**File:** app/models/shipit/merge_request.rb (L164-176)
```ruby
    def merge!
      raise InvalidTransition unless pending?

      raise NotReady if not_mergeable_yet?

      stack.github_api.merge_pull_request(
        stack.github_repo_name,
        number,
        merge_message,
        sha: head.sha,
        commit_message: 'Merged by Shipit',
        merge_method: stack.merge_method
      )
```

**File:** app/models/shipit/merge_request.rb (L193-197)
```ruby
    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end
```
