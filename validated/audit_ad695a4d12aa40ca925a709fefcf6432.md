This confirms the finding decisively. The base `Handler` class provides a `stacks` helper that scopes lookups via `Repository.from_github_repo_name(payload.dig('repository', 'full_name'))`, and `PushHandler` and `CheckSuiteHandler` both use this `stacks` scope to bind the webhook's payload repository to the correct `Stack`/`Repository` before touching any commit records. `StatusHandler`, however, bypasses this scoping entirely and queries `Commit.where(sha: params.sha)` globally, with no use of `stacks` or any check against `payload.dig('repository', 'full_name')`.

### Title
Unscoped global `Commit.where(sha:)` lookup in `StatusHandler#process` lets a status webhook from any repository merge a victim's pending `MergeRequest` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits purely by `sha` across the entire `commits` table, without checking that the webhook's `payload['repository']['full_name']` matches the `github_repo_name` of the `Stack` owning the matched `Commit`. Any GitHub repository whose webhook signature verifies for `Shipit.github(organization: repository_owner)` can therefore post a `status` event for a sha that happens to also exist as a victim `Stack`'s `MergeRequest#head` commit, causing `ProcessMergeRequestsJob` to merge the victim's PR.

### Finding Description
The broken binding: the equality that must hold is `payload.dig('repository','full_name') == commit.stack.github_repo_name` for the `Commit` being updated. In `StatusHandler#process` [1](#0-0) , this equality is never checked:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```

Compare with `PushHandler`, which does scope through `Repository.from_github_repo_name(repository_name)` via the `stacks` helper before touching any records [2](#0-1) , and `CheckSuiteHandler`, which similarly scopes `stacks.where(branch:)` before calling `stack.commits.where(sha:)` [3](#0-2) . The base `Handler` class provides exactly this scoping primitive (`stacks`, backed by `Repository.from_github_repo_name(payload.dig('repository','full_name'))`) [4](#0-3) , but `StatusHandler` does not use it.

`commit.create_status_from_github!` writes a `Status` record tied to `stack_id` derived from the matched `Commit`'s own `stack_id`, not from the webhook's repository [5](#0-4) . Once the status transitions the commit to `success`/`pending`, `add_status` schedules `stack.schedule_merges` [6](#0-5) , which enqueues `ProcessMergeRequestsJob` for the *victim's* stack. That job calls `merge_request.all_status_checks_passed?` [7](#0-6) , which in turn calls `StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?` [8](#0-7) , and on success calls `merge!`, which invokes `stack.github_api.merge_pull_request(stack.github_repo_name, number, ...)` against the **victim's** repository [9](#0-8) .

Why existing guards fail:
- `verify_signature` in `WebhooksController` only checks the HMAC against the GitHub App/org config keyed by `repository_owner` (`payload.dig('repository','owner','login')`), i.e., it authenticates "some repo belonging to a configured organization sent this", not "the specific repository whose commit is being updated sent this" [10](#0-9) .
- `drop_unhandled_event` and the `ExplicitParameters` schema for `StatusHandler` only validate `sha`/`state`/etc. shape; they don't require or check `repository` [11](#0-10) .
- No `require_permission!`, `User#authorized?`, or `stacks` scope is applied in this handler.

Exploit flow: attacker's `attacker/repo` belongs to (or is created under) the same GitHub organization/app config that Shipit trusts for webhook signature verification (a precondition — the org must be one Shipit has configured, since otherwise `verify_signature` raises `GithubOrganizationUnknown` and returns 422). The attacker pushes/copies the identical commit object (same tree/parents/author/committer/timestamps/message) that is the head of a victim `MergeRequest` into `attacker/repo` — since git SHAs are content-addressed, this reproduces the exact sha. The attacker's own CI (or a manually configured webhook on `attacker/repo`) posts a `status: success` event; GitHub signs it with the org's webhook secret, `verify_signature` passes, and `StatusHandler#process` matches the victim's `Commit` by `sha` alone and marks it successful, triggering the merge.

### Impact Explanation
This lets one repository's CI/webhook mutate another repository's `Stack` state (a `Status` record and, transitively, a merge decision) — matching the Critical category "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy, rollback or merge." The victim repository has its own PR merged via `stack.github_api.merge_pull_request` without the victim's own CI having reported success, purely because an unrelated repository's webhook happened to reference the same sha. This is repeatable against any victim stack whose `MergeRequest#head` sha the attacker can reproduce, and is scoped to any stack under the same Shipit-configured GitHub organization/app as the attacker-controlled repository.

### Likelihood Explanation
Preconditions: victim `Stack` has `merge_queue_enabled: true` with a `pending` `MergeRequest`; attacker needs a repository whose owner/org is one already configured in Shipit (`Shipit.github(organization:)` must resolve, or `GithubOrganizationUnknown` blocks the request) so its status webhook signature verifies; attacker needs the ability to reproduce the exact victim head commit sha in their own repo (trivial for public repos/forks — same content yields the same sha regardless of hosting repository) and to trigger a `status` webhook (via their own CI or a custom webhook configured on their own repo pointing at Shipit's public `/webhooks` endpoint). No Shipit session, API token, or GitHub secret is required beyond what the attacker's own repository/org membership already grants them for their own webhook. This is feasible in any deployment where multiple repositories share one Shipit-configured GitHub organization and the attacker controls or can create one of them.

### Recommendation
In `StatusHandler#process`, scope the lookup to the payload's repository, mirroring `PushHandler`/`CheckSuiteHandler`: use `stacks` (backed by `Repository.from_github_repo_name(payload.dig('repository','full_name'))`) to select the correct `Stack`(s), then query `stack.commits.where(sha: params.sha)` instead of the global `Commit.where(sha:)`.

### Proof of Concept
minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb` or `test/jobs/shipit/process_merge_requests_job_test.rb`):
1. Create victim `Stack` A with `github_repo_name: 'victim/repo'`, `merge_queue_enabled: true`, and a `MergeRequest` in `pending` state whose `head` is a `Commit` with `sha: 'deadbeef...'` belonging to Stack A.
2. Create a second `Stack`/`Repository` B (or none at all) with `github_repo_name: 'attacker/repo'`.
3. Simulate the webhook payload with `repository.full_name == 'attacker/repo'` and `sha: 'deadbeef...'`, `state: 'success'`, and invoke `Shipit::Webhooks::Handlers::StatusHandler.call(payload)`.
4. Assert (current, vulnerable behavior) that `commit_a.reload.statuses.last.state == 'success'` even though the payload's repository was `attacker/repo`, not `victim/repo` — i.e., `payload['repository']['full_name'] != commit_a.stack.github_repo_name` yet the status was still written.
5. Stub `Shipit.github.api.merge_pull_request` and assert it is called with `('victim/repo', merge_request.number, ...)` after running `ProcessMergeRequestsJob.perform_now(stack_a)`, proving an unauthorized merge on Stack A triggered by a payload naming `attacker/repo`.
6. After applying the fix (scoping via `stacks`/`Repository.from_github_repo_name`), assert the same payload no longer creates a `Status` on `commit_a` and `merge_pull_request` is never called.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
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

**File:** app/models/shipit/commit.rb (L366-384)
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
```

**File:** app/jobs/shipit/process_merge_requests_job.rb (L10-31)
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
```

**File:** app/models/shipit/merge_request.rb (L164-191)
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
      begin
        if stack.github_api.pull_requests(stack.github_repo_name, base: branch).empty?
          stack.github_api.delete_branch(stack.github_repo_name, branch)
        end
      rescue Octokit::UnprocessableEntity
        # branch was already deleted somehow
      end
      complete!
      true
    rescue Octokit::MethodNotAllowed # merge conflict
      reject!('merge_conflict')
      false
    rescue Octokit::Conflict # shas didn't match, PR was updated.
      raise NotReady
    end
```

**File:** app/models/shipit/merge_request.rb (L193-197)
```ruby
    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end
```

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
