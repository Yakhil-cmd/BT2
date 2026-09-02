### Title
`StatusHandler#process` resolves commits by SHA alone, letting a status webhook from an unrelated repository write `Status` rows into a victim stack's commit and flip merge-queue CI gating - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` looks up commits with `Commit.where(sha: params.sha)` and applies the incoming webhook's state to every matching row, without checking that the payload's `repository.full_name` matches the owning stack's repository. Since git SHAs are content-addressed and identical across forks/clones that share history, a status webhook legitimately emitted by an attacker's own (forked) repository for a shared-history commit is applied to any other stack's `Commit` row with the same SHA, including a victim's pending merge-queue PR head, letting `MergeRequest#all_status_checks_passed?` see a forged "success".

### Finding Description
The binding that should hold is: `Status` rows consumed by `MergeRequest#all_status_checks_passed?` for a given `head` commit must only be created from webhook payloads whose `repository.full_name` equals `head.stack.repository.full_name`. This binding is broken.

`StatusHandler#process` is:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [1](#0-0) 

This performs a **global, unscoped** lookup by `sha` across every stack in the database, with no filter on `payload['repository']['full_name']`. Contrast this with `PushHandler#process`, which correctly restricts to the repository-scoped `stacks` helper before matching branches:
```ruby
def process
  stacks
    .not_archived
    .where(branch:)
    .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
end
``` [2](#0-1) 

The base `Handler` class even provides this repository-scoping primitive (`stacks`, derived from `payload.dig('repository', 'full_name')`), which `StatusHandler` simply does not use: [3](#0-2) 

For every `Commit` row matching the SHA (potentially belonging to many different stacks/repositories), `create_status_from_github!` runs and creates a `Status` scoped to *that commit's own* `stack_id`:
```ruby
def create_status_from_github!(github_status)
  add_status do
    statuses.replicate_from_github!(stack_id, github_status)
  end
end
``` [4](#0-3) 
`add_status` then calls `stack.schedule_merges` when the new status is `pending` or `success`: [5](#0-4) 

This feeds `MergeRequest#reject_unless_mergeable!` -> `any_status_checks_failed?` / `all_status_checks_passed?`, which read `head.statuses_and_check_runs` with no repository check at all: [6](#0-5) 
and ultimately `merge!` calls `stack.github_api.merge_pull_request` using `head.sha`: [7](#0-6) 

**Why this is exploitable without needing a true SHA-1 collision:** Git commit SHAs are content-addressed and are identical across forks and clones that share the same commit objects (same tree, parents, author/committer, timestamps, message). Any public fork of a repository shares the SHAs of all commits up to the fork point / any point where history hasn't diverged (e.g., merge bases, unmodified base branches, or PRs opened before new commits are added). An attacker who forks a repository that a victim also tracks (or that shares ancestry with the victim's tracked repo) can cause GitHub to emit a legitimately-signed `status` event **from their own repository** for a SHA that also exists as `head.sha` of a pending `MergeRequest` in a completely different Shipit stack. `verify_signature` only checks that the webhook is authentically from GitHub for the org identified in the payload (`repository_owner`) — it does not, and cannot, prevent a legitimate webhook about repository A from being misapplied to a `Commit` belonging to stack B, because `StatusHandler` never checks which repository a `Commit` belongs to.

Existing guards do not stop this:
- `verify_signature` / `drop_unhandled_event` only validate that GitHub is the sender and that the event type is a `status` event; they say nothing about which stack the SHA belongs to.
- `ExplicitParameters` schema on `StatusHandler` requires `sha`/`state`/etc. but does not require or check `repository`.
- No model validation ties a `Status`/`Commit` row to a repository check against the incoming payload.

### Impact Explanation
A single crafted (but genuinely GitHub-signed) `status` webhook from an attacker-controlled repository can write a `Status` row (`state: 'success'`) into a `Commit` belonging to an unrelated victim stack, as long as the SHA is shared (via forked/common history) or otherwise coincides. If that `Commit` is the `head` of a `pending` `MergeRequest` in a stack with `merge_queue_enabled: true`, this can cause `all_status_checks_passed?` to report true and `any_status_checks_failed?`/`any_status_checks_missing?` to clear, unblocking `MergeRequest#merge!`, which invokes `stack.github_api.merge_pull_request` using the app's `GITHUB_TOKEN`/installation credentials — i.e., "a payload for one repository mutating another's stack" and potentially "an unauthorized merge," which matches the Critical severity bucket in scope.

### Likelihood Explanation
Preconditions: victim stack has `merge_queue_enabled: true` with a `pending` `MergeRequest`, and the attacker needs a commit SHA that coincides with `head.sha` of that pending PR. Practical routes to a coincidence are (a) forking the victim's tracked repository and sending a status for a shared ancestor commit while the victim's PR head happens to equal that shared commit (e.g., a PR with no new commits over base, or a merge commit identical across forks), or (b) an actual SHA-1 collision, which is not realistically achievable by an unprivileged, low-cost attacker for arbitrary targets. The shared-fork-history route is realistic and repeatable across many stacks that track public/forked repositories, but landing the collision precisely on a currently-pending merge-queue head SHA narrows the window and requires some luck/timing, so likelihood is moderate rather than trivial — however, the underlying binding failure in `StatusHandler#process` is unconditionally present in the code regardless of how the SHA collision is engineered.

### Recommendation
In `app/models/shipit/webhooks/handlers/status_handler.rb`, scope the commit lookup by the payload's repository, mirroring the `stacks` helper already used elsewhere (e.g., `Handler#stacks`), for example: iterate `stacks.commits.where(sha: params.sha)` (or otherwise join through `Repository.from_github_repo_name(repository_name)`) instead of the global `Commit.where(sha: params.sha)`, so a `Status` can only be created on a `Commit` whose `stack.repository.full_name` matches `payload['repository']['full_name']`.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`, or a `MergeRequest` test):
1. Create two stacks, `victim_stack` (repository `victim/repo`) and `attacker_stack` (repository `attacker/repo`), both persisted normally via factories.
2. Create a `Commit` under `victim_stack` with `sha: "deadbeef..."` and a `MergeRequest` on `victim_stack` with `merge_status: 'pending'`, `head:` that commit, `stack.merge_queue_enabled: true`.
3. Assert baseline: `merge_request.all_status_checks_passed?` is `false` (no statuses yet), and `victim_stack.commits.find_by(sha: "deadbeef...").statuses` is empty.
4. Invoke `Shipit::Webhooks::Handlers::StatusHandler.call({'sha' => 'deadbeef...', 'state' => 'success', 'context' => 'ci', 'repository' => {'full_name' => 'attacker/repo'}})` — a payload naming `attacker/repo`, not `victim/repo`.
5. Assert the equality binding is violated as coded: `victim_stack.commits.find_by(sha: 'deadbeef...').statuses.reload` is non-empty and `state == 'success'` even though the payload's `repository.full_name` (`attacker/repo`) does not equal `victim_stack.repository.full_name` (`victim/repo`).
6. Assert `merge_request.reload.all_status_checks_passed?` is now `true`, and stub/mock `stack.github_api.merge_pull_request` to assert it *would* be invoked by `schedule_merges`/`merge!` given the forged status — demonstrating the unauthorized-merge path is reachable purely from an out-of-repository webhook.

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

**File:** app/models/shipit/merge_request.rb (L193-206)
```ruby
    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end

    def any_status_checks_failed?
      status = StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec)
      status.failure? || status.error?
    end

    def any_status_checks_missing?
      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).missing?
    end
```
