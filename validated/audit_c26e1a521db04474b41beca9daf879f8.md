### Title
Cross-stack status forgery via unscoped SHA lookup in `Commit.where(sha:)` triggers victim's merge queue - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits purely by `sha`, with no scoping to the repository that sent the webhook, unlike every other handler in the same module which resolves a `repository`/`stacks` scope from `params.repository.full_name` before acting. Because the `commits` table enforces uniqueness only on `(sha, stack_id)` (not on `sha` alone), the same SHA can legitimately exist in multiple stacks (e.g., forks or mirrors sharing history), and a status event addressed to one repository will be applied to every commit row across every stack sharing that SHA, including `stack.schedule_merges` being invoked for a victim stack the attacker never authenticated to.

### Finding Description
The broken binding: "a `status` webhook accepted for `params.repository.full_name` == R must only mutate commits belonging to stacks whose `Repository` matches R" — this equality is **not enforced**.

`app/models/shipit/webhooks/handlers/handler.rb` defines a `stacks` helper that properly scopes to `Repository.from_github_repo_name(repository_name)`, and it is used correctly by handlers such as `PullRequest::EditedHandler`, `PullRequest::ClosedHandler`, `PullRequest::LabeledHandler`, etc. [1](#0-0) 

`StatusHandler`, however, never consults `params.repository` at all — its param schema doesn't even require it — and queries commits globally: [2](#0-1) 

`Commit#create_status_from_github!` calls `add_status`, and `add_status` invokes `stack.schedule_merges` whenever the new status is `pending` or `success`: [3](#0-2) 

The schema explicitly permits the same SHA across multiple stacks — uniqueness is `(sha, stack_id)`, not `sha` alone: [4](#0-3) [5](#0-4) 

Root cause: git commit SHAs are content hashes shared across any repositories with common ancestry (forks, mirrors, or multiple Shipit stacks tracking the same upstream repo at different environments/branches). `StatusHandler#process` treats "matches this SHA" as sufficient authorization to mutate a commit's status and cascade `stack.schedule_merges`, without verifying the SHA belongs to the same `Repository` that the (signature-verified) webhook payload names.

Exploit flow: an attacker who owns/controls a repository that shares a common ancestor commit `S` with a victim's tracked repository (e.g., they forked it, or it was mirrored) can trigger a genuine, correctly-signed `status` webhook naming their own repository and `sha: S`, `state: success` (e.g. by posting a commit status via the GitHub API against their own repo/commit, causing GitHub to deliver a validly-signed webhook to Shipit for that org/app installation). `StatusHandler#process` ignores the `repository` field, finds the victim's `Commit` row(s) with the same `sha`, calls `create_status_from_github!`, transitions state to `success`, and unconditionally calls `stack.schedule_merges`, which for a `merge_queue_enabled` stack re-evaluates the entire queue via `ProcessMergeRequestsJob`/`MergeRequest` scheduling — see the existing test explicitly documenting this side effect: [6](#0-5) .

Signature verification (`verify_signature` in `WebhooksController`) does not prevent this because it only authenticates that the payload came from GitHub for the organization named in the payload's own `repository.owner.login` — it says nothing about which stack's commits the handler is permitted to touch, and `StatusHandler` never checks that.

### Impact Explanation
The result is a write (a new `Status` row plus a queue-scheduling side effect) applied to a victim stack's commit and merge queue, triggered by a webhook payload that authenticated only the attacker's own repository/organization — a payload for one repository mutating another's stack/commit and perturbing an unauthorized merge queue processing cycle. This matches the "Critical" category: a payload for one repository mutating another's stack/commit, and unauthorized influence over merge/deploy processing. The blast radius is any stack whose commit history overlaps (forks, mirrors, monorepo splits) with a repository the attacker controls, and is repeatable on demand since the attacker can generate arbitrary numbers of status events against their own repo.

### Likelihood Explanation
Preconditions: (1) attacker owns a repository that shares at least one commit SHA with a victim `merge_queue_enabled` stack (realistic for forks/mirrors/renamed repos, or any organization-wide GitHub App installation covering the attacker's own account); (2) the attacker's own repository/organization must pass the existing `verify_signature` check, which is satisfied naturally by genuine GitHub-delivered webhooks for a repository the attacker controls — no secret needs to be guessed. No Shipit session, API token, or elevated GitHub permission is required beyond normal control of a repository. This is low-cost and repeatable.

### Recommendation
In `StatusHandler`, require and use `params.repository.full_name` (matching the pattern used by other handlers) to scope the commit lookup, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or `Commit.joins(stack: :repository).where(sha: params.sha, shipit_repositories: { id: repository.id })`, so a status event can only mutate commits belonging to stacks of the repository that GitHub actually attributed the event to.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "status webhook for repository A does not mutate a commit/stack belonging to repository B sharing the same sha" do
  victim_stack = shipit_stacks(:shipit) # merge_queue_enabled stack, unrelated to attacker repo
  shared_sha = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
  victim_commit = victim_stack.commits.create!(sha: shared_sha, message: "victim", author: shipit_users(:walrus), committer: shipit_users(:walrus), authored_at: Time.now, committed_at: Time.now)

  attacker_repo_payload = {
    'sha' => shared_sha,
    'state' => 'success',
    'context' => 'ci/attacker',
    'branches' => [{ 'name' => 'master' }],
    'repository' => { 'full_name' => 'attacker/unrelated-repo' }
  }

  assert_no_enqueued_jobs only: ProcessMergeRequestsJob do
    Shipit::Webhooks::Handlers::StatusHandler.call(attacker_repo_payload)
  end

  refute victim_commit.reload.statuses.exists?(context: 'ci/attacker'),
    "attacker's status webhook for an unrelated repository must not create a status on the victim's commit"
end
```
Both sides of the equality: LHS = "commits mutated by this webhook" (currently: all `Commit` rows with `sha == shared_sha`, i.e. includes `victim_commit`); RHS = "commits belonging to stacks of `attacker/unrelated-repo`" (empty set). They diverge today because `StatusHandler#process` never filters by repository, confirming the vulnerability.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-24)
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

**File:** db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb (L1-5)
```ruby
class IndexCommitsOnStackIdAndSha < ActiveRecord::Migration[5.1]
  def change
    add_index :commits, %i(sha stack_id), unique: true
  end
end
```

**File:** test/dummy/db/schema.rb (L79-86)
```ruby
    t.string "sha", limit: 40, null: false
    t.integer "stack_id", limit: 4, null: false
    t.datetime "updated_at"
    t.index ["author_id"], name: "index_commits_on_author_id"
    t.index ["committer_id"], name: "index_commits_on_committer_id"
    t.index ["created_at"], name: "index_commits_on_created_at"
    t.index ["sha", "stack_id"], name: "index_commits_on_sha_and_stack_id", unique: true
    t.index ["stack_id"], name: "index_commits_on_stack_id"
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
