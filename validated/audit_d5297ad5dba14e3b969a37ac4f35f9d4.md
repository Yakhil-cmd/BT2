### Title
Unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` lets a status authenticated by one repository mutate commit status/deployability in unrelated stacks — ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` resolves target commits purely by `sha`, with no filter on `params.repository` or any repository/stack ownership check, then calls `commit.create_status_from_github!` on every match. [1](#0-0)  Because `Commit` rows are keyed only by `sha` per stack and the query spans the entire table, a status payload that is legitimately signed for repository A will also update `Commit`/`Status` rows belonging to any other stack (same or different repository) whose commit history happens to contain that same SHA (e.g. shared ancestor commits between a fork and its upstream, or multiple stacks tracking the same repo).

### Finding Description
The broken binding is: **the stack/repository that receives a status update == the repository that authenticated the webhook**. Tracing the code shows this equality does not hold:

- `StatusHandler#process` does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — `params.repository` (present in the GitHub payload schema for status events) is never read or used to scope the query. [1](#0-0) 
- `Commit#create_status_from_github!` writes into `statuses` for whatever commit was matched and calls `add_status`, which recomputes `status`, emits `deployable_status`/`commit_status` hooks, and calls `stack.schedule_merges` — i.e., it can flip merge/ship/block state for the stack owning that `Commit` row. [2](#0-1) [3](#0-2) 
- `Commit` is `belongs_to :stack` with no cross-table uniqueness constraint tying `sha` to a single repository; the same SHA can legitimately exist in multiple `Commit` rows across different stacks (multi-stack repos, forks sharing history, etc.). [4](#0-3) 

Regarding the second half of the claim — that a `review_stacks_enabled: false` setting interacting with a "provision? precedence" bug is required to weaponize this — that linkage does not exist in the code. `review_stacks_enabled` is only referenced in `PullRequest::OpenedHandler`, `ReopenedHandler`, `LabeledHandler`, `UnlabeledHandler`, and `Repository`/`NullRepository`; it is never read by `StatusHandler` or `Commit`. [5](#0-4)  `StatusHandler` is unconditional — it processes matching commits regardless of whether the owning stack is a review stack, has review stacks enabled, or requires `buildkite/deploy` at all. The precedence issue in `provision?`/`unarchive?` (where `repository.review_stacks_enabled && allow_all?` is grouped by `&&`/`||` precedence such that the `allow_with_label?`/`prevent_with_label?` branches are not gated by `review_stacks_enabled`) is a real, separate logic bug in the PR-provisioning handlers, [5](#0-4) [6](#0-5)  but it does not gate or interact with `StatusHandler#process` in any way. The question's causal chain (review-stacks-disabled + provisioning bug → forces the status flip to matter) is not supported by the code; `StatusHandler`'s unscoped write is exploitable independent of `review_stacks_enabled` or the provisioning behavior setting.

No existing guard closes the gap for `StatusHandler` itself: signature verification authenticates that the payload came from *some* registered repository, but nothing in `StatusHandler`/`Commit` re-checks that the matched `Commit#stack#repository` corresponds to `params.repository`.

### Impact Explanation
A commit-status write lands on every stack whose `Commit` table has a matching `sha`, not only the stack/repository that GitHub actually signed the webhook for. Since `add_status` drives `deployable?`/`blocked?` semantics and triggers `stack.schedule_merges`, this is a "payload for one repository mutating another's stack, commit" scenario — matching the Critical impact category (record written for a repository that did not authenticate it, leading to unauthorized deploy/block/merge changes). The blast radius is bounded by which stacks actually share a SHA with the authenticating repository's commit history (typically fork/upstream pairs or multiple stacks against the same repo), not arbitrary unrelated tenants.

### Likelihood Explanation
Exploitation requires the attacker to control (or push to) a repository that is itself registered as a Shipit repository/stack and whose commit history shares a SHA with the victim stack (e.g., a fork of the victim repo, or a shared subtree/rebase). The attacker still needs a validly-signed webhook from GitHub for their own repository — no forged signatures or stolen secrets are needed, since GitHub itself will emit the `status` event when the attacker (as the fork owner) posts a commit status via a CI integration on their own repo, and that same commit exists (with identical SHA) in the victim stack's commit table. This is a plausible, low-cost, repeatable scenario in fork-heavy or multi-stack setups, but is not a fully unauthenticated "any internet user with zero repo relationship" attack — it requires the attacker to own/administer a Shipit-registered repository that shares history with the victim.

### Recommendation
Scope the `StatusHandler` (and `CheckRunHandler`, if it has the same pattern) lookup by repository, not just SHA — e.g. join through `Commit -> Stack -> Repository` and filter by `params.repository.full_name` before calling `create_status_from_github!`. Separately (unrelated to this finding but a genuine bug), fix the operator-precedence in `OpenedHandler#provision?` and `ReopenedHandler#unarchive?` by explicitly parenthesizing `repository.review_stacks_enabled && (...)` around the entire disjunction so `review_stacks_enabled: false` disables provisioning regardless of `provisioning_behavior`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb (conceptual addition)
test "#process only updates statuses for commits belonging to the authenticating repository" do
  repo_a = shipit_repositories(:shipit) # attacker-controlled / authenticated repo
  repo_b = create_repository(owner: "victim", name: "app")
  stack_b = create_stack(repository: repo_b, environment: "production")

  shared_sha = "a" * 40
  commit_a = create_commit(stack: create_stack(repository: repo_a), sha: shared_sha)
  commit_b = create_commit(stack: stack_b, sha: shared_sha)

  params = { sha: shared_sha, state: "failure", context: "buildkite/deploy",
             repository: { full_name: repo_a.full_name } }

  Shipit::Webhooks::Handlers::StatusHandler.new(nil, params).process

  # BEFORE: commit_b (repo_b/stack_b) had no failure status for buildkite/deploy
  # AFTER (expected, correct behavior): commit_b.reload.statuses should remain unchanged
  assert_not commit_b.reload.statuses.exists?(context: "buildkite/deploy", state: "failure"),
             "status for repo_a's webhook leaked into repo_b's commit/stack"

  # ACTUAL (current code): this assertion fails because Commit.where(sha:) is global
  assert commit_b.reload.statuses.exists?(context: "buildkite/deploy", state: "failure")
end
```

Note: the compound claim involving `review_stacks_enabled: false` plus the `provision?` operator-precedence bug is not corroborated as part of this exploit chain — `StatusHandler` never consults `review_stacks_enabled`, and the precedence bug lives in unrelated PR-provisioning handlers (`OpenedHandler`, `ReopenedHandler`). The reported finding above reflects only the confirmed, independent unscoped-write bug in `StatusHandler#process`.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/commit.rb (L11-12)
```ruby
    belongs_to :stack
    has_many :statuses, -> { order(created_at: :desc) }, dependent: :destroy, inverse_of: :commit
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L65-70)
```ruby
          def provision?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L70-75)
```ruby
          def unarchive?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end
```
