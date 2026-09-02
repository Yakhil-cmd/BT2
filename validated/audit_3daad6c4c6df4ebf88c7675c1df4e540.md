### Title
`status` webhook context-flip on cross-stack `Commit` rows sharing a SHA - unbounded write in `StatusHandler#process` (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` writes a GitHub `status` (e.g. `ci/coverage: failure`) to **every** `Commit` row matching the raw `sha`, with no scoping to the repository/stack that authenticated the webhook. Because `Shipit::Commit belongs_to :stack` [1](#0-0)  and multiple stacks of the *same* repository (e.g. a production stack and an auto-provisioned review stack from `review_stacks_enabled=true, provisioning_behavior=allow_all`) independently create their own `Commit` row for shared ancestor SHAs, a single signed `status` event about one stack's commit is replicated onto the sibling stack's identically-shaed commit, flipping its deployability/merge-queue state.

### Finding Description
The broken binding: `status.stack_id == webhook.repository.stack_id` is expected to hold, but `StatusHandler` never establishes it.

`StatusHandler#process`:
```
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [2](#0-1) 

This is a **global, unscoped** `Commit.where(sha:)` query — it is not filtered by `repository`, `stack_id`, or any other tenant boundary, even though the `params` schema only requires `sha`/`state`/`context` and accepts `branches`, with no repository reference used for scoping [3](#0-2) .

`Commit belongs_to :stack` [1](#0-0)  means every stack that tracks a given repository (production stack tracking `master`, and any review stack auto-provisioned per PR via `ReviewStackAdapter`/`OpenedHandler` when `review_stacks_enabled && provisioning_behavior_allow_all?` [4](#0-3) ) maintains its **own** `Commit` row for the same SHA once that SHA is reachable via that stack's branch history (via `GithubSyncJob` for the base branch, and via `find_or_create_commit_from_github_by_sha!`/PR head/base sync for the review stack, e.g. `app/models/shipit/pull_request.rb:52-61` and `app/models/shipit/merge_request.rb:303-312`). Ancestor commits (any commit already merged into the base branch before the PR was opened) will be present, with the identical SHA, in *both* the base stack and the auto-provisioned review stack's `Commit` table.

`create_status_from_github!` → `add_status` recomputes the commit's aggregate `state` via `Status::Common#blocking?`/`#required?` (delegated to `stack.blocking_statuses`/`stack.required_statuses` [5](#0-4) ) and this state feeds `Commit#deployable?`:
```
def deployable?
  !locked? && (stack.ignore_ci? || (success? && !blocked?))
end
``` [6](#0-5) 
and `Commit#blocked?` walks **that stack's** undeployed commit range for any `blocking?` status [7](#0-6) . It also fires `deployable_status`/`ProcessMergeRequestsJob` hooks as shown in `test/models/commits_test.rb:678-777`, which drive the merge queue and deploy gating [8](#0-7) .

Attack: an unprivileged attacker opens a PR against a repository with `review_stacks_enabled=true` and `provisioning_behavior=allow_all`. GitHub auto-provisions a review stack for that PR (`ReviewStackAdapter#create!`) which shares ancestor commits (identical SHAs) with the base/production stack. Any legitimate `status` webhook (real, correctly signed by GitHub for that repository/org) naming `context: ci/coverage`, `state: failure` on one of those shared SHAs is written by `StatusHandler` to **every** `Commit` row with that SHA — including the row belonging to the production stack — not only the row for the stack the event is nominally "about." This is a genuine cross-stack write within the same repository/organization, so `verify_signature`'s per-organization check (`Shipit.github(organization: repository_owner)` in `app/controllers/shipit/webhooks_controller.rb:24-30`) does not block it: the signature is valid for the org, but the handler has no additional binding tying the status to a single stack/repository record.

None of the existing guards intervene: `verify_signature` only authenticates the org, not the target stack; `drop_unhandled_event` only checks the event type is registered; the `params` schema in `StatusHandler` has no repository field to enforce scoping; `Commit`/`Stack` model validations do not constrain cross-stack SHA collisions since `Commit` is intentionally scoped `belongs_to :stack` and duplicate rows per stack for the same SHA are a normal, expected occurrence (confirmed by `by_sha`/`find_or_create_commit_from_github_by_sha!` all being explicitly stack-scoped elsewhere in the codebase, e.g. `app/models/shipit/pull_request.rb:52-61`, `app/models/shipit/merge_request.rb:303-312` — `StatusHandler` is the one outlier that is *not* scoped this way).

### Impact Explanation
A `status` event nominally about a review stack's commit (or vice versa) is written into a different stack's `Commit`/`Status` records for the same repository, flipping `deployable?`, blocking merges, or unblocking a deploy for a stack that never authenticated that status. This is a "payload for one repository/stack mutating another's stack/commit" — matching the Critical impact category (unauthorized deploy/rollback/merge decision driven by data that did not originate from, and was not scoped to, the affected stack). The blast radius is bounded to stacks that share commit history with a review-stack-enabled repository, but is trivially repeatable against any repository configured with `review_stacks_enabled=true, provisioning_behavior=allow_all` — an explicitly documented, commonly recommended configuration (`docs/review_stacks.md:12`).

### Likelihood Explanation
Preconditions: target repository must have `review_stacks_enabled=true` with `allow_all` (or `allow_with_label` and a labeled PR), a supported/common configuration. The attacker needs only the ability to open a PR (any GitHub user with fork/push access) and for GitHub/CI to emit a real `status` webhook on a SHA shared between the base and review stack (trivial: any ancestor commit shared by branch history, e.g. the PR's merge-base). No secrets, sessions, or privileged roles are required — this fully satisfies the "unprivileged attacker" model. Repeatable per PR/commit.

### Recommendation
Scope `StatusHandler#process` by the repository asserted in the webhook payload (`params.repository.full_name` / `params.name`), restricting the `Commit.where(sha:)` lookup to commits belonging to stacks whose `Repository` matches the authenticated repository, e.g. `Commit.joins(stack: :repository).where(sha: params.sha, shipit_repositories: { full_name: params.name/params.repository.full_name })`, mirroring the repository-scoped resolution already used in `PullRequest#find_or_create_commit_from_github_by_sha!` and `MergeRequest#find_or_create_commit_from_github_by_sha!`.

### Proof of Concept
minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`):
1. Create `repository_a` (`review_stacks_enabled: true`, `provisioning_behavior: :allow_all`).
2. Create `stack_production` for `repository_a` and `stack_review` (a `ReviewStack`) for `repository_a`, each with `blocking_statuses`/`required_statuses` including `ci/coverage`.
3. Create two `Commit` rows with the identical `sha = "deadbeef..."`, one `stack_id: stack_production.id`, one `stack_id: stack_review.id`, both currently `success?`/`deployable?`.
4. Build a webhook payload for `repository_a` (`{"sha" => sha, "state" => "failure", "context" => "ci/coverage", ...}`) intended for `stack_review` only.
5. Call `Shipit::Webhooks::Handlers::StatusHandler.new(payload).process`.
6. Assert: `stack_production.commits.find_by(sha:).reload.deployable?` is now `false` (or `blocked?` is `true`) — i.e. `commit_production.state == 'failure'` — proving the status "for" `stack_review` mutated `stack_production`'s commit/deployability, violating the binding `status.stack_id == webhook.intended_stack_id`.

### Citations

**File:** app/models/shipit/commit.rb (L11-11)
```ruby
    belongs_to :stack
```

**File:** app/models/shipit/commit.rb (L57-58)
```ruby
    delegate :broadcast_update, :github_repo_name, :hidden_statuses, :required_statuses, :blocking_statuses,
             :soft_failing_statuses, to: :stack
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/commit.rb (L231-237)
```ruby
    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L60-70)
```ruby
          def respond_to_pull_request_opened?
            params.action == "opened" &&
              provision?
          end

          def provision?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
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
