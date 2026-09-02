### Title
Unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` lets a status event from one repository flip commit state for another stack sharing the same SHA - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits purely by `sha`, with no filter on `repository`/`stack`, and then writes a `Status` for every matching `Commit` row regardless of which repository the incoming webhook actually authenticated for. Because GitHub webhook signatures are verified at the organization level (not per-repository), any real status event from any repository under the same GitHub organization — including forks that share commit history with a target repo — can flip `deployable?`/merge-eligibility for a completely different stack whose commits happen to share that SHA. This is independent of `review_stacks_enabled`, which only affects the pull_request provisioning handlers, not `StatusHandler`.

### Finding Description
The broken invariant, stated as an equality that should hold but does not:
`status.stack_id == webhook.repository_that_authenticated_the_request.stack_id` for every `Status` created by `StatusHandler#process`.

Code path:
- `StatusHandler#process`:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [1](#0-0) 

This query is scoped only by `sha`, across the entire `commits` table, i.e. across every `Stack`/`Repository` known to the Shipit instance. There is no `params.repository.full_name` check, no `stack_id` filter, nothing tying the write back to the repository that actually emitted the webhook.

`create_status_from_github!` then calls `add_status`, which persists a `Status` and, on create, triggers `enable_ci_on_stack` and `schedule_continuous_delivery` for the affected commit's own stack: [2](#0-1) [3](#0-2) 

`Commit#deployable?` is driven by the aggregate `status` (built from all `Status` rows tied to the commit), so injecting a `success` status for `deploy/production` (a context the victim stack requires) can flip `deployable?`/merge-blocking behavior on a stack that never received a webhook of its own: [4](#0-3) 

`WebhooksController` verifies the signature per-organization (`Shipit.github(organization: ...).verify_webhook_signature`), not per-repository, so any legitimate webhook (real GitHub-triggered `status` event) from any repository under the same org passes signature verification. If two repos under that org share commit SHAs (a fork of the target repo, or a repo that was renamed/merged, or any repo whose history intersects), a status delivered for the attacker's own repo will be applied by `StatusHandler` to every `Commit` row across every stack with that SHA — including the victim's stack, in a different repository.

The `review_stacks_enabled`/provisioning-precedence issue referenced in the question (in `OpenedHandler#provision?` and similar handlers, where `repository.review_stacks_enabled && ...allow_all? || (...allow_with_label? && ...) || (...prevent_with_label? && ...)` has an operator-precedence bug that lets stacks provision even when `review_stacks_enabled` is false) is a real, separate bug: [5](#0-4) 
However, this precedence bug pertains only to whether a review stack gets *provisioned* via pull_request events; it has no bearing on `StatusHandler`, which performs its unscoped `Commit.where(sha:)` lookup unconditionally regardless of `review_stacks_enabled`. The cross-stack status-pollution vulnerability exists whether `review_stacks_enabled` is true or false — the question's framing that the two bugs must combine is not supported by the code; the `StatusHandler` scoping bug alone is sufficient and is the actual root cause of the flip.

None of the listed guards prevent this: `verify_signature`/`GitHubApp#verify_webhook_signature` only assert the payload came from the correct GitHub organization, not the correct repository; `ExplicitParameters` only validates the shape of `sha`/`state`/`context`, not repository ownership; there is no `require_permission!`/`stacks` scope check inside `StatusHandler`.

### Impact Explanation
A `Status` record (and its downstream effects: `deployable?`, `blocked?`, `enable_ci!`, `schedule_continuous_delivery`, and merge-request status checks via `Commit#statuses_and_check_runs`) can be written for a stack that the attacker never actually sent a webhook for. This is "a payload for one repository mutating another's stack/commit" and can force or block a deploy/merge on a stack the attacker does not control, provided the two repos (attacker's and the victim's) share a commit SHA and are validated by the same organization-level webhook secret. This matches the Critical class: unauthorized deploy/merge/block resulting from a cross-tenant write.

### Likelihood Explanation
Preconditions: attacker needs a repository under the same GitHub organization as the victim stack (or any repo that shares commit SHAs with the victim, e.g. a fork with unmerged history retaining the same SHAs) so that the webhook signature validates; no Shipit credentials, API tokens, or team membership are required. GitHub itself will deliver a correctly-signed `status` event for any commit in the attacker's own repository, including SHAs inherited from a fork's upstream history. Feasibility is high in typical GitHub organizations with many repos sharing one Shipit GitHub App installation, and the write is repeatable per SHA collision found.

### Recommendation
Scope the commit lookup in `StatusHandler#process` (and analogously in `PushHandler`/`CheckSuiteHandler` if they share this pattern) to the repository that authenticated the webhook, e.g. `Commit.joins(:stack).merge(Stack.where(repository: repository_from_payload)).where(sha: params.sha)`, or filter by `stack_id` derived from `params.repository.full_name` before creating a `Status`. Independently, fix the operator-precedence bug in `provision?`/`unarchive?`/`archive?`/`respond_to_label_change?` methods across the pull_request handlers so `review_stacks_enabled` gates every provisioning branch, e.g. `repository.review_stacks_enabled && (provisioning_behavior_allow_all? || (...) || (...))`.

### Proof of Concept
```ruby
test "status webhook for one repository must not affect a commit belonging to another stack sharing the same sha" do
  victim_stack = shipit_stacks(:shipit) # requires 'deploy/production' context, review_stacks_enabled false on its repository
  shared_sha = "deadbeef" * 5
  victim_commit = victim_stack.commits.create!(sha: shared_sha, author: shipit_users(:walrus), authored_at: Time.now, committer: shipit_users(:walrus), committed_at: Time.now, message: "victim commit")

  other_stack = shipit_stacks(:cyclimse) # different repository/org member repo, unrelated to victim
  attacker_commit = other_stack.commits.create!(sha: shared_sha, author: shipit_users(:walrus), authored_at: Time.now, committer: shipit_users(:walrus), committed_at: Time.now, message: "attacker fork commit, same sha")

  refute_predicate victim_commit.reload, :deployable? # baseline: no successful deploy/production status yet

  params = Shipit::Webhooks::Handlers::StatusHandler::Params.new(
    sha: shared_sha, state: "success", context: "deploy/production", description: nil, target_url: nil, created_at: Time.now.iso8601, branches: []
  )
  Shipit::Webhooks::Handlers::StatusHandler.new(params).process

  assert_predicate victim_commit.reload, :deployable?, "status delivered for attacker's repo flipped deployability on an unrelated victim stack"
end
```
This demonstrates that `StatusHandler#process`'s `Commit.where(sha: params.sha)` (with no repository/stack scoping) writes a `Status` onto `victim_commit`, changing `deployable?` from `false` to `true`, even though the webhook was never scoped to `victim_stack`'s repository.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/status.rb (L18-20)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

```

**File:** app/models/shipit/status.rb (L36-44)
```ruby
    private

    def enable_ci_on_stack
      commit.stack.enable_ci!
    end

    def schedule_continuous_delivery
      commit.schedule_continuous_delivery
    end
```

**File:** app/models/shipit/commit.rb (L219-237)
```ruby
    delegate :pending?, :success?, :error?, :failure?, :blocking?, :state, to: :status

    def active?
      return false unless stack.active_task?

      stack.active_task.includes_commit?(self)
    end

    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end

    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
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
