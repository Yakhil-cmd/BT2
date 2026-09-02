### Title
Unscoped `Commit.where(sha:)` in `StatusHandler#process` lets a status webhook from one repository mutate commit status/deployability in another stack - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` looks up commits by bare SHA with no repository/stack scoping, then writes a GitHub status onto every matching `Commit` row across the entire database. A commit SHA is git content-addressed and can be shared across unrelated repositories/forks that Shipit tracks as separate stacks, so a legitimately signed webhook from repo A can flip `release/gate` to `success` on a commit that belongs to repo B's stack, changing that stack's `deployable?`/`blocked?` state and triggering `stack.schedule_merges`.

### Finding Description
Broken binding: the invariant the code should enforce is `status.repository == commit.stack.repository` for every `Commit` mutated by a status event; instead the code enforces only `status.sha == commit.sha`.

```ruby
# app/models/shipit/webhooks/handlers/status_handler.rb
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [1](#0-0) 

The `params` schema for this handler never requires or reads a `repository` field, confirming no repo-scoping is even attempted at the handler level: [2](#0-1) 

`Commit.where(sha: ...)` is a global, cross-stack, cross-repository query — `Commit` only `belongs_to :stack`, and nothing in the query filters by `stack.repository`. `create_status_from_github!` then writes the status and recomputes deployability/merge scheduling: [3](#0-2) [4](#0-3) 

Because `deployable?` and `blocked?` are derived from `status`/`blocking?` on the freshly written status, and `add_status` calls `stack.schedule_merges` whenever the new status is `pending?` or `success?`, flipping a required `release/gate` context to `success` on a victim stack's commit can make that commit deployable and trigger merge-queue/continuous-delivery scheduling for a stack the attacker never authenticated against: [5](#0-4) 

Exploit flow: the attacker owns/controls a GitHub repository that Shipit tracks (satisfying the "emit webhooks from a repository they own" capability). GitHub content-addresses commits by SHA, so a commit shared via fork/cherry-pick/history sharing between the attacker's repo and a victim's tracked repo has the identical SHA in both `Commit` tables (one row per stack that has seen that commit). The attacker creates/updates a commit status with `context: release/gate`, `state: success` on that SHA via the GitHub API on their own repo. GitHub signs and delivers a legitimate `status` webhook to Shipit for the attacker's repo. `Shipit::WebhooksController#create` validates the signature against the sending repo's own webhook secret — signature verification is scoped to "did the correct repo send this", not "does this SHA belong to that repo's stacks." `StatusHandler#process` then updates **every** `Commit` row across **all** stacks matching that SHA, including the victim's unrelated stack.

Why existing guards don't catch this: `verify_signature`/`GitHubApp#verify_webhook_signature` only prove the payload came from the repository named in the payload — they do not constrain which `Commit` rows the handler is permitted to touch. `ExplicitParameters` validates field types/presence, not cross-tenant scoping. There is no `stacks`-scope or repository check anywhere in `StatusHandler` or `Commit#create_status_from_github!`.

The `review_stacks_enabled`/`provision?` operator-precedence issue in `PullRequest::OpenedHandler` (`repository.review_stacks_enabled && repository.provisioning_behavior_allow_all? || (repository.provisioning_behavior_allow_with_label? && ...) || (...)`, where `&&` binds tighter than `||` so `review_stacks_enabled` only gates the `allow_all` branch) is a real logic bug, but it is not required for this exploit: the victim in this scenario is an existing, already-provisioned regular `Stack`, not a review stack being created. The status-flip mutation across repositories works purely through the unscoped `Commit.where(sha:)` query, independent of review-stack provisioning behavior. [6](#0-5) 

### Impact Explanation
A webhook correctly authenticated for repository A can write a `Status` row and drive `deployable?`/`blocked?`/merge scheduling for a `Commit` belonging to an unrelated stack/repository B, whenever the two repositories share a commit SHA (common with forks, mirrors, or shared upstream history). This is a cross-tenant write — "a payload for one repository mutating another's stack, commit" — and can force a required `release/gate` gate to `success`, unblocking deploys/merges on a stack the attacker does not control, matching the Critical impact category. It is repeatable for every shared SHA and against any stack that happens to share commit history with an attacker-controlled repository.

### Likelihood Explanation
Preconditions: the attacker must own/control a repository tracked by Shipit and be able to set a commit status on a SHA that is also recorded as a `Commit` in a victim stack — realistic for forks of the same upstream, monorepo mirrors, or any repository pair with shared git history. No Shipit secrets, sessions, or GitHub App keys are required; the attacker uses their own repo's legitimate GitHub webhook delivery. Cost is low (one GitHub API call to set a status); the flaw is deterministic and repeatable for any matching SHA.

### Recommendation
Scope the commit status lookup in `StatusHandler#process` to the repository that authenticated the webhook, e.g. join through `stack.repository` and filter `Commit.joins(:stack).where(sha: params.sha, shipit_stacks: { repository_id: repository.id })` (or equivalent using `params.repository.full_name`), so a status can only mutate commits belonging to stacks of the repository that sent it. Separately, fix the `provision?` operator precedence in `PullRequest::OpenedHandler` by parenthesizing `repository.review_stacks_enabled && (...)` around the whole expression.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "a status for a shared SHA does not affect an unrelated stack's commit" do
  shared_sha = "a" * 40

  attacker_repo  = shipit_repositories(:shipit) # repo the attacker's webhook is signed for
  victim_stack   = shipit_stacks(:shipit)        # unrelated stack, review_stacks_enabled: false,
                                                  # required_status: 'release/gate'
  victim_commit  = victim_stack.commits.create!(sha: shared_sha, message: "shared commit")

  before_deployable = victim_commit.deployable?
  before_status     = victim_commit.status.state

  params = Shipit::Webhooks::Handlers::StatusHandler.new(
    Shipit::ExplicitParameters::Parameters.new(
      sha: shared_sha, state: "success", context: "release/gate"
    ), attacker_repo
  )
  params.process

  victim_commit.reload
  # Binding under test: victim_commit.status/deployable? must equal before_* values
  # because attacker_repo never authenticated for victim_stack's repository.
  assert_equal before_status, victim_commit.status.state,
    "status handler mutated a commit belonging to a stack of a different repository"
  assert_equal before_deployable, victim_commit.deployable?
end
```
This test demonstrates the binding `commit.stack.repository == webhook.repository` is not enforced by `Commit.where(sha: params.sha)` in `StatusHandler#process`.

### Citations

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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L227-237)
```ruby
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

**File:** app/models/shipit/commit.rb (L360-386)
```ruby
    private

    def message_parser
      @message_parser ||= CommitMessage.new(message)
    end

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
