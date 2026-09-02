### Title
`StatusHandler#process` writes GitHub statuses by bare SHA with no repository scoping, letting a status from one repository flip a commit's required-context state for a different stack, feeding `continuous_deployment` auto-ship/auto-block - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` loads commits with `Commit.where(sha: params.sha)` and calls `create_status_from_github!` on every match, without ever checking that the incoming webhook's `payload['repository']['full_name']` matches the `stack`/`repository` that owns each matched `Commit` row. Every other handler in the engine (`PushHandler`, `CheckSuiteHandler`, pull-request handlers) resolves work through the base `Handler#stacks` helper, which filters by `Repository.from_github_repo_name(repository_name)`; `StatusHandler` is the exception. Because `sha` is not globally unique across repositories/stacks in this schema, a `status` event carrying a colliding SHA can mutate a `Commit`/`Status` row that belongs to an unrelated stack, and if that victim stack has `continuous_deployment` enabled, the mutated status can trigger or block `ContinuousDeliveryJob`.

### Finding Description
The broken binding: the code implicitly assumes `commit.stack.repository.full_name == payload['repository']['full_name']` for every `Commit` matched by `params.sha`, but never asserts it.

Path:
- `Shipit::WebhooksController#create` dispatches the raw payload to `Handler.call` for the `status` event type, invoking `StatusHandler#process`: [1](#0-0) .
- `StatusHandler#process` does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — this is a bare, cross-tenant SQL lookup keyed only on `sha`, with no repository/stack filter: [1](#0-0) .
- Contrast with the base `Handler` class, which provides a `stacks` helper explicitly scoped by `Repository.from_github_repo_name(repository_name)` (`repository_name` read from `payload.dig('repository', 'full_name')`) for handlers that use it: [2](#0-1) . `StatusHandler` never calls `stacks` — it bypasses this scoping entirely.
- `Commit#create_status_from_github!` records the status and calls `add_status`, which recomputes `status`, and — critically — calls `stack.schedule_merges` when the new status becomes `pending?` or `success?`: [3](#0-2) [4](#0-3) .
- Separately, `Commit#schedule_continuous_delivery` (fired `after_commit` on creation, and reachable again any time `deployable?`/status state flips downstream logic re-evaluates) checks `deployable? && stack.continuous_deployment? && stack.deployable?` before enqueuing `ContinuousDeliveryJob`: [5](#0-4) . `deployable?` itself is driven by `success?`/`blocked?`, both derived from the `status` that `StatusHandler` just mutated: [6](#0-5) .

Exploit flow: an attacker who controls (or whose fork shares commit history/SHAs with) a repository wired into Shipit's webhook pipeline sends (or gets GitHub to send, e.g. via their own CI reporting a `status`) a `status` event with `context: ci/lint`, `state: failure`, and a `sha` that also exists as a `Commit` row in a victim stack (e.g., shared monorepo history, forked repository, or any scenario producing identical content-addressed SHAs across two repositories tracked by different Shipit stacks). `StatusHandler` matches the victim's `Commit` row purely by `sha` and writes the attacker-controlled `failure` status onto it, flipping the victim stack's `deployable?`/`blocked?` state and its `continuous_deployment` auto-ship/auto-block decision — despite the request never having been authenticated for, or originating from, the victim's repository.

Existing guards do not catch this: `verify_signature`/webhook signature validation only proves the payload came from a repository configured with the shared webhook secret — it says nothing about which `Commit`/stack the `sha` inside the payload should touch. The `ExplicitParameters` schema only validates types (`sha`, `state`, `context` are strings) and does not enforce repository ownership. `drop_unhandled_event` and `force_github_authentication` are irrelevant to this internal model-level write. No `Repository` or `Stack` validator constrains cross-stack SHA reuse. This confirms the invariant "a `ci/lint` status affects only the repository that authenticated it" is violated at the code level, in contrast to how `Handler#stacks` is designed to enforce it for other handlers.

### Impact Explanation
The write lands on a `Commit`/`Status` record and, transitively, on `Stack#schedule_merges` and `ContinuousDeliveryJob` decisioning, for a repository/stack that never sent or authenticated the request. On a victim stack with `continuous_deployment` enabled, forcing a commit's `ci/lint` context to `failure` can block an otherwise-green deploy (denial of legitimate deploys/rollout), and conversely forcing it to `success` on a previously failing/pending commit can make `deployable?` true and drive `ContinuousDeliveryJob` to ship attacker-influenced state. This matches the "Critical" category in the rules: a payload for one repository mutating another's stack/commit, resulting in an unauthorized deploy or block of a deploy. Blast radius spans any stack whose commits share a SHA space with an attacker-reachable repository (multi-repo/monorepo/fork setups are the realistic trigger).

### Likelihood Explanation
Preconditions: (1) the victim stack must have `continuous_deployment` enabled and (2) a `Commit` sha collision/overlap must exist between the attacker's reachable repository and the victim stack (e.g., shared git history via fork, subtree, or mirrored repo) — this is the main feasibility constraint, since arbitrary unrelated repositories won't normally share commit SHAs. Given that constraint is met, the attacker's cost is a single unauthenticated-content `status` webhook (or one triggered via their own CI/GitHub Actions) with no privileged Shipit credentials, and the action is fully repeatable/scriptable against any SHA overlap they can find or create.

### Recommendation
Scope `StatusHandler#process` the same way other handlers are scoped: resolve the affected stacks/commits via `Repository.from_github_repo_name(repository_name)` (i.e., use/extend the base `Handler#stacks` helper) and only update `Commit` rows whose `stack.repository` matches the authenticated payload's repository, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` instead of the bare `Commit.where(sha: params.sha)`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "status webhook does not mutate a commit belonging to a different repository's stack" do
  victim_stack = shipit_stacks(:shipit)
  victim_stack.update!(continuous_deployment: true)
  victim_commit = victim_stack.commits.create!(sha: "a" * 40, message: "victim commit")

  attacker_repo_payload = {
    "sha" => victim_commit.sha,
    "state" => "failure",
    "context" => "ci/lint",
    "repository" => { "full_name" => "attacker/unrelated-repo" }, # not victim_stack's repository
  }

  assert_no_difference -> { victim_commit.statuses.count } do
    Shipit::Webhooks::Handlers::StatusHandler.call(attacker_repo_payload)
  end

  victim_commit.reload
  refute_equal "failure", victim_commit.status.state
end
```
Currently this assertion fails: `StatusHandler#process` matches `victim_commit` purely by `sha` and calls `create_status_from_github!`, creating a `failure` status and changing `victim_commit.status.state`, even though `attacker_repo_payload["repository"]["full_name"]` does not correspond to `victim_stack`'s repository — demonstrating the cross-repository write.

### Citations

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

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
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
