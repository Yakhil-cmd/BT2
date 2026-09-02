### Title
`StatusHandler#process` mutates Commit rows via unscoped `Commit.where(sha:)`, affecting archived and review-app stacks identically to active ones - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits solely by `sha`, with no filter on `stack_id`, repository, or stack lifecycle state (`archived?`). Because the query is entirely unscoped, any commit sharing a colliding sha in *any* stack - active, archived, or review-app - gets a `Status` row created and can trigger `stack.schedule_continuous_delivery`, regardless of that stack's archived/active status.

### Finding Description
The broken binding: `Commit.where(sha: params.sha).stack_id == webhook.payload['repository']['full_name']`'s corresponding stack, for **all** stacks matching that sha, is claimed to hold, but it does not - it should instead be scoped to stacks belonging to the repository named in the payload, and independent of stack archival state.

Code path: `StatusHandler#process` runs
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [1](#0-0) 

This query has no `stack_id`/repository predicate at all, and no `stack.active?`/`archived?` filter either. Note the `Handler` base class defines a `stacks` helper scoped to `Repository.from_github_repo_name(repository_name)` [2](#0-1)  but `StatusHandler` never calls it - it queries `Commit` globally instead.

`Commit#create_status_from_github!` calls `add_status`, which calls `stack.schedule_merges` on state transitions and (via the `after_create`/model callbacks path more broadly) `schedule_continuous_delivery` checks `stack.continuous_deployment? && stack.deployable?` before enqueuing `ContinuousDeliveryJob` [3](#0-2)  and [4](#0-3) . Nothing in `add_status` or `create_status_from_github!` checks `stack.archived?` before creating the `Status` row itself - so the vulnerable write (`statuses.replicate_from_github!`) happens unconditionally on any matching `Commit`, active or archived stack alike [5](#0-4) .

Because this is the same root cause as the general "no repository scope" issue - the query is unscoped in every dimension (repository, stack state) - the archived/review-stack angle is not a separate bug requiring a separate fix; it's evidence of the same missing predicate. There is no `verify_signature`, `drop_unhandled_event`, or `ExplicitParameters` schema check that constrains which `Commit` rows are touched; those guards only validate webhook authenticity and payload shape, not scope of the DB write.

### Impact Explanation
An attacker who can make a `sha` collide (e.g. via a repo they control, or naturally via short/duplicate shas across unrelated repos) can, by sending one webhook, mutate `Status` rows on Commits belonging to unrelated stacks - including archived and review-app stacks - and potentially cause `ContinuousDeliveryJob` to fire for those stacks if their `continuous_deployment?`/`deployable?` predicates independently pass. This is a cross-repository write to state the attacker did not authenticate for (Critical category: "a payload for one repository mutating another's stack, commit ... or an unauthorized deploy"). It is repeatable against any repository/stack pair sharing a sha, without any privilege.

### Likelihood Explanation
Requires only that some commit sha collides across the target stack and the attacker's own repo (achievable by pushing to the attacker's own repo/fork, or naturally on short SHA collisions in the wild, though full 40-char collisions require pre-existing shared history/rebasing across the two stacks). No Shipit secret or team membership is needed - only a webhook `POST` reaching the handler. Given how the vulnerable line was already independently identified as unscoped, this holds equally for archived/review stacks since the code makes no distinction.

### Recommendation
Scope the `Commit` lookup in `StatusHandler#process` to the repository derived from the payload (and, ideally, only to stacks that are not archived), e.g. use the `stacks` helper from `Handler` (`stacks.flat_map(&:commits).where(sha: params.sha)` or equivalent join through `Stack` filtered by `repository_id`) instead of the bare `Commit.where(sha:)`.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`):
1. Create two `Stack` fixtures for two different repositories, `stack_a` (active) and `stack_b` (`archived_since` set, i.e. archived, or a `ReviewStack`).
2. Create `Commit` records on both stacks with the identical `sha` value `"deadbeef..."`.
3. Build a status webhook payload for `stack_a`'s repository with that `sha` and `state: "success"`.
4. Call `StatusHandler.call(payload)`.
5. Assert `stack_a`'s commit gains the expected `Status`.
6. Assert `stack_b`'s commit **also** gains a `Status` row (`commit_b.statuses.count` increased) even though `stack_b.archived?` is true - proving the write crossed both repository and stack-lifecycle boundaries.
7. If `stack_b.continuous_deployment?` and `stack_b.deployable?` are stubbed true, assert `ContinuousDeliveryJob` was enqueued for `stack_b`, demonstrating potential unauthorized deploy trigger on an archived/review stack.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
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

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
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
