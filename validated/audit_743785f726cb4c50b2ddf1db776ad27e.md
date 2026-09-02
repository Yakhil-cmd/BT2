This confirms the vulnerability: `PushHandler` and `CheckSuiteHandler` both scope their queries through `stacks` (which is derived from `Repository.from_github_repo_name(repository_name)`), but `StatusHandler#process` uses `Commit.where(sha: params.sha)` with no repository/stack scoping at all. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

### Title
Cross-repository status bleed via unscoped `Commit.where(sha:)` in `StatusHandler#process` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` writes a GitHub `status` webhook to **every** `Commit` row across the entire installation that shares the reported SHA, with no filter on `repository_name`/`stack`, unlike sibling handlers (`PushHandler`, `CheckSuiteHandler`) which correctly scope through the `stacks` helper derived from the payload's `repository.full_name`. Two different repositories/forks can legitimately share an identical commit SHA (git SHAs are content-addressed and forks/mirrors of the same history reuse SHAs), so a `status` event that is validly signed for repo A can flip the CI status of the identical commit recorded under a completely unrelated stack B, including a production-environment stack requiring `ci/jenkins`.

### Finding Description
The broken binding: the code implicitly assumes `commit.sha == params.sha` implies `commit.stack.repository == payload.repository`, but the model only enforces the SHA equality — `Commit.where(sha: params.sha)` [5](#0-4)  has no join or filter on `repository_name`, `github_repo_name`, or `stack_id`. Every matching row across all stacks/tenants gets `commit.create_status_from_github!(params)` called on it [6](#0-5) , which replicates the status and recomputes `status`/`deployable?`/`blocked?` [7](#0-6) [8](#0-7) , and can trigger `stack.schedule_merges` or `ContinuousDeliveryJob` [9](#0-8) [10](#0-9) .

`verify_signature` in `WebhooksController` only validates that the payload was genuinely signed for the *organization owning the reporting repository* [11](#0-10) ; it says nothing about which `Commit` rows the handler is allowed to mutate. The handler base class even exposes a `stacks` helper, scoped by `Repository.from_github_repo_name(repository_name)` [12](#0-11) , which `PushHandler` and `CheckSuiteHandler` both use correctly to constrain their writes to the reporting repository's own stacks — `StatusHandler` alone bypasses this and queries the global `Commit` table directly.

Exploit flow: an attacker forks or otherwise obtains a repository that shares commit history (and therefore identical SHAs) with a victim's production-environment repository (a common occurrence for forks, mirrors, or repos created by rebasing/cherry-picking identical commits). The attacker's own CI system (or any system able to post a `status` webhook that GitHub relays, signed with the secret belonging to the attacker's own org/repo) reports `context: ci/jenkins`, `state: success` for that shared SHA. `verify_signature` passes because the signature is valid for the attacker's own repository/organization. `StatusHandler#process` then finds the row in `Commit` with the matching SHA that belongs to the victim's production stack and applies the success status to it, potentially satisfying `required_statuses` and unblocking `deployable?`/triggering continuous deployment on a stack the attacker never authenticated against.

### Impact Explanation
A payload authenticated for one repository mutates the CI status of a commit belonging to a completely different repository's stack, satisfying the Critical impact category explicitly defined in the rules ("a payload for one repository mutating another's stack, commit, task or team"). Because `deployable?` and `blocked?` are derived directly from status state [8](#0-7) , and status changes drive `stack.schedule_merges` and continuous delivery scheduling [13](#0-12) , this can force an unauthorized deploy or unblock a merge on a production stack the attacker does not control. This is repeatable against any commit SHA that happens to be shared across repositories, and the blast radius spans every stack/tenant on the Shipit instance since the query has no tenant boundary.

### Likelihood Explanation
The attacker needs: (1) a repository (their own, or any repo they can push CI statuses for) whose commit history intersects with a victim's, producing identical SHAs — realistic for forks/mirrors of the same upstream project — and (2) the ability to have a genuinely GitHub-signed `status` event delivered for that repository (e.g., via their own CI integration reporting to their own fork, which GitHub relays as a normal signed webhook). No Shipit secrets, sessions, or privileged roles are required; the attacker only needs control of a repository/webhook-emitting integration for which Shipit's GitHub App/org is configured, which is a standard, low-cost precondition, not a theoretical one.

### Recommendation
Scope `StatusHandler#process` the same way `PushHandler`/`CheckSuiteHandler` do: restrict the `Commit` lookup to commits belonging to `stacks` (i.e., `stacks.flat_map(&:commits).where(sha: params.sha)` or equivalently join through `Stack`/`Repository` filtered by `payload.dig('repository', 'full_name')`) before calling `create_status_from_github!`.

### Proof of Concept
minitest plan (`test/models/webhooks/handlers/status_handler_test.rb` conceptually — not asserting file path since out of scope per rules, but describing the binding to test):
1. Create two stacks, `stack_a` (attacker-associated repo `attacker/repo`) and `stack_b` (victim, production environment, `required_statuses: ['ci/jenkins']`).
2. Create a `Commit` with the same `sha` under both `stack_a` and `stack_b` (simulating shared git history).
3. Assert baseline: `stack_b.commits.find_by(sha: sha).deployable?` == `false` (blocked, pending status).
4. Invoke `Shipit::Webhooks::Handlers::StatusHandler.call('sha' => sha, 'state' => 'success', 'context' => 'ci/jenkins', 'repository' => { 'full_name' => 'attacker/repo' })`.
5. Assert after: `stack_b.commits.find_by(sha: sha).deployable?` == `true` (or `blocked?` flips to `false`), proving a payload scoped to `attacker/repo` mutated `stack_b`'s commit state — violating the invariant "A `ci/jenkins` status affects only the repository that authenticated it."

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** app/models/shipit/commit.rb (L379-387)
```ruby
      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
      new_status
    end
  end
```

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
