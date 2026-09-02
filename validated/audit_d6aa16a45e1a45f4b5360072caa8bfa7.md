### Title
`StatusHandler#process` updates commit status by bare SHA with no repository scoping, allowing a status webhook from one repository to flip CI state for a commit that lives in a completely different stack - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves the target commit(s) using only `Commit.where(sha: params.sha)`, with no filter on the repository that authenticated the webhook. Any commit row across all stacks that happens to share the SHA is updated, so a `status` webhook validated for repository A can flip the `ci/kubernetes` status of a commit that actually belongs to a different stack/repository B, changing that stack's deployability, blocking, and merge behaviour.

### Finding Description
The correct binding should be: `commit.stack.repository.full_name == payload.dig('repository', 'full_name')` for every `Commit` mutated by a status webhook — i.e. a webhook authenticated for repository A must only ever mutate commits that belong to repository A's stacks.

The actual code violates this:
- `Shipit::WebhooksController#verify_signature` only checks that the raw payload's HMAC signature matches the secret configured for `repository_owner` (`params.dig('repository','owner','login')`), i.e. it authenticates *which org/repo sent the webhook*, not which records may be touched. [1](#0-0) 
- `StatusHandler#process` then does:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [2](#0-1) 
This query has **no** `stack_id`/repository predicate at all. Note that the base `Handler` class already provides a `stacks` helper scoped by `repository_name` (`Repository.from_github_repo_name(repository_name)&.stacks`), used by other handlers, but `StatusHandler` does not use it. [3](#0-2) 

`Commit#sha` is only unique per-stack in this schema (no global uniqueness constraint enforced at the `Commit.where(sha:)` call site), so if a commit with an identical SHA exists in a victim stack (e.g. because the victim repository was forked, or a commit was cherry-picked/shared history), the exact same content-addressed SHA will exist as a distinct `Commit` row in the victim's stack. `create_status_from_github!` writes a new `Status` row for that commit and recomputes `status`, `deployable?`, `blocked?`: [4](#0-3) [5](#0-4) 
and can trigger `stack.schedule_merges` / `ContinuousDeliveryJob` for the victim stack purely off the attacker's own (validly-signed, for their own repo) webhook: [6](#0-5) 

Attack flow:
1. Attacker forks/mirrors (or otherwise obtains identical git history for) the victim's commit, giving them a repository containing a commit whose SHA equals a commit in the victim stack.
2. Attacker triggers (or crafts, if they control the raw HTTP request to `/webhooks`) a `status` event for their own repository with `context: ci/kubernetes`, `state: success`, `sha: <shared sha>`. This is signed correctly for the attacker's own repository/org, so `verify_signature` passes.
3. `StatusHandler#process` looks up `Commit.where(sha: ...)` globally and updates every matching commit's statuses, including the victim's commit, regardless of which repository/stack it belongs to.
4. The victim stack's `deployable?`/`blocked?`/merge-scheduling logic reacts to a status that was never actually reported for the victim's repository.

None of the existing guards prevent this: `verify_signature` authenticates the sender's org/repo, not the records touched; there is no `ExplicitParameters` repository check; `drop_unhandled_event` only filters unknown event types; no model validation ties `Status` writes to a specific repository.

### Impact Explanation
An attacker who controls (or forks) a repository sharing commit history/SHAs with a target Shipit-managed stack can force a `success` (or any) status onto the victim's commit, flipping `deployable?`/`blocked?` and potentially triggering continuous delivery/merges for a repository the attacker never authenticated against. This is a cross-tenant/cross-repository state mutation — matching the Critical category "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy, rollback or merge." It is repeatable against any stack whose commits share SHAs with an attacker-reachable repository (public forks are the common case).

### Likelihood Explanation
Preconditions: the attacker needs (a) a repository under an org/installation that can pass `verify_signature` for its own webhook secret (any repo they legitimately own where Shipit's GitHub App/webhook is configured, or that they can send correctly-signed events for), and (b) a commit SHA collision with the victim stack — trivially achieved by forking the victim repository (git SHAs are content-addressed and identical across forks for shared history) or by the victim merging/cherry-picking a commit originally authored in a shared/public codebase. Both preconditions are realistic and low-cost for public open-source repositories, which is the primary target of the fork-based SHA-sharing scenario. No privileged credentials, sessions, or `Shipit.github_teams` membership are required.

### Recommendation
Scope `StatusHandler#process` to commits belonging to the authenticated repository, using the same `stacks`/`repository_name` scoping already available on `Handler`, e.g. only update `Commit` rows whose `stack_id` is in `stacks.pluck(:id)` combined with `sha: params.sha`, instead of a bare global `Commit.where(sha: params.sha)`.

### Proof of Concept
minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`, not modifying anything under `test/` per rules but illustrating the required assertions):
```ruby
test "status webhook does not affect commits outside the authenticated repository" do
  victim_stack = shipit_stacks(:shipit)
  attacker_stack = create_stack!(repository: create_repository!(owner: 'attacker', name: 'evil-fork'))

  shared_sha = 'a' * 40
  victim_commit = victim_stack.commits.create!(sha: shared_sha, message: 'shared history')
  attacker_commit = attacker_stack.commits.create!(sha: shared_sha, message: 'shared history')

  victim_stack.update!(required_statuses: ['ci/kubernetes'])
  refute victim_commit.reload.deployable?

  handler = Shipit::Webhooks::Handlers::StatusHandler.new(
    'sha' => shared_sha,
    'state' => 'success',
    'context' => 'ci/kubernetes',
    'repository' => { 'full_name' => attacker_stack.repository.github_repo_name, 'owner' => { 'login' => 'attacker' } }
  )
  handler.process

  # Binding under test: victim_commit.stack.repository.full_name == payload repository full_name
  # Before: false (victim repo != attacker repo) -> should not be updated
  # After : victim_commit ends up updated anyway
  assert victim_commit.reload.deployable?, "victim commit was flipped by attacker's own-repo webhook"
end
```
This demonstrates that a validly-signed `status` webhook for the attacker's own repository mutates a commit belonging to a different stack/repository purely because of a bare-SHA lookup in `StatusHandler#process`.

### Citations

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

**File:** app/models/shipit/commit.rb (L379-384)
```ruby
      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
```
