### Title
StatusHandler#process forges negative statuses onto commits in unrelated repositories via unscoped `Commit.where(sha:)`, blocking legitimate merges/deploys - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` looks up commits by SHA alone across the entire `commits` table, with no scoping to the repository that authenticated the webhook (`payload.dig('repository', 'full_name')`). An attacker who owns a repository whose commit history happens to share a SHA with a commit tracked by a victim's Shipit stack (trivially achievable by cherry-picking/pushing the exact same commit into their own repo, since a git SHA is derived only from the commit's content) can send a signed `status` event with `state: failure` or `state: error` from their own repository and have it recorded as a `Status` on the victim's `Commit` row, causing `blocked?`/`deploy_failed?`-driven logic to reject a legitimate deploy/merge.

### Finding Description
The broken binding: `repository_authenticated (payload.dig('repository','full_name'), verified by HMAC signature) == repository_of_mutated_commit (commit.stack.github_repo_name)` is claimed but never enforced — and tracing the code confirms it.

`StatusHandler#process` is:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [1](#0-0) 

This query is global across all stacks/repositories in the Shipit instance — `params.sha` is attacker-controlled and there is no `where(stack_id: ...)` or repository filter. The base `Handler` class does expose a `stacks`/`repository_name` helper scoped from `payload.dig('repository', 'full_name')` [2](#0-1)  but `StatusHandler` does not use it at all — it queries `Commit` directly and unconditionally.

`commit.create_status_from_github!(params)` calls `add_status { statuses.replicate_from_github!(...) }` [3](#0-2) , which persists a new `Status` row with whatever `state` the attacker supplied (`failure`/`error`), recomputes `commit.status`, and — critically — calls `stack.schedule_merges` only on `pending?`/`success?` transitions [4](#0-3) , but the persisted negative status is immediately visible to any subsequent read of `commit.status`, `blocked?`, and `deploy_failed?` for the victim stack. `blocked?` walks `stack.commits.reachable...any?(&:blocking?)` and will see the forged failing status on the shared-SHA commit [5](#0-4) ; `deploy_failed?` reads `stack.deploys.unsuccessful.where(until_commit_id: id)` — that one isn't directly touched, but `deployable?` (`!locked? && (stack.ignore_ci? || (success? && !blocked?))`) [6](#0-5)  is flipped negative, which is exactly the "block a legitimate merge/deploy" impact.

Root cause: same defect as the success-path forgery finding — `StatusHandler` never checks that the commit's owning stack/repository matches the repository that presented a valid HMAC signature for this specific webhook payload. Webhook signature verification (`verify_signature`/`GitHubApp#verify_webhook_signature`) proves the payload was signed by *some* registered app installation for the repository named in `payload['repository']['full_name']`, but it does not (and cannot) prove that no other unrelated repository shares the same commit SHA. Since the SHA is derived purely from tree/parent/commit metadata that the attacker fully controls in their own repo, they can force a shared SHA between their own commit and an existing victim commit (e.g., an unmodified upstream commit that they also have in their fork's history — trivial for any commit that is or was on a public branch the victim's repo pulled from, or via cherry-pick of identical tree+parents+author+committer+timestamps). None of `drop_unhandled_event`, `ExplicitParameters`, `force_github_authentication`, `Repository`/`Stack` validators, or `EnvironmentVariables#permit` address this — those guard unrelated surfaces (event routing, param schema, session/OAuth, model format, env var whitelisting), none of them scope the `Commit` lookup by repository.

### Impact Explanation
A single signed webhook from an attacker-controlled repository writes a `Status` row (state `failure`/`error`) onto a `Commit` belonging to a completely different tenant's stack, without that tenant's repository ever authenticating the request. This directly matches the Critical category "a payload for one repository mutating another's stack, commit, task or team" — here specifically causing an "unauthorized deploy, rollback or merge" **denial**: a queued `MergeRequest`/commit that should pass CI checks is forced into a blocked/failed state, preventing a legitimate merge or deploy from proceeding. This is repeatable against any repository/stack for which the attacker can produce (or already has) a commit with a matching SHA, and is not limited to a single target — any shared-SHA collision across tenants is exploitable the same way.

### Likelihood Explanation
Preconditions: the attacker needs (a) a GitHub repository they control that can emit a signed webhook (any repo with the Shipit GitHub App/webhook installed on it — commonly self-serve for any repo the attacker owns if the GitHub App is installable by any user, or if webhook secrets are per-app rather than per-repo), and (b) a commit SHA collision with a commit tracked in the victim's Shipit stack. SHA collision is not cryptographic — it is achievable by construction: forking/cloning a public upstream repo and pushing the identical commit (same tree, parents, author, committer, timestamps) into their own repository gives byte-identical SHA1, which GitHub accepts. This is a realistic scenario for open-source dependents, shared-fork workflows, or monorepo/subtree situations. No Shipit secrets, sessions, or privileged roles are required — only a normal GitHub webhook delivery. Cost is low and the attack is repeatable at will.

### Recommendation
Scope the `Commit` lookup in `StatusHandler#process` to only commits belonging to stacks whose repository matches `payload.dig('repository', 'full_name')`, mirroring the `stacks`/`repository_name` helper already defined on `Handler`, e.g. `Commit.joins(stack: :repository).where(sha: params.sha, shipit_repositories: { ... matching repository_name ... })`, before calling `create_status_from_github!`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb (conceptual, no live GitHub)
test "a status forged from repo B cannot block a merge queued on stack A sharing a sha" do
  repo_a = shipit_repositories(:shipit) # victim
  repo_b = create_repository(full_name: "attacker/evil-repo") # attacker-owned, unrelated

  stack_a = create_stack(repository: repo_a)
  shared_sha = "a" * 40
  commit = create_commit(stack: stack_a, sha: shared_sha)
  merge_request = create_merge_request(stack: stack_a, merge_commit: commit)

  # sanity: before attack, no blocking status exists
  assert_not commit.reload.blocked?

  payload = {
    'repository' => { 'full_name' => repo_b.full_name }, # attacker's own, correctly signed repo
    'sha' => shared_sha,
    'state' => 'failure',
    'context' => 'ci/forged',
  }

  Shipit::Webhooks::Handlers::StatusHandler.call(payload)

  commit.reload
  assert_equal 'failure', commit.status.state
  assert commit.blocked? # or commit.blocking? per relevant helper
  assert_not commit.deployable?
  # Binding check: repository_authenticated (repo_b.full_name) != commit.stack.github_repo_name (repo_a.full_name)
  assert_not_equal repo_b.full_name, commit.stack.github_repo_name
end
```

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
