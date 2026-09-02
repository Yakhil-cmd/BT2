### Title
Cross-repository status forgery in `StatusHandler#process` corrupts `Commit#deployable?` / `UndeployedCommit#deploy_state` for unrelated stacks - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` resolves the target commit(s) for an incoming GitHub `status` webhook by SHA only, with no check that the SHA belongs to the repository named in the payload. Any commit object that shares a SHA across two different repositories tracked by Shipit (a normal occurrence for forks/shared history, or an intentionally replayed commit with identical content) will have its status/deployability mutated by a webhook that is only valid for a different repository.

### Finding Description
The broken binding, stated as an equality that should hold but does not:

`Status.stack_id (and its commit) == the stack corresponding to payload['repository']['full_name']`

In `StatusHandler#process`:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [1](#0-0) 

This query is **global across all stacks/repositories** — it is not scoped by `stack_id`, `repository`, or any owner/name field from the verified payload. `params` schema only requires `sha`/`state` and does not even carry the repository (the repository is only used earlier, by the controller, for signature verification against an organization) [2](#0-1) .

Each matching `Commit` (regardless of which stack/repo it lives in) then calls `create_status_from_github!`, which creates a `Status` row scoped to `commit.stack_id` (the *commit's own* stack — correct locally) but this stack is selected purely because it happens to share the SHA with the attacker-controlled payload, not because the payload was ever verified against that repository [3](#0-2) . `Status.replicate_from_github!` blindly persists `state` from the payload [4](#0-3) .

Downstream, `Commit#deployable?` recomputes from the newly created status: `!locked? && (stack.ignore_ci? || (success? && !blocked?))` [5](#0-4) , and `UndeployedCommit#deploy_state` surfaces `'allowed'` once `deployable?` is true [6](#0-5) . `Stack#next_commit_to_deploy` selects from `deployable_commits`, so the forged commit becomes eligible for the next continuous-delivery cycle [7](#0-6) .

**Why the controller-level guard doesn't close the gap:** `WebhooksController#verify_signature` verifies that the raw payload bytes were signed by the correct GitHub App/organization secret for `params.dig('repository','owner','login')` [8](#0-7) . This proves the payload genuinely came from GitHub for *some* repository within that organization — it does **not** prove that the SHA in the payload actually belongs to the repository whose commit is being mutated. Signature verification authenticates the *sender/org*, not the *sha-to-repository binding*. Once inside `StatusHandler#process`, that repository information is discarded entirely.

**Attacker path:** the attack surface explicitly allowed by the rules is "emit webhooks from a repository they own." An attacker who owns/controls any repository within an organization Shipit is configured for (e.g., a fork, or any other repo covered by the org's GitHub App installation) can create a commit whose SHA collides with a specific commit in the victim's tracked repository — trivial to achieve deliberately, since Git SHAs are content-addressed: replaying the exact same tree, parent, author/committer, timestamps, and message in a different repository yields the identical SHA (this is exactly what happens naturally between a repo and its fork for shared history, and can be reproduced for new commits via `git commit-tree`/`git filter-branch`-style replay of publicly visible metadata). The attacker then sets that commit's status to `success` via the GitHub Status API on their own repository, causing GitHub to emit a validly-signed `status` webhook containing `sha=<victim_sha>`, `state=success`. `StatusHandler#process` matches `Commit.where(sha: victim_sha)` across all stacks and writes a `success` `Status` onto the victim's `Commit`, flipping `deployable?` to true.

### Impact Explanation
A single forged status write from an attacker-controlled repository causes the victim's `Commit#deployable?` to become true and `UndeployedCommit#deploy_state` to report `'allowed'` to any viewer, and — critically — makes the commit a candidate returned by `Stack#next_commit_to_deploy`. If the victim stack has `continuous_deployment` enabled, this can trigger an unauthorized deploy of a commit that never passed the victim repository's actual CI (e.g., one that is currently `pending` or `failure`). This is a payload for one repository mutating another repository's stack/commit state and coercing an unauthorized deploy, matching the **Critical** category ("a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy"). The write is repeatable against any stack/repository pair that shares (or is made to share, via content replay) a commit SHA, and is not limited to a single victim.

### Likelihood Explanation
Preconditions: (1) the attacker must control/own a repository that is covered by a GitHub App installation/webhook configuration for an organization already known to Shipit (`Shipit.github(organization: repository_owner)` must resolve) — this is a real but not-Shipit-privileged bar, satisfiable by anyone with any repo under that org's App scope; (2) the attacker must produce a commit SHA collision with the victim commit, which is not cryptographically hard but a deterministic content-replay of the victim's public commit metadata into their own repo, or use of naturally shared history (forks). No Shipit secrets, sessions, or GitHub tokens are required. Cost per exploit attempt is low (one API call to set a commit status), and the action is repeatable against multiple victim stacks/commits.

### Recommendation
Scope `StatusHandler#process` (and analogously `check_suite`/other handlers keyed only by `sha`) to the repository named in the verified payload: resolve the target `Stack`/`Repository` from `params.dig('repository', 'full_name')` (or equivalent verified field) and constrain the `Commit` lookup to `Commit.where(sha: params.sha, stack_id: matching_stack.id)` (or join through `Repository`), rejecting/ignoring statuses whose declared repository does not match the commit's own stack repository.

### Proof of Concept
```ruby
# test/models/webhooks/handlers/status_handler_test.rb (conceptual, no live GitHub)
test "status from a foreign repository flips deploy_state of an unrelated stack's commit" do
  victim_stack  = shipit_stacks(:shipit)          # tracks victim/repo
  victim_commit = shipit_commits(:first)           # sha shared/forged, currently pending/failure
  victim_commit.statuses.destroy_all
  victim_commit.statuses.create!(stack_id: victim_stack.id, state: 'pending')

  undeployed = Shipit::UndeployedCommit.new(victim_commit, index: 0)
  assert_equal 'pending', undeployed.deploy_state(true) # baseline: NOT allowed

  # Forged payload: repository field does not match victim_stack's repo,
  # only the sha matches (simulating attacker-owned repo emitting genuinely-signed webhook)
  forged_params = ActionController::Parameters.new(
    sha: victim_commit.sha,
    state: 'success',
    context: 'ci/attacker',
    repository: { full_name: 'attacker/unrelated-repo' }
  )

  Shipit::Webhooks::Handlers::StatusHandler.new(forged_params, event: 'status').call

  victim_commit.reload
  undeployed = Shipit::UndeployedCommit.new(victim_commit, index: 0)
  assert_equal 'allowed', undeployed.deploy_state(true) # BUG: now deployable despite foreign repo

  assert_includes victim_stack.next_commit_to_deploy&.deployable_commits.to_a, victim_commit
end
```
Both sides of the binding equality (`Status.stack_id` chosen == the repository actually authenticated by the payload) should be asserted: before the fix, the test shows `deploy_state` transitioning to `'allowed'` purely because of a foreign-repository payload with a matching SHA, with no verification that `forged_params[:repository][:full_name]` equals the victim stack's repository.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L6-18)
```ruby
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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/status.rb (L24-33)
```ruby
      def replicate_from_github!(stack_id, github_status)
        find_or_create_by!(
          stack_id:,
          state: github_status.state,
          description: github_status.description,
          target_url: github_status.target_url,
          context: github_status.context,
          created_at: github_status.created_at
        )
      end
```

**File:** app/models/shipit/undeployed_commit.rb (L18-19)
```ruby
    def deploy_state(bypass_safeties = false)
      state = deployable? ? 'allowed' : status.state
```

**File:** app/models/shipit/stack.rb (L235-243)
```ruby
    def next_commit_to_deploy
      commits_to_deploy = commits.order(id: :asc).newer_than(last_deployed_commit).reachable.preload(:statuses)
      if maximum_commits_per_deploy
        commits_with_max_applied = commits_to_deploy.limit(maximum_commits_per_deploy)
        deployable_commits(commits_with_max_applied) || deployable_commits(commits_to_deploy)
      else
        deployable_commits(commits_to_deploy)
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
