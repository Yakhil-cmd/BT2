### Title
`StatusHandler#process` mutates commits across all stacks/repositories sharing a SHA, ignoring both branch and repository scoping - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github! }` with no scoping to the webhook's originating repository or branch, even though the base `Handler` class provides a repository-scoped `stacks` helper and the params schema accepts (but never uses) `branches`. Any attacker who can get a legitimate, correctly-signed status webhook delivered for a repository/org they control (e.g. their own fork, where they know their own configured `webhook_secret`) can write status records onto commits belonging to any other stack/repository in the same Shipit instance whose commits happen to share that SHA.

### Finding Description
Binding claimed vs. enforced: the code should enforce `commit.stack.repository == payload.repository && commit.stack.branch ∈ params.branches.map(name)`, but it enforces neither.

```ruby
# app/models/shipit/webhooks/handlers/status_handler.rb
params do
  requires :sha, String
  requires :state, String
  ...
  accepts :branches, Array do
    requires :name, String
  end
end

def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```

`Handler` (the base class) already exposes a repository-scoped accessor:
```ruby
# app/models/shipit/webhooks/handlers/handler.rb
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end
```
`StatusHandler` never calls `stacks`; it queries the global `Commit` table by `sha` alone. `verify_signature` (`app/controllers/shipit/webhooks_controller.rb`) only checks that the webhook payload was signed with the secret configured for `repository_owner` taken from the payload itself - it proves the request came from a GitHub org/repo the attacker controls (or whose secret they know), not that the `sha` in the payload belongs to that repository. Because `verify_signature` is per-organization, an attacker who owns/administers any repository tracked by Shipit (their own fork, their own org) can trigger a fully-signed `status` webhook naming any `sha` value they choose, including a SHA that is only actually present on a completely different stack/repository (e.g., a shared upstream commit history via fork, or any coincidental cross-repo SHA reuse). `create_status_from_github!` (`app/models/shipit/commit.rb`) will then write a `Status` for that foreign commit, calling `enable_ci_on_stack`, `schedule_continuous_delivery`, etc. (`app/models/shipit/status.rb`), which can trigger continuous-deployment merges/deploys on a stack the attacker never owns.

Existing guards do not stop this:
- `verify_signature` validates payload authenticity for the attacker's own org, not sha ownership.
- `drop_unhandled_event` only filters by event type.
- `ExplicitParameters` schema accepts `branches` syntactically but the handler body never reads `params.branches`.
- No model validation ties `Commit#sha` uniqueness or ownership to a single `Stack`/`Repository` (the `commits` table allows the same sha to exist under many different `stack_id`s, e.g. via forks/branches/legitimate cross-stack cases like PR/review stacks).

### Impact Explanation
Any repository or stack whose commit history shares a SHA with a commit the attacker can name in a self-signed webhook gets a forged `Status` created for them, potentially flipping `deployable?`/`state` and triggering `ProcessMergeRequestsJob`/continuous deployment (`Status#schedule_continuous_delivery`, `Status#enable_ci_on_stack`). This is a payload for one repository (or one branch's stack) mutating another repository's/stack's commit and status state - matching the Critical category "a payload for one repository mutating another's stack, commit, task or team." The attack is repeatable against any sha that exists in more than one stack's `commits` table (which is a realistic scenario for forks, mirrors, or multiple stacks tracking different branches of the same repo, as described in the question) without requiring any Shipit credentials beyond control of one's own already-onboarded repository/org.

### Likelihood Explanation
Preconditions: the attacker's own repository/org must already be configured in Shipit (so a valid `webhook_secret` exists for `verify_signature` to pass) - this is available to "any GitHub user who can push to a fork" only if that fork/org is itself connected to the Shipit instance; if not, they cannot produce a valid signature and the attack does not work through the public `POST /webhooks` endpoint alone. Given that precondition, exploitation is trivial and free: craft a JSON body with an existing/shared `sha` and any `state`, sign it with the known secret, POST it. No SHA-1 collision is actually required to reach cross-branch/cross-stack impact if the attacker's own onboarded repository already shares commit SHAs with another tracked stack (e.g., via fork ancestry) - the `branches` field being ignored is sufficient by itself once repository scoping is also absent.

### Recommendation
In `StatusHandler#process`, scope the lookup to the requesting repository using the existing `stacks` helper (`Commit.where(sha: params.sha, stack_id: stacks.select(:id))`), and additionally filter by `params.branches` when present, matching `commit.stack.branch` against the named branches before calling `create_status_from_github!`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "process only updates commits belonging to the webhook's repository/branch" do
  repo = shipit_repositories(:shipit)
  master_stack = shipit_stacks(:shipit) # branch: master
  release_stack = Shipit::Stack.create!(repository: repo, environment: 'release-env', branch: 'release')

  shared_sha = 'deadbeef' * 5
  master_commit = master_stack.commits.create!(sha: shared_sha, message: 'm', author: shipit_users(:walrus), committer: shipit_users(:walrus), authored_at: Time.now, committed_at: Time.now)
  release_commit = release_stack.commits.create!(sha: shared_sha, message: 'r', author: shipit_users(:walrus), committer: shipit_users(:walrus), authored_at: Time.now, committed_at: Time.now)

  payload = {
    'repository' => { 'full_name' => repo.github_repo_name },
    'sha' => shared_sha,
    'state' => 'success',
    'branches' => [{ 'name' => 'master' }]
  }

  Shipit::Webhooks::Handlers::StatusHandler.call(payload)

  assert master_commit.reload.statuses.exists?, "expected the named-branch stack's commit to get the status"
  assert release_commit.reload.statuses.exists?,
    "BUG: the release-branch stack's commit was also updated even though the webhook named only 'master'"
end
```
This demonstrates that `params.branches` naming only `master` still results in `release_commit` (a different stack, different branch) receiving the forged status, confirming the broken binding between the declared `branches` parameter and the actual mutation scope.