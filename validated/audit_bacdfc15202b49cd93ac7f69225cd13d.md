### Title
`StatusHandler#process` matches commits by `sha` alone with no `stacks`/repository or `branches` scoping, letting a status webhook from one repository mutate a commit tracked by an unrelated stack - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` without ever calling the `stacks` helper (which scopes by `payload.dig('repository', 'full_name')`) and without checking `params.branches` at all. [1](#0-0)  Every other handler that touches per-repository state (`PushHandler`, `CheckSuiteHandler`) explicitly filters through `stacks.where(branch:)` before touching a commit; `StatusHandler` is the outlier that skips this filter entirely. [2](#0-1) [3](#0-2) 

### Finding Description
The binding that should hold is: `payload.repository.full_name (webhook's claimed repository) == commit.stack.repository.full_name (repository owning the mutated commit)`, and additionally `params.branches[].name == commit.stack.branch`. Neither is enforced.

`Handler` exposes a `stacks` helper that resolves `Repository.from_github_repo_name(repository_name)&.stacks` from the webhook payload's `repository.full_name`. [4](#0-3)  `PushHandler` and `CheckSuiteHandler` both use this scope to restrict which stacks/commits they touch. [2](#0-1) [3](#0-2)  `StatusHandler`, however, declares `branches` in its parameter schema but never reads it in `process`, and queries `Commit` globally by `sha` with no `stacks`/repository scope: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`. [5](#0-4) 

Since `Commit#sha` has no uniqueness constraint scoped per repository visible in the model (`Commit` belongs to `:stack` with no repository-level sha uniqueness enforced), any commit across the entire Shipit installation sharing the same `sha` as the one referenced by the webhook will receive a new `Status` record and go through `create_status_from_github!`, which updates the commit's CI/deploy-blocking state. [6](#0-5) [7](#0-6) 

Attack precondition: the attacker must control (own, as a legitimate GitHub repository/stack registered in Shipit) a repository whose GitHub organization's webhook secret is configured in this Shipit instance, so that `verify_webhook_signature` for a genuine GitHub-originated status event passes. Given that, the attacker can produce a real GitHub commit whose SHA-1 collides with a victim commit's SHA-1 - which is trivially achievable when a commit is shared between repositories (forks, mirrors, cherry-picked/rebased shared history, vendored upstream commits, etc., which is common) rather than requiring a SHA-1 hash break. The attacker then triggers (or manually crafts, since content/sha is fully under their control for their own commit) a `status` event naming their own branch (`branches: [{name: 'attacker-branch'}]`) and repository, with an arbitrary `state`/`description`. Shipit's `StatusHandler` matches this against every `Commit` row with that `sha`, including the victim's commit tracked on the victim stack's `branch` (e.g. `master`) in an entirely different repository, and creates/mutates that `Status`.

This bypasses `verify_signature`/`GitHubApp#verify_webhook_signature` because those only authenticate that the payload really came from GitHub for the *attacker's own* organization - they say nothing about which `Commit` row in Shipit's database the handler is allowed to touch. The `ExplicitParameters` schema for `StatusHandler` only validates shape (`sha`, `state`, optional `branches`), not that `branches` matches the target stack's `branch`, and there is no model-level guard preventing cross-stack sha collisions from being treated as the "same" commit.

### Impact Explanation
A `Status` record is written against a commit belonging to a stack/repository the attacker does not own, using state/branch/description data the attacker fully controls, with no cross-check that the claimed branch or repository matches the victim stack. This mutates a victim's commit CI state (`Commit#state`, `deployable_status`/`commit_status` hooks fire, `enable_ci_on_stack`, `schedule_continuous_delivery`) purely from a webhook whose `repository`/`branches` fields never had to correspond to the victim stack at all - matching the Critical category "a payload for one repository mutating another's stack, commit". The impact is repeatable against any commit sha the attacker can reproduce in a repository they control, and scales across every stack in the Shipit install sharing that sha, not just one target.

### Likelihood Explanation
Requires the attacker to control a legitimate, Shipit-registered repository under a GitHub organization whose webhook secret is already configured in this Shipit instance (a realistic bar for any Shipit multi-tenant deployment where many orgs/teams share one install). It further requires a `sha` collision with a victim commit, which does not require breaking SHA-1 - it only requires the same commit object (same tree/parent/message/timestamps) to exist in both the attacker's repository and the victim's tracked stack, a common occurrence with forks/mirrors/shared history/vendored commits. No Shipit session, API token, or GitHub secret theft is needed beyond the attacker's own legitimate webhook credentials for their own repository.

### Recommendation
In `StatusHandler#process`, scope the commit lookup through the `stacks` helper (as `PushHandler`/`CheckSuiteHandler` do) filtered by `payload.dig('repository', 'full_name')`, and additionally verify `params.branches` (when present) intersects the target commit's `stack.branch` before calling `create_status_from_github!`. Reject/ignore statuses whose repository or branch does not match the stack owning the candidate commit.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "cross-repository status does not mutate a commit tracked on an unrelated stack/branch" do
  victim_stack = shipit_stacks(:shipit) # tracked on branch "master", repo shipit-engine/shipit-engine
  victim_commit = victim_stack.commits.create!(sha: "deadbeef" * 5, branch: "master", ...)

  payload = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'branches' => [{ 'name' => 'attacker-branch' }],
    'repository' => { 'full_name' => 'attacker/unrelated-repo' }
  }

  assert_no_difference -> { victim_commit.statuses.count } do
    Shipit::Webhooks::Handlers::StatusHandler.call(payload)
  end
  # Currently FAILS: a Status is created for victim_commit even though
  # payload.repository != victim_stack's repository and
  # payload.branches != victim_stack.branch, proving the binding
  # "branch/repo reported in webhook == branch/repo tracked by the mutated commit's stack"
  # is not enforced by StatusHandler#process.
end
```

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L7-24)
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

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
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

**File:** app/models/shipit/commit.rb (L11-16)
```ruby
    belongs_to :stack
    has_many :statuses, -> { order(created_at: :desc) }, dependent: :destroy, inverse_of: :commit
    has_many :check_runs, -> { order(created_at: :desc) }, dependent: :destroy, inverse_of: :commit
    has_many :commit_deployments, dependent: :destroy
    has_many :release_statuses, dependent: :destroy
    belongs_to :merge_request, inverse_of: :merge_commit, optional: true
```

**File:** app/models/shipit/status.rb (L11-19)
```ruby
    belongs_to :stack, required: true
    belongs_to :commit, required: true

    deferred_touch commit: :updated_at

    validates :state, inclusion: { in: STATES, allow_blank: true }, presence: true

    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```
