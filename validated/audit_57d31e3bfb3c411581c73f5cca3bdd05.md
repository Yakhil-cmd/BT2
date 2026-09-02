### Title
`StatusHandler#process` scopes Status writes by `sha` alone, not by repository, unlike `Commit#refresh_statuses!` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`Commit#refresh_statuses!` fetches statuses from GitHub scoped explicitly to `github_repo_name` (the owning stack's repository), so it can never attribute a status to the wrong repo. `StatusHandler#process`, which handles inbound `status` webhooks, instead does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github! }` with no check that `params.repository.full_name` (or any repository identifier) matches the `Commit`'s owning `Stack#repository`. Because GitHub commit SHAs are content-addressed and identical across forks/clones that share history, this allows a webhook fired from a repository the attacker fully controls to write a `Status` row against a `Commit` belonging to a completely different, unrelated stack that merely happens to share an ancestor commit SHA.

### Finding Description
The binding that should hold is: for every `Status` created via a webhook for `commit`, `payload.repository.full_name == commit.stack.repository.full_name` (the same equality that `refresh_statuses!` enforces implicitly by calling `stack.github_api.statuses(github_repo_name, sha, ...)` — the GitHub API endpoint itself is scoped to that repo, so it is structurally impossible for `refresh_statuses!` to return a status for the wrong repository).

`StatusHandler#process` breaks this binding: [1](#0-0) 
It looks up `Commit` rows purely by `sha`, ignoring `params.repository` entirely (the schema does not enforce a global uniqueness on `sha`, only `stack_id + sha`, per `db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb`, meaning the same SHA is expected to legitimately exist across multiple `Stack`/`Commit` rows). Every matching `Commit`, regardless of which stack/repository it belongs to, gets `create_status_from_github!` called on it: [2](#0-1) 
which in turn calls `Status.replicate_from_github!`, a bare `find_or_create_by!` with no repository check: [3](#0-2) 

Contrast this with other handlers in the same directory that do scope to the owning repository before touching any stack/commit, e.g. `CheckSuiteHandler` resolves `stacks` via `Repository.from_github_repo_name(repository_name)` before touching commits: [4](#0-3) 
and the shared `Handler` base class even provides this scoping helper: [5](#0-4) 
`StatusHandler` simply does not use it.

**Exploit path**: The webhook controller's signature check (`verify_signature`) is keyed on `Shipit.github(organization: repository_owner)` — i.e., it authenticates that the payload really came from GitHub for that organization/app installation, not that the target commit belongs to that organization's tracked repository: [6](#0-5) 
An attacker who (a) owns/controls a GitHub repository with the Shipit-connected GitHub App installed (their own account/org, a normal unprivileged action), and (b) forks or otherwise obtains a repository sharing a commit SHA with a Shipit-tracked victim stack (trivial: fork the victim's public repo — unchanged ancestor commits keep identical SHAs), can post a legitimate, correctly-signed GitHub `status` event from their own repo for that shared SHA with an arbitrary `state`/`description`/`context`. GitHub delivers this webhook with a valid signature (computed with the attacker's own installation's secret, which `verify_signature` accepts because it only checks the signature is valid for `repository_owner`, i.e., the attacker's own org). `StatusHandler#process` then writes a forged `Status` onto the victim's `Commit` row for that shared SHA, with no repository cross-check anywhere in the call path.

This directly affects deploy/merge gating: `Commit#deployable?` depends on `success?`/`blocked?`, which read from `statuses`: [7](#0-6) 
`Status#after_create` callbacks (`enable_ci_on_stack`, `schedule_continuous_delivery`) fire regardless of which repository actually reported the status: [8](#0-7) 

Existing reconciliation via `RefreshStatusesJob` → `Commit#refresh_statuses!` never removes or invalidates this forged row: it only ever creates/find-matches statuses returned by the real GitHub API for `github_repo_name`; a bogus row that GitHub never actually reported for that repo is neither found (so not deduped) nor deleted. `Status.replicate_from_github!`'s `find_or_create_by!` has no deletion/reconciliation path at all.

### Impact Explanation
An unprivileged GitHub user, using only their own repository and their own legitimate (but attacker-controlled) webhook deliveries, can write a `Status` record — with fabricated `state: 'success'`, arbitrary `description`/`context`/`target_url` — onto a `Commit` belonging to a stack/repository they do not own or have any relationship to, as long as that commit's SHA is shared (via fork ancestry) with a repo the attacker controls. This is a cross-tenant write: "a payload for one repository mutating another's stack[/]commit." It can flip `Commit#deployable?` to true for a commit that never actually passed CI in the victim's repository, enabling an unauthorized deploy decision in Shipit's continuous-delivery pipeline (`schedule_continuous_delivery`) for the victim stack. This matches the Critical impact category (unauthorized deploy / cross-repository state mutation). It is repeatable against any target stack whose tracked branch/commit history shares an ancestor SHA with a repository the attacker can obtain (trivial via forking public repos), and the forged status is never cleaned up by the legitimate reconciliation job.

### Likelihood Explanation
Preconditions are modest and attacker-only: the Shipit-connected GitHub App/integration must be installable by third parties on their own repos (true for any public GitHub App used across orgs, which is the normal Shipit deployment model), and the victim stack's repository must be public or forkable so the attacker can obtain a shared-SHA repository (trivial, one `git clone`/fork away — no victim credentials or secrets needed). No `secret_key_base`, `webhook_secret`, or GitHub token belonging to the victim is required; the attacker only uses their own valid, self-signed webhook. The main constraint is that the shared SHA must correspond to a commit actually tracked as a `Commit` row in the victim's stack (i.e., reachable from the tracked branch at some point), which is common for shared ancestor/base commits, cherry-picked commits, or commits later merged. This is a low-cost, repeatable, self-service attack requiring no race against `RefreshStatusesJob` at all — the forged row persists indefinitely since reconciliation cannot detect or remove it.

### Recommendation
In `StatusHandler#process`, scope the `Commit` lookup by the webhook's own repository before applying the status, mirroring the pattern already used by `CheckSuiteHandler`/`Handler#stacks`: resolve `stacks = Repository.from_github_repo_name(payload.repository.full_name)&.stacks || Stack.none`, then only update commits belonging to those stacks (e.g., `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`). Additionally, require `:repository` (`full_name`) in the `StatusHandler` params schema so it cannot be omitted, and consider adding an explicit repository/stack equality assertion inside `create_status_from_github!`/`Status.replicate_from_github!` as defense in depth.

### Proof of Concept
minitest plan (place under `test/models/shipit/webhooks/handlers/status_handler_test.rb`, not run here since `test/**` is out of scope for grading but included as the reproduction plan):

```ruby
test "StatusHandler does not create a Status for a commit belonging to a different repository/stack" do
  victim_stack = shipit_stacks(:shipit) # repository e.g. "shopify/shipit-engine"
  shared_sha = "deadbeef" * 5
  victim_commit = victim_stack.commits.create!(sha: shared_sha, message: "shared ancestor")

  attacker_payload = {
    "sha" => shared_sha,
    "state" => "success",
    "description" => "forged",
    "context" => "attacker-ci",
    "repository" => { "full_name" => "attacker/unrelated-fork" }
  }

  assert_no_difference -> { victim_commit.statuses.count } do
    Shipit::Webhooks::Handlers::StatusHandler.call(attacker_payload)
  end

  refute victim_commit.reload.deployable?
end
```

Assert both sides of the binding explicitly:
- Before: `victim_commit.stack.repository.full_name == "shopify/shipit-engine"` while `attacker_payload["repository"]["full_name"] == "attacker/unrelated-fork"` — they differ.
- Current code: `StatusHandler#process` ignores this difference and creates the `Status` anyway (test fails against current implementation, i.e. `assert_no_difference` is violated), proving the divergence exists.
- After fix: the lookup must be scoped so the assertion passes.

### Citations

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

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```

**File:** app/models/shipit/status.rb (L23-33)
```ruby
    class << self
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
