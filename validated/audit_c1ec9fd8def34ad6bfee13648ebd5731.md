### Title
`StatusHandler#process` matches and mutates `Commit` rows across unrelated Stacks/repositories via unscoped `Commit.where(sha:)` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits solely by `sha`, with no filter on `stack_id`/repository, then calls `commit.create_status_from_github!(params)` on every match. Because SHA-1 commit hashes are frequently shared across unrelated repositories (e.g. one repo forked from another, or an intentionally created identical commit), a valid, correctly-signed webhook for repository A can mutate the status of a `Commit` row that actually belongs to a Stack tracking repository B.

### Finding Description
Binding claimed to hold: `Stack#repository_id` for every `Commit` mutated by one `StatusHandler#process` call should be a single value (i.e. all mutated commits belong to the stack that owns the webhook's `repository.full_name`). This binding is violated.

The handler's `process` method is:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [1](#0-0) 

`Commit.where(sha: params.sha)` is a global, unscoped query across the entire `commits` table — it is not restricted to the repository that sent the webhook. Contrast this with `CheckSuiteHandler#process`, which correctly scopes to the webhook's repository via the base `Handler#stacks` helper before touching commits:
```ruby
def process
  stacks.where(branch: params.check_suite.head_branch).each do |stack|
    stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
  end
end
``` [2](#0-1) 

The base `Handler` class exposes exactly this repository-scoping primitive:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [3](#0-2) 

`StatusHandler` never calls `stacks`/`repository_name` — it is the only status-related handler that skips this scoping.

`WebhooksController#verify_signature` authenticates that the payload really came from GitHub for the claimed `repository_owner`, and `ExplicitParameters` validates the shape of `params.sha`/`params.state`, but neither of these guards constrains which `Commit` rows get matched by that `sha` — they only prove the request is a genuine GitHub status event for *some* repository, not that the mutated `Commit` rows belong to that repository's stacks.

Exploit path: an attacker who owns/controls repository A (a fork of, or independently containing the same commit SHA as, a repository B that has a Shipit `Stack`) sets a commit status (e.g. via the GitHub Status API, GitHub Actions, or any third-party CI hooked to their own repo) on a commit whose SHA also exists as a `Commit` row for B's stack. GitHub delivers a legitimately signed "status" webhook naming repository A. `StatusHandler#process` ignores the payload's repository and updates/creates a `Status` on **every** `Commit` row sharing that SHA, including the one belonging to Stack B. This can flip B's commit status (e.g. to `success`), which feeds into `Commit#add_status`, deploy-readiness checks (`stack.schedule_merges`), and hook emission (`Hook.emit(:deployable_status, ...)`), directly influencing merge/deploy eligibility for a stack the attacker does not control.

### Impact Explanation
An attacker-controlled repository can inject a forged/attacker-chosen CI status (`success`, `failure`, `pending`, `error`) onto a `Commit` belonging to a completely different tenant's `Stack`, as long as any commit SHA is shared between the two repositories (trivially true for forks of the same upstream, which is a common real-world configuration). This can cause `deployable_status` to be marked `success` for a commit in a victim stack, enabling automated merge queues (`stack.schedule_merges`) or deploy gating logic that trusts commit status to proceed incorrectly — this is a cross-tenant mutation of another repository's Stack/Commit state, matching the Critical category ("a payload for one repository mutating another's stack, commit ... or an unauthorized deploy, rollback or merge").

### Likelihood Explanation
The only precondition is that two Shipit-tracked (or Shipit-and-attacker-owned) repositories share at least one commit SHA — a condition that arises naturally from forking and does not require any cryptographic SHA-1 collision. The attacker needs the ability to set a status on their own repository/commit and have GitHub deliver that webhook to the shared Shipit instance, both of which are within the unprivileged capabilities defined for this audit (push to a fork, emit webhooks from a repository they own). No Shipit session, API token, or secret is needed. This is repeatable per shared-SHA commit and does not require guessing any secret.

### Recommendation
Scope `StatusHandler#process` to the webhook's own repository, mirroring `CheckSuiteHandler`, e.g.:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```

### Proof of Concept
```ruby
test "StatusHandler#process only updates commits belonging to the reporting repository's stacks" do
  stack_a = shipit_stacks(:shipit)          # repository A
  stack_b = shipit_stacks(:cyclimse)        # repository B, unrelated repository_id
  shared_sha = "4b825dc642cb6eb9a060e54bf8d69288fbee4904" # shared/forked SHA

  commit_a = stack_a.commits.create!(sha: shared_sha, author: shipit_users(:walrus),
    committer: shipit_users(:walrus), authored_at: Time.now, committed_at: Time.now, message: "shared")
  commit_b = stack_b.commits.create!(sha: shared_sha, author: shipit_users(:walrus),
    committer: shipit_users(:walrus), authored_at: Time.now, committed_at: Time.now, message: "shared")

  payload = { "sha" => shared_sha, "state" => "success", "context" => "ci/attacker",
              "repository" => { "full_name" => stack_a.github_repo_name } }

  Shipit::Webhooks::Handlers::StatusHandler.call(payload)

  distinct_repo_ids = [commit_a.reload, commit_b.reload].select { |c| c.statuses.last }.map { |c| c.stack.repository_id }.uniq
  assert_equal 1, distinct_repo_ids.size # FAILS: both stacks mutated, size is 2
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
