### Title
Cross-repository commit-status forgery bypasses `Stack#deployable?` via unscoped `sha` lookup - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves the target commit(s) for an incoming GitHub `status` webhook using only `Commit.where(sha: params.sha)`, with no check that the webhook's originating repository matches the repository of the stack that owns the commit. Since git commit SHAs are content-addressed and repo-agnostic, an attacker who controls any repository hooked into Shipit can reproduce an identical commit object (same tree, parents, author/committer, message) that exists in a victim stack, post a `success` status for that SHA from their own repo, and have Shipit apply that forged status to the victim's commit, flipping `Commit#deployable?` / `Stack#deployment_checks_passed?` to `true`.

### Finding Description
The broken binding: `commit.create_status_from_github!(payload)` should only be invoked when `payload.repository.full_name == commit.stack.repository.full_name`, but the actual code does not evaluate `payload.repository` at all.

`app/models/shipit/webhooks/handlers/status_handler.rb`: [1](#0-0) 

The `params` schema only requires `sha`, `state`, and optional `description`/`target_url`/`context`/`created_at`/`branches` — it never requires or reads `repository`. `process` then does:
```
Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }
```
This is a global, cross-stack lookup keyed solely by `sha`. `create_status_from_github!` calls `statuses.replicate_from_github!(stack_id, github_status)` and triggers `add_status`, which recomputes `Commit#status` via `Status::Group.compact` and, if the simple state flips, calls `stack.schedule_merges` / potentially cascades to `schedule_continuous_delivery`. [2](#0-1) [3](#0-2) 

`Stack#deployable?` and `Commit#deployable?` are derived from this same aggregate status/check-run state: [4](#0-3) [5](#0-4) 

Exploit flow:
1. Attacker registers/owns a repository (repo A) that is a legitimately tracked Shipit stack (or any repo Shipit is subscribed to), so they can send real, properly signed GitHub `status` webhooks for repo A.
2. Attacker inspects the victim's stack (repo B, e.g. via the public GitHub history) and identifies the commit SHA currently gating `deployment_checks_passed?` (a failing/pending status).
3. Because git commit objects are content-addressed (hash of tree, parents, author, committer, timestamps, message) and independent of which repository stores them, the attacker constructs/pushes an object with an identical SHA into repo A (e.g., via `git fast-import`/`git hash-object` + push of a matching commit object), without needing any relationship to repo B.
4. Attacker calls the GitHub Statuses API on repo A for that SHA with `state: "success"`. GitHub emits a legitimately signed `status` webhook to Shipit's `POST /webhooks` naming repo A.
5. `StatusHandler#process` ignores the webhook's repository and updates every `Commit` row across the whole database matching that `sha` — including the victim's commit in repo B's stack.
6. `Commit#status` recomputes to success, `Commit#deployable?` becomes true, and `Stack#deployment_checks_passed?` / `Stack#deployable?` on the victim stack flip to `true`, removing the `refute_predicate @stack, :deployable?` guard in `trigger_continuous_delivery`, allowing `trigger_deploy` → `Command#start` to run against the victim host.

No existing guard intercepts this: `verify_signature`/`GitHubApp#verify_webhook_signature` only proves the webhook came from *some* GitHub repository configured with a matching secret — it does not bind the payload's `repository` to the `commit`/`stack` being mutated; there is no `require_permission!` or stack-scoping check inside `StatusHandler`.

### Impact Explanation
An attacker with no privileges on the victim's repository or Shipit instance can forge a passing CI status for an arbitrary victim stack's gating commit purely by controlling an unrelated repository that Shipit also tracks. This directly flips `Stack#deployable?`, bypassing the deploy gate and enabling an unauthorized deploy (`trigger_deploy` → `Command#start`) — matching the "unauthorized deploy" / "payload for one repository mutating another's stack" Critical impact category. The attack is repeatable against any stack whose gating commit SHA the attacker can reproduce, and is not limited to a single tenant — any multi-tenant Shipit instance is affected wherever the attacker also has (or can obtain) any tracked repository.

### Likelihood Explanation
Preconditions: the attacker needs (a) a repository already tracked by the target Shipit instance (this can be their own, trivially added if self-service repo registration is allowed, or any repo Shipit already watches), and (b) the ability to reproduce a commit object with an identical SHA to the victim's gating commit — achievable exactly by copying the victim's public commit's raw content (tree, parents, author/committer identities and timestamps, message) since GitHub exposes this via the API/git protocol for public repos. No secrets, sessions, or elevated GitHub permissions are required. Cost is low: standard `git` tooling to fashion the commit object, plus one authenticated GitHub Statuses API call on a repo the attacker controls.

### Recommendation
In `StatusHandler#process` (and the analogous check-run handler), require and validate the payload's `repository.full_name` against `commit.stack.repository.full_name` (or restrict the `Commit` lookup with `.where(stack: Stack.where(repository: matching_repo))`) before calling `create_status_from_github!`, rejecting/skipping any status whose repository does not match the commit's owning stack.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`):
1. Create `stack_victim` for `repository: "victim/repo"` and a `commit` on it with a known `sha`, plus an existing failing `Status` so `stack_victim.deployable?` is `false` (assert this first: `refute stack_victim.reload.deployable?`).
2. Create an unrelated `stack_attacker` for `repository: "attacker/repo"`.
3. Build a `status` webhook payload naming `attacker/repo` but with `sha` equal to the victim commit's sha and `state: "success"`.
4. Invoke `Shipit::Webhooks::Handlers::StatusHandler.new(...).process` (or POST through the webhooks pipeline) with that payload.
5. Assert the equality that should have held but didn't: `payload.repository.full_name == commit.stack.repository.full_name` is `false` yet the status was still applied — verify via `commit.reload.status.success?` is `true` and `stack_victim.reload.deployable?` is `true`, proving the cross-repository bypass.

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

**File:** app/models/shipit/commit.rb (L304-306)
```ruby
    def status
      @status ||= Status::Group.compact(self, statuses_and_check_runs)
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
