## Answer

The vulnerability is confirmed. `StatusHandler#process` queries `Commit.where(sha: params.sha)` globally, with no repository/stack scoping, unlike the sibling `CheckSuiteHandler` which properly scopes through `stacks.where(branch: ...)` before touching `stack.commits`. [1](#0-0) [2](#0-1) 

### Title
Cross-repository Commit/Status mutation via unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits solely by `sha`, with no constraint tying the match to the repository that authenticated the webhook. Because git commit shas are content-addressed and identical across forks that share history, any org/repo the attacker legitimately controls and has registered in Shipit can emit a genuinely-signed `status` webhook that mutates `Commit`/`Status` rows belonging to a completely unrelated stack (e.g., the victim's), flipping `Commit#state` and `Commit#deployable?`.

### Finding Description
The broken binding: `repository_owner` (org that signed the webhook, verified in `WebhooksController#verify_signature` via `Shipit.github(organization: repository_owner)`) should equal the `owner`/`repository` of every `Commit` mutated by the resulting `Status`, but it does not.

- `WebhooksController#verify_signature` only checks that the HMAC signature matches the webhook secret configured for `repository_owner` (the org named in the payload's `repository.owner.login`) — it authenticates *which org sent the request*, not *which commits it may affect*. [3](#0-2) 
- `StatusHandler#process` then does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — it never filters by `stack`, `repository`, or the handler's `stacks` scope. [1](#0-0) 
- Compare with `CheckSuiteHandler#process`, which correctly narrows to `stacks.where(branch:)` (the org/owner-scoped stacks) before touching `stack.commits.where(sha:)`, proving the codebase has an established pattern for scoping that `StatusHandler` fails to follow. [2](#0-1) 
- `Commit#sha` is only indexed/expected-unique per `(stack_id, sha)` (per the `20170524104615_index_commits_on_stack_id_and_sha.rb` migration name found in the repo), not globally unique — so identical shas legitimately exist across different stacks/repos that share git history (forks).
- `Commit#create_status_from_github!` creates the `Status` and runs `add_status`, which can flip `commit.state`/`deployable?` and even fire `Hook.emit(:deployable_status, ...)` and block `Stack#trigger_continuous_delivery` gating on the victim stack. [4](#0-3) [5](#0-4) 

Exploit flow: attacker forks the victim's public/monitored upstream repo (retaining a shared historical commit sha), registers their own fork as a Shipit stack (an ordinary, unprivileged action against their own repo), then triggers (or fabricates via the GitHub Status API on their own fork, which they own) a `status` event with `state: failure` for that shared sha. GitHub signs and delivers this webhook using the attacker's own org's legitimate webhook secret, so `verify_signature` passes. `StatusHandler#process` then matches **every** `Commit` row across **every** stack with that sha — including the victim's — and writes a `failure`/`error` `Status` onto it, degrading `Commit#deployable?` and blocking `Stack#trigger_continuous_delivery` for a repository the attacker never authenticated against.

None of the existing guards catch this: `verify_signature` validates the signing org, not the target repository of the mutated record; `drop_unhandled_event` only checks the event type is handled; the `ExplicitParameters` schema on `StatusHandler` only validates the shape of `sha`/`state`, not ownership; there is no `force_github_authentication`, `User#authorized?`, or `stacks`-scope check anywhere in `StatusHandler#process`.

### Impact Explanation
A payload authenticated for one repository (the attacker's fork) mutates `Commit`/`Status` state belonging to another tenant's stack (the victim's), matching the Critical category "a payload for one repository mutating another's stack, commit, task or team." The attacker can degrade a victim's commit from deployable to blocked (sabotage), or in the inverse direction (not this question's focus, but symmetric) mark a victim commit as falsely `success`. This is repeatable against any stack in the Shipit instance whose repository shares any commit sha with a repository the attacker controls — which is guaranteed for any fork of a monitored repo that hasn't rewritten history back to the fork point.

### Likelihood Explanation
Preconditions: the victim repo must be tracked by Shipit, and the attacker must have a fork registered as a Shipit stack (ordinary self-service action, no elevated privilege, no secrets needed) and must be able to trigger a `status` webhook on their own fork (trivial — status API/CI on their own repo). Cost is a single legitimate webhook delivery from GitHub for a repo the attacker owns; it requires zero Shipit credentials, sessions, or `webhook_secret` knowledge. This is straightforwardly repeatable and does not depend on any race condition or timing.

### Recommendation
Scope `StatusHandler#process` by the handler's `stacks` (owner/repository-scoped, as `CheckSuiteHandler` already does), e.g. `stacks.find_each { |stack| stack.commits.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) } }`, so a webhook can only mutate commits belonging to stacks under the repository that authenticated it.

### Proof of Concept
Minitest under `test/models/webhooks/handlers/status_handler_test.rb` (or `test/controllers/webhooks_controller_test.rb`) plan:
1. Create two stacks with different repositories (`stack_a` for `attacker/fork`, `stack_b` for `victim/repo`), each with a `Commit` sharing the same `sha` value (simulating a common fork-point commit).
2. Post a `status` webhook payload with that shared `sha`, `state: 'failure'`, and `repository.owner.login` set to the attacker's org, stubbing `verify_signature`/`verify_webhook_signature` to simulate legitimate signing for the attacker's org only (`Shipit.github(organization: 'attacker').verify_webhook_signature` returns true).
3. Assert before: `stack_b.commits.first.state == 'success'` (or whatever baseline), and the equality `commit.stack.repository_owner == 'attacker'` is **false** for `stack_b`'s commit.
4. After posting, assert `stack_b.commits.first.reload.state == 'failure'` and `stack_b.commits.first.deployable? == false`, proving a record was written for a repository (`victim/repo`) that never authenticated the request — only `stack_a`'s commit should have changed.

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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
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
