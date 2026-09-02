### Title
`StatusHandler#process` performs a global, repository-unscoped `Commit.where(sha:)` lookup, allowing a webhook for one repository to mutate a `Commit`/`Stack` belonging to an unrelated repository - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits by `sha` alone across the *entire* `commits` table and calls `commit.create_status_from_github!(params)` on every match, without ever using `Handler#stacks` (which resolves `Repository.from_github_repo_name(repository_name)`) to restrict the update to commits belonging to the repository named in the verified payload. Because `Commit#create_status_from_github!` (`app/models/shipit/commit.rb`) writes the status using `commit.stack_id`, a status webhook that is validly signed for the attacker's own repository/installation can flip the state of a `Commit` in a completely different stack, as long as the `sha` value matches — which is guaranteed to happen for any commit shared via a GitHub fork.

### Finding Description
The broken binding, stated explicitly:
`repository_name = payload.dig('repository', 'full_name')` should equal `commit.stack.repository.full_name` for every `commit` mutated by `StatusHandler#process`. In the actual code this equality is never checked.

Code path:
- `Handler` base class defines a helper `stacks` that correctly scopes to the repository of the incoming payload: `Repository.from_github_repo_name(repository_name)&.stacks` [1](#0-0) 
- `StatusHandler#process` ignores that scoping entirely and instead does a bare, table-wide lookup: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [2](#0-1) 
- `Commit#create_status_from_github!` then writes the status keyed on that commit's own `stack_id`, with no re-validation against the webhook's repository: `statuses.replicate_from_github!(stack_id, github_status)` inside `add_status` [3](#0-2) 

Signature verification (performed upstream in `WebhooksController`/GitHub App verification, out of this file) only proves that GitHub sent the payload for *some* installation the app is authorized on — typically a single app-level secret shared across every repository the app is installed on. It proves the `repository` field is authentic for the sender's own repo, but does nothing to prevent `StatusHandler` from applying the update to an unrelated `Commit` row that merely shares the same `sha`.

Exploit flow:
1. Attacker owns/administers a public repository (or fork) where the target Shipit installation's GitHub App is installed — a routine, permission-less action for any GitHub user on their own repos/forks.
2. Because forks initially share git object history, many commits in the attacker's repo have the exact same SHA-1 as commits in the upstream repository that Shipit tracks in an unrelated `Stack`.
3. Attacker triggers (or directly sends, since GitHub allows repo owners to configure/re-deliver status webhooks) a `status` event for that shared `sha` with `state: 'success'` from their own repository.
4. `StatusHandler#process` matches the `Commit` row belonging to the *victim's* stack purely by `sha`, and calls `create_status_from_github!`, flipping that commit's status to `success` even though the correctly-scoped `commit.stack.repository.full_name` differs from the webhook's `repository.full_name`.

None of the listed guards prevent this: signature verification authenticates the sender/repo of the payload, not which `Commit` rows may be touched; `ExplicitParameters` only validates the shape of `sha`/`state`/etc., not repository binding; there is no `stacks`/repository filter applied in this handler at all.

### Impact Explanation
A `success` (or any) status pushed from an attacker-controlled repository can flip the CI status of a commit belonging to a completely different, unrelated stack/repository that the attacker does not own or administer. Since `deployable?` and `blocked?` on `Commit` depend on status state, this can make an otherwise-blocked commit in the victim stack appear deployable, directly enabling an unauthorized deploy path for a repository the attacker never authenticated against. This matches the "payload for one repository mutating another's stack/commit" and "unauthorized deploy" Critical impact categories. The attack is repeatable against any commit sha collision the attacker can produce (trivial via forking), across any stack configured in the same Shipit instance.

### Likelihood Explanation
Preconditions are low-cost and attacker-controllable: own/administer a repository with the app installed (standard GitHub permission for one's own repos), and rely on git's content-addressed SHA-1 to naturally produce shared commit hashes between a fork and its upstream (or between any repos with common history) — no cryptographic collision or brute force needed. No Shipit secrets, session, or maintainer role is required. This is repeatable at will for any commit whose SHA the attacker's own repo also contains.

### Recommendation
Scope the lookup in `StatusHandler#process` to the repository of the verified payload, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` (using the existing `Handler#stacks` helper), or explicitly verify `commit.stack.repository.full_name == repository_name` before calling `create_status_from_github!`, dropping/logging any mismatched commit.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`):
1. Create `stack_a` for repository `"attacker/repo"` and `stack_b` for repository `"victim/repo"`.
2. Create `commit_b` under `stack_b` with `sha: "deadbeef..."` and an existing `failure`/`pending` `Status`.
3. Build a `StatusHandler` payload with `repository.full_name = "attacker/repo"`, `sha: "deadbeef..."`, `state: "success"` (simulating the shared-history collision — no commit under `stack_a` needs to exist for the bug to trigger).
4. Call `StatusHandler.call(payload)`.
5. Assert the broken binding: before, `commit_b.stack.repository.full_name` ("victim/repo") != payload `repository.full_name` ("attacker/repo"); after processing, assert `commit_b.reload.state == "success"`, proving the mismatched-repository payload mutated `stack_b`'s commit despite the inequality never being checked by the code.

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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
