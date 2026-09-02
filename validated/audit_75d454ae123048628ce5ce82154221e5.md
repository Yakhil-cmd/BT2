### Title
Cross-tenant status fan-out via unscoped `Commit.where(sha:)` in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits purely by `sha`, without scoping to the repository named in the webhook payload, unlike `PushHandler#process` which scopes through `Handler#stacks` (derived from `payload['repository']['full_name']`). Because `Commit.sha` is not globally unique (only unique per `stack_id`, per the `index_commits_on_stack_id_and_sha` migration), a status webhook for one repository can mutate commit status records belonging to every other stack that happens to share that sha, e.g. a common initial/template commit.

### Finding Description
Broken binding: `{stack_id(commit) : commit ∈ mutated_set}` should equal `{stack_id : stack ∈ Repository.from_github_repo_name(payload.repository.full_name).stacks}` (size 1 for a single named repository), but instead equals `{stack_id : commit.sha == params.sha}` unconstrained by repository — size N for N stacks sharing that sha.

Code path: `StatusHandler#process` at app/models/shipit/webhooks/handlers/status_handler.rb:21 runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`. This never calls `stacks` (defined in the base `Handler` class, app/models/shipit/webhooks/handlers/handler.rb:32-34), which is what `PushHandler#process` (app/models/shipit/webhooks/handlers/push_handler.rb:12-17) uses to scope to `Repository.from_github_repo_name(repository_name).stacks`. `Commit` has only a per-stack uniqueness constraint (`belongs_to :stack`, and DB index on `[stack_id, sha]`), not a global uniqueness constraint on `sha` alone — see app/models/shipit/commit.rb:11 and db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb. Thus identical shas across independently-created stacks (e.g., repos forked/initialized from a common template with an identical initial empty commit) are legitimately different `Commit` rows, one per stack, all matching the same `sha`.

`create_status_from_github!` (app/models/shipit/commit.rb:165-169) creates a `Status` record scoped to that commit's `stack_id`, and `add_status` (lines 366-386) fires `Hook.emit` events scoped to `stack`. So each matching commit across unrelated stacks gets a new success/failure status written and hooks emitted for that stack, even though only one repository was named in, and authenticated by, the incoming webhook.

Existing guards do not prevent this: signature verification (`verify_signature`/`GitHubApp#verify_webhook_signature`) only proves the payload came from GitHub for the *named* repository — it does not restrict which DB rows are touched once inside `process`. `ExplicitParameters` validates the shape of `sha`/`state`/etc. but does not scope the sha to a repository. There is no `stacks`/`repository.full_name` filter anywhere in `StatusHandler`.

Attacker exact action: control (or push to) any repository configured as a Shipit stack whose initial commit sha is shared with other tenants' stacks (common for template-based repo creation), then trigger a `status` webhook from GitHub for their own repository/commit (a legitimate action any repo owner can perform, e.g. by having their own CI report a commit status). GitHub signs this webhook validly for the attacker's own repository, so `verify_signature` passes. `StatusHandler#process` then writes `Status` rows and fires hooks on every other stack (regardless of repository) that has a `Commit` with the same sha.

### Impact Explanation
A single, validly-signed webhook for one repository causes `Shipit::Status` records to be created (and status/deployable_status hooks emitted) on stacks belonging to unrelated repositories/tenants that merely share a commit sha (e.g., a common template's initial empty commit). This can flip a foreign stack's commit into "success" state, potentially unblocking `continuous_deployment?` / `schedule_continuous_delivery` (app/models/shipit/commit.rb:281-287) and triggering an unauthorized deploy on someone else's stack — a payload for one repository mutating another's stack/commit data. This matches the Critical category "a payload for one repository mutating another's stack, commit, task or team" / "an unauthorized deploy."

### Likelihood Explanation
Requires that at least one commit sha be shared across multiple independently-managed `Stack` fixtures/repos — realistic when many repositories are bootstrapped from the same template and share an initial commit before diverging (this is explicitly called out as a common real-world scenario). No secrets, tokens, or elevated privileges are needed beyond controlling one's own repository and being able to trigger a status webhook (a routine, low-cost action, e.g., via a connected CI). Fully repeatable against any set of stacks sharing a sha.

### Recommendation
Scope `StatusHandler#process` the same way `PushHandler` does: restrict the commit lookup to commits belonging to stacks resolved from the webhook's `repository.full_name`, e.g. `Commit.where(sha: params.sha, stack: stacks).each { ... }` using the existing `Handler#stacks` method, instead of an unscoped `Commit.where(sha:)`.

### Proof of Concept
Minitest plan (under `test/models/shipit/webhooks/handlers/status_handler_test.rb`):
1. Create three `Shipit::Stack` fixtures for three distinct repositories (`repo-a/x`, `repo-b/y`, `repo-c/z`).
2. Create one `Shipit::Commit` per stack, all with an identical `sha` (e.g. `"deadbeef" * 5`), simulating a shared template initial commit.
3. Build a status webhook payload naming only `repo-a/x` as `repository.full_name`, with `sha` set to the shared sha and `state: 'success'`.
4. Call `Shipit::Webhooks::Handlers::StatusHandler.call(payload)`.
5. Assert on both sides of the binding:
   - Expected (correct binding): `Shipit::Status.where(state: 'success', stack_id: stack_a.id).count == 1` and `Shipit::Status.where(state: 'success', stack_id: [stack_b.id, stack_c.id]).count == 0`.
   - Actual (current code): `Shipit::Status.where(state: 'success').count == 3`, i.e. `stack_b` and `stack_c` also received a `success` status despite the payload only naming `repo-a/x`.

The test demonstrates the divergence and would fail against the current implementation, confirming the vulnerability.