### Title
Cross-repository commit status forgery via unscoped SHA lookup in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits by `sha` alone across the entire database (`Commit.where(sha: params.sha)`), never restricting the query to the repository that authenticated the webhook. Since the signature verification (`WebhooksController#verify_signature`) only proves that the payload was signed with the webhook secret of the organization named in the payload's own `repository.owner.login`/`organization.login`, an attacker who owns `attacker/repo` can flip the `state` of any `Commit` row sharing the same sha in an unrelated victim repository (e.g., identical/empty-tree commits shared across forks).

### Finding Description
The broken binding: `verify_signature` proves `repository_owner(payload) == attacker_org`, but `StatusHandler#process` mutates commits where `Commit#stack.repository.full_name` may equal `victim/repo`. These are never checked to be equal, i.e. `authenticated_repository != mutated_repository`.

Code path:
- `WebhooksController#create` (app/controllers/shipit/webhooks_controller.rb:10-15) parses the raw JSON and dispatches to `Shipit::Webhooks.for_event(event)` handlers after `verify_signature` passes.
- `verify_signature` (app/controllers/shipit/webhooks_controller.rb:24-49) calls `Shipit.github(organization: repository_owner)` and `verify_webhook_signature`, where `repository_owner` is read straight from the attacker-controlled payload (`params.dig('repository','owner','login')`). This proves only that the payload was signed by the org named in the payload — i.e., the attacker's own org, since the attacker fully controls what repository/organization fields appear in a webhook they self-generate for `attacker/repo`.
- `StatusHandler#process` (app/models/shipit/webhooks/handlers/status_handler.rb:20-24):
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
This performs a global `Commit` lookup keyed only on `sha`, with no join/filter on `Stack`/`Repository`. Contrast with `PushHandler#process` (app/models/shipit/webhooks/handlers/push_handler.rb:12-17), which correctly scopes work through the base class's `stacks` helper (`Repository.from_github_repo_name(repository_name)&.stacks`), derived from `payload.dig('repository','full_name')` (app/models/shipit/webhooks/handlers/handler.rb:32-38). `StatusHandler` never calls `stacks` or `repository_name` at all, so the repository-scoping guard that other handlers rely on is entirely absent here.

Attacker's exact request: attacker pushes a commit to `attacker/repo` whose sha X is identical to a commit that independently exists in `victim/repo` (trivially achievable with content-identical/empty commits, e.g. the well-known empty tree sha `4b825dc642cb6eb9a060e54bf8d69288fbee4904`, or any cherry-picked/forked commit). Attacker then POSTs a GitHub `status` webhook to `/webhooks` with `X-Github-Event: status`, a valid `X-Hub-Signature` computed with `attacker/repo`'s own org webhook secret (which the attacker legitimately possesses/controls), and body `{"repository": {"owner": {"login": "attacker-org"}}, "sha": "X", "state": "success", ...}`.

Exploit flow: `verify_signature` succeeds (attacker-org secret matches attacker-signed payload) → `StatusHandler.call` → `Commit.where(sha: "X")` returns rows from both `attacker/repo` and `victim/repo` stacks → `commit.create_status_from_github!(params)` is invoked on the victim's `Commit` row, flipping its status/state to `success` even though the victim's repository never authenticated this payload.

Existing guards do not prevent this: `verify_signature` only binds the signature to the org named in the same attacker-controlled payload, not to the actual owner of every `Commit` row that will be touched; `ExplicitParameters` only validates shape (`sha`, `state`, etc.), not ownership; there is no `stacks`/`repository_name` scoping call anywhere in `StatusHandler`.

### Impact Explanation
An attacker with no privileges on the victim repository can cause the victim's `Commit#state` to become `success` for any sha they can also produce in a commit of their own repository. Because `Stack#trigger_continuous_delivery` and related automation act on commit status, this can unblock/trigger a deploy pipeline on the victim's stack that never received a legitimate status update from GitHub for that repository — a cross-repository write and effective authentication-bypass of the repository-scoping invariant. This matches the "Critical" category: a payload for one repository mutating another's commit/stack state and potentially triggering an unauthorized deploy.

### Likelihood Explanation
Preconditions are attacker-achievable: own any GitHub repo registered with Shipit (`attacker/repo`), and find/create a commit whose sha collides with a commit that exists in a target victim stack (trivial for well-known empty/boilerplate commits, or via forking, cherry-picking, or shared vendored history — an increasingly common scenario for forks of open source projects onboarded to the same Shipit instance). No secrets, sessions, or elevated roles are required. The attack is a simple, repeatable HTTP POST and can be repeated against any commit sha shared across tenants.

### Recommendation
Scope `StatusHandler#process` to only commits belonging to the authenticated repository, mirroring `PushHandler`'s use of `stacks`:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
or equivalently join `Commit` through `Stack`/`Repository` filtered by `repository_name` derived from the payload before applying the status update.

### Proof of Concept
Minitest plan (models/shipit/webhooks/handlers/status_handler_test.rb style):
1. Create two `Stack`/`Repository` pairs: `attacker_repo` (`attacker/repo`) and `victim_repo` (`victim/repo`).
2. Create `attacker_commit = create_commit(stack: attacker_stack, sha: 'X')` and `victim_commit = create_commit(stack: victim_stack, sha: 'X')` — same sha, different stacks/repositories.
3. Assert precondition: `assert_equal 'unknown', victim_commit.state` (or whatever the default pre-status state is).
4. Build a `status` payload with `repository.full_name` / `owner.login` set to `attacker/repo`'s org, `sha: 'X'`, `state: 'success'`.
5. Call `Shipit::Webhooks::Handlers::StatusHandler.call(payload)` directly (bypassing controller signature verification, since the vulnerability is inside the handler regardless of a valid attacker signature).
6. Assert the equality that should NOT hold but does: `assert_equal 'success', victim_commit.reload.state` — proving that a payload authenticated only for `attacker/repo` mutated `victim/repo`'s commit.
7. Optionally assert `victim_stack.commits.find_by(sha: 'X').status_from_context(...)` or similar to show downstream effect (e.g., `trigger_continuous_delivery` eligibility) is now satisfied for the victim stack without any legitimate victim-side webhook.