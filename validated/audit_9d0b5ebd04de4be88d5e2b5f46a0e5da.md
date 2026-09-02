### Title
StatusHandler#process writes GitHub status onto commits by SHA alone, ignoring the verified payload's repository - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits globally by `sha` with no repository/stack scoping and calls `create_status_from_github!` on every match. Because git SHAs are content-addressed and can collide across unrelated repositories (e.g. the well-known empty tree `4b825dc642cb6eb9a060e54bf8d69288fbee491`, or any commit with identical tree, parents, author/committer and timestamps), an attacker who owns repository B and can get GitHub to emit a validly-signed `status` webhook for B can cause a `Status` row to be written on stack A's commit even though the verified payload names repository B.

### Finding Description
Binding claimed broken: `payload.dig('repository','full_name')` (the repository authenticated by `verify_signature`) == the repository owning the `Commit` row mutated by `create_status_from_github!`. This must be false for the exploit to work, and the code never checks it.

Code path:
- `Shipit::WebhooksController#create` (`app/controllers/shipit/webhooks_controller.rb:10-15`) parses the JSON body and dispatches to handlers for the event, after `verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) validates the HMAC using the GitHub App resolved from `repository.owner.login` in the payload. This proves the payload was signed by repository B's own secret — it says nothing about which `Commit` rows exist for that sha.
- `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`):
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
This queries `Commit` across **all stacks/repositories** by `sha` only — there is no `where(stack_id: stacks.pluck(:id))` or repository filter, unlike the base `Handler#stacks`/`repository_name` helpers (`app/models/shipit/webhooks/handlers/handler.rb:32-38`) which exist precisely to scope work to the repository named in the payload, but `StatusHandler` does not use them.
- `Commit#create_status_from_github!` (`app/models/shipit/commit.rb:165-169`) then creates a `Status` on that commit via `add_status`, with no re-validation that the commit's `stack.repository` matches the webhook's repository.

Exploit: Attacker owns repo `attacker/B`, forks/pushes a commit whose sha equals a sha already present in stack A (any git object with identical content, e.g. an empty-tree commit, or any commit crafted to have identical tree, parent set, message, author, committer and timestamps — feasible because such fields are attacker-controlled and SHA collisions of this kind are a known, demonstrated technique for shared blobs/empty trees, not requiring SHA-1 cryptanalysis). GitHub sends a `status` event to Shipit for repository B, correctly HMAC-signed with B's own `webhook_secret`. `verify_signature` passes (it's a genuine signature for B). `StatusHandler#process` finds `Commit` rows with that sha regardless of stack, including stack A's commit, and writes a `Status` there — a cross-tenant write despite the payload naming `attacker/B`.

Existing guards checked and found insufficient:
- `verify_signature` only proves "this payload was signed by the app belonging to the named repository's owner" — it does not scope which `Commit` rows the handler is allowed to touch.
- `drop_unhandled_event` / `ExplicitParameters` schema (`params do ... end` in `status_handler.rb:7-18`) validate presence/types of `sha`, `state`, etc., but never validate that `sha` belongs to the repository in `params.repository`.
- The `Handler` base class provides `stacks`/`repository_name` scoping helpers (`handler.rb:32-38`) that other handlers could use, but `StatusHandler` never calls `stacks` and queries `Commit` unscoped.

### Impact Explanation
A single crafted, self-signed `status` webhook from an attacker-owned repository can inject a `Status` record (arbitrary `state`, `context`, `description`, `target_url`) onto another tenant's commit in stack A. Since `Commit#status` drives `deployable?`/CI gating and `schedule_continuous_delivery` (`app/models/shipit/commit.rb:227-229, 281-287`), a forged "success" status can help make a commit appear deployable, or a forged "failure"/"error" status can block deploys — a cross-repository write of another tenant's CI/deploy state. This matches the Critical category: "a payload for one repository mutating another's stack, commit, task or team." It is repeatable against any commit sha the attacker can reproduce, and the attack scales to any stack that happens to share a sha (most reliably via well-known empty-tree/degenerate objects that many repos may contain).

### Likelihood Explanation
Preconditions: attacker needs (1) an unprivileged GitHub repository they control that is configured to send Shipit webhooks with a valid `webhook_secret` for that app/org (standard Shipit setup for any onboarded repo), and (2) a commit sha collision with the target stack's commit. Colliding on content-identical git objects (empty tree, or commits with identical tree/parents/author/committer/timestamps) is feasible without breaking SHA-1 cryptographically — it only requires the target's commit metadata to be knowable/reproducible, which is easiest for well-known constant objects like the empty tree sha, likely present across many repositories. Attacker cost is very low (own repo, valid GitHub-generated signature); the request is fully repeatable and requires no privileged Shipit role, session, or secret.

### Recommendation
Scope the commit lookup in `StatusHandler#process` to the repository named in the verified payload, e.g. use the existing `stacks` helper from `Handler`:
```ruby
def process
  Commit.where(sha: params.sha, stack_id: stacks.select(:id)).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
This ensures only commits belonging to stacks tied to `payload.dig('repository','full_name')` can be mutated by a given webhook.

### Proof of Concept
Minitest under `test/models/shipit/webhooks/handlers/status_handler_test.rb` (conceptual, illustrating the missing binding check):
1. Create `stack_a` for repository `owner/A` and `stack_b` for repository `attacker/B`.
2. Create `commit_a = shipit_commits(:...)` under `stack_a` with `sha: "4b825dc642cb6eb9a060e54bf8d69288fbee491"`.
3. Create `commit_b` under `stack_b` with the same `sha`.
4. Build `payload = { 'sha' => commit_b.sha, 'state' => 'success', 'repository' => { 'full_name' => 'attacker/B' } }`.
5. Call `Shipit::Webhooks::Handlers::StatusHandler.new(payload).process`.
6. Assert:
   - `payload.dig('repository','full_name') == 'attacker/B'` (payload's authenticated repository)
   - `commit_a.stack.repository.full_name != 'attacker/B'` (the mutated commit's owning repository)
   - `commit_a.reload.statuses.count == 1` and `commit_a.statuses.last.state == 'success'` — proving stack A's commit was mutated despite the payload naming a different repository.