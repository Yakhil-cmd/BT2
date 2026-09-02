### Title
Cross-repository Status forgery via global sha lookup in `StatusHandler#process` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` resolves the target commit(s) for an incoming GitHub `status` webhook using a global, repository-unscoped query, `Commit.where(sha: params.sha)`. Because git commit shas are content-addressed and deterministic, any attacker who controls a repository can craft a commit whose sha collides with a commit already tracked by an unrelated Shipit stack, and legitimately trigger GitHub to send a real, correctly-signed status webhook for their own repository that Shipit then applies to every other stack sharing that sha — most reliably the well-known empty-tree/no-parent initial commit sha.

### Finding Description
The broken binding is: `commit.stack.repository == payload['repository']` should hold for every `Status` created from a webhook, but the code only checks `commit.sha == params.sha`.

Code path:
- `app/models/shipit/webhooks/handlers/status_handler.rb`:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
This queries `Commit` across the entire `commits` table with no `stack_id`/`repository` filter, even though the base `Handler` class (`app/models/shipit/webhooks/handlers/handler.rb`) already exposes a `repository_name`/`stacks` helper (derived from `payload.dig('repository', 'full_name')`) that other handlers (e.g. the pull_request handlers) use to scope work to the stacks belonging to the webhook's own repository. `StatusHandler` does not use it at all.

`Commit#create_status_from_github!` (`app/models/shipit/commit.rb:165-169`) then unconditionally writes a `Status` row (via `statuses.replicate_from_github!`) for whatever `commit` was matched, using `commit.stack_id` — the *victim* stack — while the webhook signature/payload actually originates from the *attacker's* repository.

Signature verification (`GitHubApp#verify_webhook_signature`) only proves that the payload came from GitHub for the repository the attacker configured the webhook on (Rt, which the attacker owns and controls the webhook secret/CI for). It says nothing about which `Commit` rows in Shipit's database that sha should apply to. `drop_unhandled_event`, `ExplicitParameters` schema validation, and `force_github_authentication` are all satisfied normally since this is a legitimate, correctly-signed webhook for Rt — none of them scope the sha to the originating repository.

Exploit flow:
1. Attacker creates a private/internal GitHub repo `Rt` with no README, so its initial commit is the well-known deterministic empty-tree-based initial commit sha (or otherwise contrives a colliding sha with a target stack's initial/known commit).
2. Attacker sets up CI (or manually POSTs a `status` payload as their own GitHub App/webhook) that reports `state: success` for that sha on `Rt`.
3. GitHub sends a correctly-signed `status` webhook to Shipit's `/webhooks` endpoint for `Rt`.
4. `StatusHandler#process` runs `Commit.where(sha: <that sha>)`, which matches the commit row(s) belonging to *every other* Shipit-tracked stack whose initial commit shares that sha.
5. `create_status_from_github!` writes a `Status` row for each of those foreign commits, attributing it to their `stack_id` — a stack the attacker never authenticated against and doesn't own.

### Impact Explanation
A payload originating from a repository the attacker fully owns is used to write `Status` records against unrelated stacks (`Status` belongs to `commit.stack_id`, not the requesting repository). This is a cross-tenant data integrity break: since `deployable?`/CI-gating logic in `Commit#deployable?`/`blocked?` and continuous delivery (`schedule_continuous_delivery`) consult status state, an attacker can potentially flip a foreign stack's commit into "success"/CI-green state and trigger `ContinuousDeliveryJob`, `Hook.emit(:deployable_status, ...)`, and downstream automatic merges/deploys for a repository they don't control — matching "a payload for one repository mutating another's stack, commit, task or team" and "an unauthorized deploy" (Critical).

### Likelihood Explanation
Preconditions: the attacker needs (a) any GitHub repository they own/control with a webhook configured to Shipit (feasible for anyone able to add repos, no Shipit privilege required), and (b) a target stack whose commit sha they can predict/collide with — trivially true for the empty-tree/no-parent initial commit sha, which is common for repositories initialized without a README and is fully deterministic (same author/committer identity+date+empty tree+no parent → same sha). No Shipit secrets, sessions, API tokens, or GitHub App keys are required; the webhook signature is valid because it is genuinely signed for `Rt`. This is repeatable at will against any tracked stack sharing a colliding sha.

### Recommendation
Scope the `Commit` lookup in `StatusHandler#process` to the commits belonging to the webhook's own repository, mirroring the `stacks`/`repository_name` helper already used by other handlers, e.g.:
```ruby
def process
  Commit.where(sha: params.sha, stack_id: stacks.select(:id)).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
so that a sha match is only applied to commits whose stack's repository matches `payload['repository']['full_name']`.

### Proof of Concept
minitest plan (`test/models/webhooks/status_handler_test.rb`-style, no live GitHub):
1. Create `stack_a` bound to `repository_a` (`full_name: "org/repo-a"`) and `stack_b` bound to `repository_b` (`full_name: "org/repo-b"`).
2. Create `commit_a` under `stack_a` and `commit_b` under `stack_b`, both with `sha: "4b825dc642cb6eb9a060e54bf8d69288fbee4904"` (the well-known empty-tree/init sha).
3. Build a webhook payload with `repository.full_name = "org/repo-a"`, `sha` = the shared sha, `state: "success"`.
4. Call `Shipit::Webhooks::Handlers::StatusHandler.call(params)` once (simulating the single POST for repo-a's webhook).
5. Assert: `commit_a.statuses.reload.count == 1` (expected write).
6. Assert (the failing binding): `commit_b.statuses.reload.count == 0` — currently this fails because the handler also creates a `Status` on `commit_b`, proving cross-stack write from a single-repository webhook.