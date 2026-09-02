### Title
Cross-repository status webhook triggers `Hook.emit(:commit_status, ...)` with attacker-controlled `description`/`target_url` for a victim stack - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves the target commit with a global, unscoped `Commit.where(sha: params.sha)` query instead of scoping it to the repository that authenticated the webhook. `WebhooksController#verify_signature` only proves the payload was legitimately signed by *some* org (the one named in `repository.owner.login`), not that this org owns the commit being updated, so an attacker with their own low-privilege GitHub App/org can push a status webhook whose `sha` collides with a commit belonging to a completely different, victim stack, and have `Hook.emit(:commit_status, stack, ...)` fire for the victim stack carrying attacker-supplied `description`/`target_url` text.

### Finding Description
The binding that should hold is:
`authenticated_org(payload) == commit.stack.repository.owner` for every `Commit` mutated by a webhook.

Trace:
1. `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) verifies the HMAC signature using `Shipit.github(organization: repository_owner)`, where `repository_owner = params.dig('repository','owner','login')`. This only proves the request was signed for *that* org's GitHub App — it says nothing about which `Commit`/`Stack` rows may be touched.
2. `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
```
This is a **global** lookup across the entire `commits` table with no `stack_id`/`repository` filter, and no comparison against `repository_owner`/`repository_name` from the payload at all. `Handler#stacks`/`repository_name` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`) exist in the base class but are never used by `StatusHandler`.
3. `Commit#create_status_from_github!` (`app/models/shipit/commit.rb:165-169`) calls `statuses.replicate_from_github!(stack_id, github_status)` using the **found commit's own `stack_id`** — i.e., the victim's stack, not any stack derived from the attacker's payload.
4. `add_status` (`app/models/shipit/commit.rb:366-386`) then calls `Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status))`, where `stack` is `commit.stack` (the victim stack) and `new_status` is built from the newly created `Status` record populated from the attacker's `description`/`target_url` fields (accepted in the `StatusHandler` params schema, `app/models/shipit/webhooks/handlers/status_handler.rb:10-11`).

Exploit flow: an attacker registers their own GitHub App/org (fully permitted under the threat model), learns or guesses a `sha` that already exists as a `Commit` row for some victim stack (commit SHAs for public repositories are not secret — they are visible via GitHub UI, PRs, CI logs, or the victim's own public Shipit stack page), and POSTs a validly-signed `status` webhook naming their own repo but referencing that `sha`, with `description`/`target_url` set to attacker-chosen strings. `Commit.where(sha: ...)` matches the victim's commit row regardless of which repository actually owns it, and the victim stack's configured `Hook` fires with the attacker's payload content.

None of the existing guards prevent this: `verify_signature` authenticates the org, not the commit/stack being mutated; `ExplicitParameters` schema only validates field types, not provenance; there is no `stacks`/`repository_name` scoping applied in `StatusHandler#process`.

### Impact Explanation
This lets an attacker who controls no victim-side credentials cause a write (`Status` record creation) on a commit belonging to a stack/repository they do not own, and cause `Hook.emit` to deliver attacker-authored payload content (`description`, `target_url`) to the victim stack's configured outbound Hook endpoint. This is a cross-tenant mutation ("a payload for one repository mutating another's stack, commit") and matches the Critical impact category. It is repeatable against any stack/commit whose `sha` the attacker can learn, and is not limited to a single victim — any known commit SHA across the whole install is a valid target since the lookup is global and unscoped.

### Likelihood Explanation
Preconditions are low-cost and match the stated attacker capability: own a GitHub App/org that can sign webhooks, and know (not guess) a target commit SHA for a victim stack. Commit SHAs are routinely public (visible on GitHub, in the Shipit web UI itself for stacks with public visibility, in CI logs, PR references, etc.), so this is highly feasible and trivially repeatable — one POST per target commit, with no rate limiting or additional authorization checks blocking it.

### Recommendation
Scope the `Commit` lookup in `StatusHandler#process` (and analogously any other handler using a bare `sha` lookup) to the repository that authenticated the request, e.g. `Repository.from_github_repo_name(repository_name)&.stacks&.commits&.where(sha: params.sha)`, mirroring the `stacks`/`repository_name` helpers already defined on `Handler`, so a commit can only be updated by a webhook whose signature was verified for the owning org/repository.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb` or `test/models/webhooks/handlers/status_handler_test.rb` style):
1. Create `victim_stack` bound to `victim-org/victim-repo`, with a `Commit` (`sha: "aaaa...aaaa"`) and a `Hook` configured on `victim_stack` for the `commit_status` event.
2. Create `attacker_org/attacker-repo` with valid GitHub App credentials configured in `Shipit.github(organization: "attacker-org")`.
3. POST a `status` event payload to `/webhooks` signed with the attacker org's webhook secret, with `repository.full_name = "attacker-org/attacker-repo"`, `sha = "aaaa...aaaa"` (matching the victim's commit), `state: "success"`, `target_url: "http://attacker-controlled/probe"`, `description: "attacker text"`.
4. Assert: LHS `repository_owner` from the verified payload = `"attacker-org"`; RHS `Commit.find_by(sha: "aaaa...aaaa").stack` = `victim_stack` (owned by `"victim-org"`) — these differ, proving the binding is broken.
5. Stub/mock `Hook.emit` and assert it is invoked with `:commit_status`, `victim_stack`, and a payload whose `commit_status`/`target_url` reflects the attacker's `"http://attacker-controlled/probe"` value, despite the request never being signed for `victim-org`.