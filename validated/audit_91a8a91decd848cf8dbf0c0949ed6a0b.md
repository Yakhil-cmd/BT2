### Title
Cross-repository ReviewStack archive/unarchive via webhook org/repository field mismatch - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/organization used to validate the HMAC signature from `params.dig('repository','owner','login')` (or `params.dig('organization','login')`), while `UnlabeledHandler#repository` independently resolves the target `Repository` from `params.repository.full_name` in the same attacker-supplied JSON body. Nothing enforces that these two fields refer to the same repository/organization, so an attacker who owns any org already onboarded to Shipit (and thus knows that org's `webhook_secret`) can sign a payload with `repository.owner.login` set to their own org while setting `repository.full_name` to a victim's repository, causing the victim's `ReviewStack` to be archived or unarchived.

### Finding Description
The broken binding is the implicit equality:
`Shipit.github(organization: repository_owner)` (the org whose secret verified the request) **must equal** the org that owns `Repository.from_github_repo_name(params.repository.full_name)` (the org whose stack gets mutated).

Trace:
1. `WebhooksController#verify_signature` (app/controllers/shipit/webhooks_controller.rb:24-30) computes `repository_owner` via `repository_owner` (line 59-62), reading `params.dig('repository','owner','login')` straight from the raw, attacker-controlled JSON — before any schema validation (`ExplicitParameters` validation happens later, inside `handler.call`, not before signature verification). It then does `github_app = Shipit.github(organization: repository_owner)` and verifies the HMAC using that org's `webhook_secret`.
2. Once signature check passes, `WebhooksController#create` dispatches to `Shipit::Webhooks.for_event(event)` handlers, e.g. `UnlabeledHandler`.
3. `UnlabeledHandler#repository` (app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb:59-63) independently resolves `Shipit::Repository.from_github_repo_name(params.repository.full_name)` — reading `repository.full_name`, a completely separate JSON field from `repository.owner.login` used in step 1. `Repository.from_github_repo_name` (app/models/shipit/repository.rb:53-56) simply splits `"owner/name"` and does a DB lookup with no relation back to which org's secret was actually used to authenticate the request.
4. `UnlabeledHandler#handle` (lines 49-57) then calls `stack.archive!`/`stack.unarchive!`, which via `ReviewStackAdapter#archive!`/`#unarchive!` (app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb:23-50) call `stack.deprovision`, `stack.archive!(user, ...)` or `Shipit::ReviewStackProvisioningQueue.add(stack)` + `stack.unarchive!(...)` — real deprovision/reprovision side effects on the victim's `ReviewStack`.

Attacker request: attacker owns org `attacker-org` legitimately connected to Shipit with its own `webhook_secret`. They build a raw `pull_request`/`unlabeled` payload JSON with:
- `repository.owner.login = "attacker-org"` (or `organization.login = "attacker-org"`)
- `repository.full_name = "victim-org/victim-repo"`
- a `pull_request.number` matching an existing PR/environment (`pr#{number}`) on the victim's onboarded repo, with `labels` chosen to trigger `archive?`/`unarchive?` per the victim repo's `provisioning_behavior`.

They sign the raw body with `attacker-org`'s own `webhook_secret` and POST to `/webhooks` with `X-Hub-Signature` and `X-Github-Event: pull_request`. `verify_signature` picks `Shipit.github(organization: "attacker-org")`, verifies successfully (attacker knows this secret), and the request proceeds. `UnlabeledHandler` then resolves and mutates `victim-org/victim-repo`'s `ReviewStack`.

Existing guards do not prevent this: `ExplicitParameters` schema (`params do ... end` in `UnlabeledHandler`) only validates types/presence of `repository.full_name`, not its consistency with `repository.owner.login`; `drop_unhandled_event` only checks the event type exists; `force_github_authentication`/`User#authorized?`/`require_permission!` are unrelated to webhook ingestion (webhooks don't go through session/API-token auth at all). No code anywhere cross-checks `repository_owner` (used for signature verification) against `repository.full_name` (used for stack mutation).

### Impact Explanation
An attacker with no privileges on the victim repository — only ownership of any Shipit-onboarded org — can trigger deprovision (`archive!`, running `stack.deprovision`) or reprovision (`unarchive!`, enqueueing `Shipit::ReviewStackProvisioningQueue`) on an arbitrary victim `ReviewStack`, repeatedly and for any victim repo/PR/environment they can guess or know about. This is a payload for one repository mutating another's stack — Critical severity per the stated impact categories. The blast radius spans all tenants/repos onboarded to the same Shipit instance, since the org used for authentication is entirely decoupled from the org whose data is mutated.

### Likelihood Explanation
Preconditions: attacker must control any org onboarded to Shipit with its own `webhook_secret` (cheap and self-servable if Shipit allows self-onboarding, or trivial if attacker already has one repo connected), and must know the victim's `repository.full_name` and an existing PR number (`environment = "pr#{number}"`) with review stacks enabled and a configured `provisioning_behavior`. No GitHub-side privilege on the victim repo is required — the request is a raw, hand-crafted HTTP POST, not a real GitHub-originated webhook. This is a low-cost, fully repeatable attack against any repo on the same Shipit instance.

### Recommendation
In `WebhooksController#verify_signature`, or in the handler layer, enforce that the organization used to verify the signature equals the owner parsed from `repository.full_name` used for the actual repository/stack lookup (e.g., derive both from the same normalized field, or explicitly compare `repository_owner` against `Repository.from_github_repo_name(payload_full_name)&.owner` before dispatching to handlers, rejecting on mismatch with a 422).

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb` style, no live GitHub):
1. Create `attacker_org` Shipit org config with `webhook_secret = "attacker-secret"`.
2. Create victim `Repository` (`victim-org/victim-repo`) with `review_stacks_enabled: true`, `provisioning_behavior: "prevent_with_label"`, and an existing `ReviewStack` for `environment: "pr123"` that is currently active (`archived?` false) and has provisioning label present.
3. Build JSON body: `action: "unlabeled"`, `number: 123`, `pull_request.state: "open"`, `pull_request.head.ref`, `pull_request.labels: []` (label removed so `pull_request_has_provisioning_label?` becomes false, triggering `archive?` for `prevent_with_label`), `repository.owner.login: "attacker-org"`, `repository.full_name: "victim-org/victim-repo"`, `sender.login: "attacker"`.
4. Compute `X-Hub-Signature` HMAC using `attacker-secret` over the raw JSON body.
5. POST to `/webhooks` with `X-Github-Event: pull_request` header and the signature header.
6. Assert response is `200 OK` (not `422`).
7. Reload the victim `ReviewStack` and assert `archived?` is now `true` (or `provision_status`/`deprovision` was invoked) — proving the attacker's own-org-signed webhook mutated a repo/stack it never authenticated for.