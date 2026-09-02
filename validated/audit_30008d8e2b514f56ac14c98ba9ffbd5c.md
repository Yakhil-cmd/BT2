### Title
Cross-organization webhook forgery via `repository.owner.login`/`repository.full_name` mismatch enables status/build-status injection and forced sync on another organization's stacks - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` authenticates an inbound webhook by looking up the GitHub App/secret keyed on `params.dig('repository','owner','login')`, but the event handlers that subsequently act on the payload key off a *different* field — `payload.dig('repository','full_name')` (or, for the `status` event, no repository scoping at all). Because Shipit exposes a raw, directly-POST-able `/webhooks` endpoint (it is not a relay strictly reconstructed by GitHub), an attacker who legitimately controls one configured GitHub App/organization (and therefore knows that organization's own `webhook_secret`) can hand-craft a JSON body whose `repository.owner.login` names their own org (to pass signature verification) while `repository.full_name` (or the `sha`) names an unrelated victim stack/commit.

### Finding Description
- Signature verification: `app/controllers/shipit/webhooks_controller.rb:24-30` selects the signing secret via `repository_owner`, defined at `app/controllers/shipit/webhooks_controller.rb:59-62` as `params.dig('repository','owner','login')`.
- Handler dispatch acts on the raw, unauthenticated-content field `full_name`: `app/models/shipit/webhooks/handlers/handler.rb:32-38` — `stacks` resolves via `Repository.from_github_repo_name(repository_name)` where `repository_name = payload.dig('repository','full_name')`.
- `PushHandler#process` (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`) forces `stack.sync_github(expected_head_sha: params.after)` on every stack of the resolved repository/branch.
- `CheckSuiteHandler#process` (`app/models/shipit/webhooks/handlers/check_suite_handler.rb:13-17`) schedules check-run refreshes scoped by the same `full_name`-derived `stacks`.
- `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) is worse: it looks up commits with **no repository scoping whatsoever** — `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — so any commit sha in the entire Shipit instance can receive an attacker-chosen `state`/`context`/`target_url`/`description`.

The HMAC signature only proves the raw body was signed with the secret belonging to whichever organization name appears in `repository.owner.login` of that same body — a field the attacker fully controls when constructing the payload. It does not bind that organization to the `full_name`/`sha` values the handlers actually act on. This is the direct analog of the reported bug: the code validates one field (`msg.value`/here, `owner.login`-derived signature) while acting on another, unvalidated field (`currency`-bound funds/here, `full_name`/`sha`).

### Impact Explanation
An attacker who is a legitimate customer/tenant of a multi-organization Shipit deployment (per `docs/setup.md` "Using Multiple Github Applications", each org gets its own `webhook_secret` in `config/secrets.yml`) knows their own org's webhook secret. Using it they can:
- Inject fabricated commit statuses (`StatusHandler`) for arbitrary commits belonging to a completely different organization's stack, potentially satisfying `required_statuses`/`blocking_statuses` used by `Commit#deployable?` (`app/models/shipit/commit.rb:227-229`) and unblocking or triggering continuous deployment (`schedule_continuous_delivery`, `app/models/shipit/commit.rb:281-287`) for a victim's stack — i.e., contributing to an unauthorized deploy.
- Force `sync_github` calls on a victim's stacks/branches (`PushHandler`) and trigger check-run refresh jobs against arbitrary victim commits (`CheckSuiteHandler`).

This crosses the "organization that authenticated versus the repository that is written" trust boundary and can materially influence deploy gating decisions on a repository the attacker has no legitimate access to.

### Likelihood Explanation
Requires only that the attacker control one legitimately configured GitHub App/organization in the same multi-tenant Shipit instance (a standard supported configuration per the docs) and be able to POST directly to the public `/webhooks` endpoint with a correctly HMAC-signed body — no Shipit session, ApiClient token, or stolen secret from another org is needed, only knowledge of their own org's secret. The webhook endpoint is unauthenticated aside from the signature check, so likelihood is high in any deployment serving more than one GitHub organization.

### Recommendation
Bind signature verification to the same field the handlers act on: derive `repository_owner` for secret selection consistently from `repository.full_name`'s owner segment (or vice versa), and reject the request if `repository.owner.login` does not match the owner parsed from `repository.full_name`. For `StatusHandler`, scope the `Commit` lookup by the resolved `Repository`/`Stack` (via `stacks`) rather than a bare global `Commit.where(sha:)`.

### Proof of Concept
1. Configure Shipit with two orgs in `config/secrets.yml` (`attacker-org`, `victim-org`), each with its own `webhook_secret`, as documented in `docs/setup.md:182-209`.
2. As the legitimate owner of `attacker-org`'s GitHub App, compute `HMAC-SHA1(attacker_secret, body)` over a hand-crafted JSON body:
```json
{
  "sha": "<victim-commit-sha>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
}
```
3. `POST /webhooks` with header `X-Github-Event: status` and `X-Hub-Signature: sha1=<computed>`.
4. `verify_signature` looks up `Shipit.github(organization: "attacker-org")` and verifies successfully because the attacker signed with `attacker-org`'s real secret.
5. `Shipit::Webhooks.for_event('status')` dispatches to `StatusHandler`, which runs `Commit.where(sha: "<victim-commit-sha>")` — with no ownership check — and calls `create_status_from_github!`, injecting a fabricated `success` status onto the victim's commit.