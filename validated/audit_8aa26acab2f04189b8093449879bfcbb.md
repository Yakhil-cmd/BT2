### Title
Cross-organization `Team` membership mutation via `membership` webhook missing organization/team ownership check - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`MembershipHandler#find_or_create_team!` looks up a `Team` solely by `params.team.id` (the GitHub team's numeric ID), and only sets `team.organization = params.organization.login` inside the `find_or_create_by!` create block. When the team already exists (the common case for any pre-existing, real Team record such as one listed in `Shipit.github_teams`), the block never runs, so the organization binding is never checked, yet `process` still calls `team.add_member(member)` / `team.members.delete(member)` on that pre-existing Team. Any attacker who controls a legitimately configured Shipit tenant (org) can sign a `membership` webhook for their own org and use it to add or remove members on a `Team` that actually belongs to a different, victim organization, as long as they know or guess that team's numeric GitHub `id`.

### Finding Description
The broken binding, stated as an equality that should hold but doesn't: `team.organization == params.organization.login` should be true for every mutation path in `MembershipHandler#process`, but it is only enforced when a `Team` row is newly created — never when one is found.

Code path:
1. `WebhooksController#create` (app/controllers/shipit/webhooks_controller.rb:10-15) parses the raw JSON body and dispatches it, unmodified, to `MembershipHandler.call(params)`.
2. `verify_signature` (app/controllers/shipit/webhooks_controller.rb:24-49) resolves the signing app via `repository_owner`, which for a `membership` event (no `repository` key) falls back to `params.dig('organization', 'login')` (app/controllers/shipit/webhooks_controller.rb:59-62). Because the attacker owns that org and can generate a correctly signed payload for it, `verify_webhook_signature` succeeds — the signature check validates *that the request came from the named organization*, not that the payload's *content* is scoped to that organization.
3. `Handler#initialize`/`.call` (app/models/shipit/webhooks/handlers/handler.rb:15-24) just parses params against the `ExplicitParameters` schema; the schema for `MembershipHandler` (app/models/shipit/webhooks/handlers/membership_handler.rb:7-21) only requires `organization.login` to be a String — it does not cross-check it against the request's signing tenant, and there is no `repository`-based scoping at all for this handler (the base `Handler#stacks`/`repository_name` helpers, app/models/shipit/webhooks/handlers/handler.rb:32-38, aren't even used here).
4. `MembershipHandler#process` (app/models/shipit/webhooks/handlers/membership_handler.rb:22-34) calls `find_or_create_team!` (lines 38-43):
   ```ruby
   Team.find_or_create_by!(github_id: params.team.id) do |team|
     team.github_team = params.team
     team.organization = params.organization.login
   end
   ```
   `find_or_create_by!` first performs a `find_by(github_id: ...)`. If a Team with that `github_id` already exists — e.g., a legitimate victim Team belonging to a different org — the block is skipped entirely, so `team.organization` is left as the victim's original value and is never compared to `params.organization.login`.
5. Back in `process`, `team.add_member(member)` or `team.members.delete(member)` (app/models/shipit/webhooks/handlers/membership_handler.rb:27-30) executes against that found (victim) `Team`, regardless of which organization actually sent the webhook.

Exploit flow: attacker registers/controls org `attacker-org` as a real Shipit tenant. They discover (or already know, e.g. because GitHub team pages/URLs and `github_id`s are frequently enumerable, or from prior legitimate interaction) the numeric `github_id` of a `Team` record tied to a victim org (potentially one listed in `Shipit.github_teams`, used for authorization gating in `User#authorized?`, app/models/shipit/user.rb:80-82). They POST to `/webhooks` with header `X-Github-Event: membership` and a body such as:
```json
{
  "action": "added",
  "team": { "id": <victim_team_github_id>, "name": "x", "slug": "x", "url": "https://api.github.com/teams/x" },
  "organization": { "login": "attacker-org" },
  "member": { "login": "attacker-user" }
}
```
signed with `attacker-org`'s legitimate webhook secret (which the attacker owns as an operator of that real tenant). `verify_signature` resolves and validates against `attacker-org` and passes. `find_or_create_team!` finds the pre-existing victim `Team` by `github_id` and skips the organization-setting block. `team.add_member(User.find_or_create_by_login!('attacker-user'))` runs, adding the attacker's own Shipit `User` to the victim's `Team`.

Existing guards do not catch this: `verify_signature` only authenticates *which organization* sent the request, not that the *payload content* (team id) belongs to that organization; `drop_unhandled_event` and `ExplicitParameters` only check event routing and payload shape, not tenant/team ownership; there is no `require_permission!`/`stacks`-scope check in this handler at all.

### Impact Explanation
If the targeted `Team` is one of the teams configured in `Shipit.github_teams`, this lets an attacker who only controls an unrelated, legitimately configured org silently add themselves (or remove legitimate members) to/from that privileged `Team`, and thereby pass `User#authorized?` (app/models/shipit/user.rb:80-82) and gain access to the whole Shipit application/deploy UI as if they were a real member of the victim's authorized team — an unauthorized escalation into `Shipit.github_teams` authorization. Even absent that specific team, this is a cross-tenant data-integrity bypass: a payload signed for org A mutates a `Team` record that belongs to org B. The attack is repeatable against any Team github_id the attacker can enumerate, for as many additions/removals as desired.

### Likelihood Explanation
Preconditions: the attacker must control at least one org that is a real, correctly configured Shipit tenant (has a `GithubApp`/webhook secret) — stated as a given precondition — and must know (or successfully guess) the target `Team`'s GitHub numeric `id`, which is often discoverable via public GitHub API/team pages or from prior interactions with the victim org. No Shipit session, API token, or GitHub App private key of the victim is required. The attacker cost is a single signed HTTP POST per mutation, fully repeatable and scriptable.

### Recommendation
Enforce the organization/team-ownership binding on both branches of `find_or_create_by!`: after finding or creating the `Team`, verify `team.organization == params.organization.login` (case-insensitively, matching existing normalization) before performing any membership mutation, and raise/drop the event (e.g., respond 422 or silently ignore) if they don't match. Alternatively, look the Team up by `github_id: params.team.id, organization: params.organization.login` instead of `github_id` alone, so a mismatched org never resolves to an existing victim `Team`.

### Proof of Concept
In `test/models/webhooks/handlers/membership_handler_test.rb` (or equivalent), add a minitest test:
1. Create a victim `Team` with `github_id: 999`, `organization: 'victim-org'`, and no members.
2. Build a `membership` payload with `team.id: 999`, `organization.login: 'attacker-org'`, `member.login: 'attacker-user'`, `action: 'added'` — omit any `repository` key.
3. Call `Shipit::Webhooks::Handlers::MembershipHandler.call(payload)` directly (bypassing signature verification, which is orthogonal to this handler-level bug) or through `WebhooksController#create` with a valid signature computed for `attacker-org`'s configured secret.
4. Assert: before the call, `victim_team.organization == 'victim-org'` and `victim_team.members.reload` is empty.
5. After the call, assert `victim_team.reload.organization` is still `'victim-org'` (unchanged — proving the equality `team.organization == params.organization.login` was never true) while `victim_team.members.reload.map(&:login)` now includes `'attacker-user'` — proving the cross-org mutation succeeded despite the mismatched organization.