### Title
Forged `membership` webhook for an org configured without `webhook_secret` allows attacker-controlled `Team`/`Membership` writes that feed `User#authorized?` - (File: `lib/shipit/github_app.rb`, `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`GitHubApp#verify_webhook_signature` unconditionally returns `true` when the resolved organization's config has no `webhook_secret`, so any `POST /webhooks` body claiming `repository.owner.login`/`organization.login` for such an org is accepted with zero authentication. `MembershipHandler` then trusts `params.team.id`, `params.organization.login`, `params.member.login` from that unauthenticated body to find-or-create a `Team` and mutate `Membership` rows that `User#authorized?` reads globally.

### Finding Description
Binding that should hold: `webhook accepted for org O` ⇒ `HMAC-SHA1(webhook_secret_O, raw_body) == X-Hub-Signature`. In `lib/shipit/github_app.rb:76-83`:
```
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
```
`@webhook_secret = @config[:webhook_secret].presence` (line 50). If the org config for `repository_owner`/`organization.login` omits `webhook_secret`, `verify_webhook_signature` returns `true` for *any* body/signature — the equality above collapses to `accepted == true` independent of `HMAC`.

`Shipit::WebhooksController#verify_signature` (lines 24-30) resolves the org via `Shipit.github(organization: repository_owner)` where `repository_owner` is taken straight from the attacker-controlled JSON body (`params.dig('repository','owner','login')` or `params.dig('organization','login')`, line 59-62). As long as that org string matches one that is `github_app_config`-configured in `secrets.github` (a legitimate, pre-existing org) but happens to have no `webhook_secret` key, the forged request sails through `verify_signature` and `check_if_ping`/`drop_unhandled_event`.

`MembershipHandler#process` (app/models/shipit/webhooks/handlers/membership_handler.rb:22-34) then:
- `find_or_create_team!` does `Team.find_or_create_by!(github_id: params.team.id) { ... team.organization = params.organization.login }` — both attacker-supplied.
- `User.find_or_create_by_login!(params.member.login)` creates/finds a `User` by attacker-supplied login.
- On `action == 'added'`, calls `team.add_member(member)`, writing a `Membership` row (`app/models/shipit/team.rb:41-43`).

`User#authorized?` (`app/models/shipit/user.rb:80-82`) is global, not stack-scoped:
```
@authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
```
`Shipit.github_teams` (`lib/shipit.rb:256-258`) is a fixed, application-wide list of `Team` records resolved once from `oauth.teams` config. If the attacker supplies `params.team.id` equal to the `github_id` of one of these pre-existing privileged `Team` rows (team IDs on GitHub are frequently discoverable via the public `/orgs/:org/teams` API or already known if the org is public), the forged `membership` event inserts a `Membership` linking an attacker-controlled `User` to that privileged `Team`. The very next call to `authorized?` for that user returns `true`, granting authorization across the entire Shipit instance — not just the misconfigured org's stacks.

No other guard intervenes: `drop_unhandled_event` only checks the event type is registered; `ExplicitParameters` (the `params do ... end` schema) only validates shape/types, not provenance; there is no per-stack or per-repository scoping check anywhere in `MembershipHandler` or `Team`/`Membership`.

### Impact Explanation
An attacker who identifies (or forces the operator to create) one legitimately-configured GitHub organization in Shipit whose config omits `webhook_secret` can forge a `membership` webhook and insert a `Membership` row tying any attacker-chosen `User` (login of their own choosing) to any pre-existing `Team` whose `github_id` is known, including teams that are part of `Shipit.github_teams`. This is a direct authentication/authorization bypass: the attacker's OAuth-authenticated Shipit session for that fabricated login will pass `User#authorized?` and gain access to protected actions across all stacks/repositories managed by the instance, not just the misconfigured org's. This matches the "High - escalation into `Shipit.github_teams` authorization" category (and edges toward Critical since it is a full authorization bypass), and is repeatable indefinitely (`action: 'removed'` can also be used to deauthorize arbitrary legitimate users by deleting their `Membership`).

### Likelihood Explanation
Preconditions: (1) at least one org configured in `secrets.github` without a `webhook_secret` — a real-world, plausible misconfiguration since the code explicitly supports and silently tolerates it (`return true unless webhook_secret`); (2) `Shipit.github_teams` non-empty (i.e., the instance uses team-based authorization, a common and recommended setup); (3) attacker knows/guesses the numeric `github_id` of a privileged team (often discoverable via GitHub's public team-listing API for public teams, or via any prior interaction). No Shipit session, token, or secret is required — only the ability to send an unauthenticated `POST /webhooks` request with the correct `X-Github-Event: membership` header and a crafted JSON body, and to control the GitHub login used as `params.member.login`.

### Recommendation
Do not treat a missing `webhook_secret` as "verified" — either reject webhooks for orgs without a configured secret (`head(422)` unconditionally when `webhook_secret` is blank) or require operators to always configure a secret and fail startup/config validation otherwise. Additionally, scope `MembershipHandler`'s `Team`/`Membership` writes and `User#authorized?`'s team check to verify the event's organization matches the `Team#organization` already on record, and consider binding authorization decisions to data fetched from GitHub's API (not raw webhook payload) for security-sensitive state changes.

### Proof of Concept
Minitest plan (under `test/controllers/webhooks_controller_test.rb` or `test/models/shipit/webhooks/handlers/membership_handler_test.rb`, following existing "no-secret organization" test conventions in `webhooks_controller_test.rb`):
1. Configure `Shipit.github_app_config`/stub `secrets.github` so org `"acme"` exists with no `webhook_secret` key, while some other org has one — mirroring existing "no-secret organization" fixtures used elsewhere in `test/controllers/webhooks_controller_test.rb`.
2. Create fixture `team = shipit_teams(:some_privileged_team)` with a known `github_id`, and stub `Shipit.github_teams` to include it.
3. Assert baseline: `user = Shipit::User.create!(login: 'attacker', name: 'attacker')`; `assert_not user.authorized?`.
4. POST to `/webhooks` with header `X-Github-Event: membership`, no/garbage `X-Hub-Signature`, and body:
```json
{
  "action": "added",
  "team": { "id": <team.github_id>, "name": "...", "slug": "...", "url": "..." },
  "organization": { "login": "acme" },
  "member": { "login": "attacker" }
}
```
5. Assert response is `200 OK` (not `422`) — proving `verify_webhook_signature` accepted the unsigned forged request.
6. Reload `user`; assert `Shipit::Membership.exists?(team_id: team.id, user_id: user.id)`.
7. Assert `user.reload.authorized?` is now `true`, demonstrating the equality "membership only affects the repo/org that authenticated it" is broken: an org with no secret let an attacker escalate a user into `Shipit.github_teams`-gated authorization instance-wide.