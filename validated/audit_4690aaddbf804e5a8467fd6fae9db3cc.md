### Title
`MembershipHandler#find_or_create_team!` mutates existing teams by `github_id` collision without verifying webhook-authenticating organization matches `Team#organization` - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`WebhooksController#verify_signature` only proves that the webhook's `organization.login` (or `repository.owner.login`) owns the `webhook_secret` used to sign the payload; it does not bind that organization to any specific `Team` record. `MembershipHandler#find_or_create_team!` uses `Team.find_or_create_by!(github_id: params.team.id)`, and the `organization=` assignment only runs inside the creation block, so if `params.team.id` collides with an existing `Team#github_id` belonging to a different organization, the existing (victim) team is fetched and then mutated via `team.add_member(member)` with no re-check that the authenticating organization matches `team.organization`.

### Finding Description
The required binding is: `repository_owner` (i.e., `params.organization.login`, the org whose `webhook_secret` signed the request, verified in `app/controllers/shipit/webhooks_controller.rb:24-30,59-62`) must equal `Team#organization` for whichever `Team` row `add_member`/`members.delete` mutates.

Trace:
1. `verify_signature` computes `github_app = Shipit.github(organization: repository_owner)` and calls `github_app.verify_webhook_signature(...)` (`app/controllers/shipit/webhooks_controller.rb:24-30`). This only proves the payload was signed with the secret configured for `repository_owner` — the attacker's own organization, since they legitimately configured a GitHub App/webhook on their own org.
2. `MembershipHandler` schema requires `organization.login`, `team.id`, `team.name/slug/url`, `member.login` (`app/models/shipit/webhooks/handlers/membership_handler.rb:7-21`) — nothing ties `team.id` to `organization.login`.
3. `find_or_create_team!` calls `Team.find_or_create_by!(github_id: params.team.id) { |team| team.github_team = params.team; team.organization = params.organization.login }` (`app/models/shipit/webhooks/handlers/membership_handler.rb:38-43`). Per ActiveRecord semantics, the block runs **only when a new record is created**. If a `Team` row with `github_id == params.team.id` already exists (e.g., a victim team from a different organization), `find_or_create_by!` returns that existing record untouched by the block — `team.organization` remains the victim's original organization, but the object returned is still handed to `team.add_member(member)` (`app/models/shipit/webhooks/handlers/membership_handler.rb:23,28`) with `params.action == 'added'`.
4. `Team#add_member` (`app/models/shipit/team.rb:41-43`) does `members.append(member) unless members.include?(member)`, creating a `Membership` row linking `member` (an attacker-controlled `User`, created via `User.find_or_create_by_login!(params.member.login)`) to the victim `Team`.

Exploit flow: the attacker configures a GitHub App/webhook on their own organization (a normal, unprivileged action for anyone who owns a GitHub org), obtaining a valid `webhook_secret` for `repository_owner = "attacker-org"`. They send a `membership` `added` event to `POST /webhooks` with `organization.login = "attacker-org"` (satisfying `verify_signature`), `team.id` set to the numeric `github_id` of a known/victim `Shipit::Team` (team `github_id`s are often discoverable/guessable GitHub team IDs), and `member.login` equal to an attacker-controlled GitHub username. `verify_signature` passes because the signature is valid for the attacker's own org. `find_or_create_team!` finds the pre-existing victim team by `github_id` and skips organization assignment. `team.add_member` then adds the attacker's `User` as a `Membership` on the victim's team, without any check that `attacker-org == victim_team.organization`.

Existing guards don't stop this: `verify_signature` only authenticates the org matching `Shipit.github(organization: repository_owner)`'s configured secret, and never checks it against the `Team` being written; `ExplicitParameters` schema validates types/presence, not cross-field consistency; there's no `require_permission!`/`current_user` check in this controller at all since it's an unauthenticated webhook endpoint gated purely by signature.

### Impact Explanation
This directly escalates an attacker-controlled `User` into membership of an arbitrary victim `Shipit::Team`, matching the listed High-severity category "escalation into `Shipit.github_teams` authorization." `Shipit.github_teams`-backed teams commonly gate deploy/stack permissions (`User#authorized?`/`require_permission!` flows reference team membership), so this can let an attacker who merely owns their own GitHub org and knows/guesses a victim team's numeric GitHub team ID silently join a privileged team used for authorization decisions on the Shipit instance — a cross-tenant privilege escalation reachable from an unauthenticated HTTP endpoint (`POST /webhooks`). It's repeatable against any team whose `github_id` the attacker can determine (GitHub team IDs are not secret and are often exposed via the GitHub API/UI to org members).

### Likelihood Explanation
Preconditions: Shipit must be configured to accept webhooks from more than one organization (multi-tenant `Shipit.github` config, which is the documented deployment model), and the attacker must control at least one such organization (to obtain a legitimate `webhook_secret`) and know the target `Team#github_id`, which is a non-secret GitHub team ID. Cost is low: no Shipit credentials, no privileged GitHub App installation on the victim org, just a single crafted signed HTTP POST. This is highly feasible and repeatable per victim team ID.

### Recommendation
In `MembershipHandler#find_or_create_team!`, after fetching/creating the team, verify `team.organization == params.organization.login` before proceeding with `add_member`/`members.delete`; if it doesn't match, drop/reject the event (e.g., raise or no-op with a log) rather than mutating the record. More generally, any handler that does `find_or_create_by!` keyed on a GitHub-provided ID should re-validate the authenticating organization against the resolved record's `organization` on every invocation, not only at creation time.

### Proof of Concept
In `test/models/shipit/webhooks/handlers/membership_handler_test.rb` (or `test/controllers/webhooks_controller_test.rb`):
1. Create a victim `Team` fixture: `victim_team = Shipit::Team.create!(github_id: 4242, organization: 'victim-org', name: 'Owners', slug: 'owners', api_url: 'https://api.github.com/teams/4242')`.
2. Ensure `Shipit.github(organization: 'attacker-org')` is configured in test with a known `webhook_secret` (e.g., via `Shipit.github_configs`/stub as done elsewhere in `webhooks_controller_test.rb`).
3. POST to `/webhooks` with header `X-Github-Event: membership`, body:
```json
{
  "action": "added",
  "team": {"id": 4242, "name": "Owners", "slug": "owners", "url": "https://api.github.com/teams/4242"},
  "organization": {"login": "attacker-org"},
  "member": {"login": "attacker-user"}
}
```
signed with `attacker-org`'s `webhook_secret` in `X-Hub-Signature`.
4. Assert the request returns `200 OK` (i.e., `verify_signature` passed for `attacker-org`).
5. Assert the binding equality fails and no mutation occurred: `victim_team.reload.organization == 'attacker-org'` should be **false** (it stays `'victim-org'`), and `victim_team.members.exists?(login: 'attacker-user')` should be **false**. Currently (bug present) this assertion fails because `add_member` does add the attacker's user to `victim_team`.