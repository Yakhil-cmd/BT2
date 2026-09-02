### Title
Cross-organization Team hijack via unscoped `Team.find_or_create_by!(github_id:)` in `MembershipHandler` - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`MembershipHandler#find_or_create_team!` looks up `Shipit::Team` by `github_id` alone, without scoping to the organization the webhook claims to originate from. An attacker who controls their own GitHub organization (registered with Shipit and thus able to produce validly-signed `membership` webhooks) can forge a payload whose `team.id` matches the `github_id` of a pre-existing `Team` belonging to a *different* organization, and get themselves added as a member of that team via `team.add_member(member)`. If that team is one of `Shipit.github_teams`, this grants `User#authorized?` to an attacker who was never actually a member of the victim org's team.

### Finding Description
The broken binding: the code assumes `params.team.id == <the github_id of a team that belongs to params.organization.login>`, but nothing enforces that equality.

Path: `WebhooksController#create` (`app/controllers/shipit/webhooks_controller.rb:10-15`) dispatches the raw JSON body to `Shipit::Webhooks::Handlers::MembershipHandler.call`. Signature verification (`verify_signature`, lines 24-49) only checks that the HMAC signature matches the `webhook_secret` configured for `repository_owner` (derived from `params.dig('organization','login')` for membership events, line 61) — i.e., it proves the request came from *an* org the attacker controls/administers, not that the `team.id` inside the payload actually belongs to that org.

`MembershipHandler#find_or_create_team!` (`app/models/shipit/webhooks/handlers/membership_handler.rb:38-43`):
```ruby
def find_or_create_team!
  Team.find_or_create_by!(github_id: params.team.id) do |team|
    team.github_team = params.team
    team.organization = params.organization.login
  end
end
```
This performs `find_by(github_id:)` with no `organization:` scope. If a `Team` row with that `github_id` already exists (created earlier from a legitimate `membership` event for a different, victim organization), it is returned unchanged — the block (which would set `organization` to the attacker's org) never runs because the record already exists. `process` (lines 22-33) then calls `team.add_member(member)`, appending `User.find_or_create_by_login!(params.member.login)` — a user record for the attacker's own GitHub login — to that pre-existing (victim) team's `members`.

Exploit flow:
1. Attacker registers/owns an org `attacker-org`, configured in Shipit with its own webhook secret (a normal, legitimate Shipit-recognized org).
2. Attacker learns or guesses the numeric GitHub `id` of a team belonging to a different org that Shipit already knows about (team ids are visible via GitHub's public API for many teams, or via previously observed webhook traffic; the question's brute-force framing is one way to obtain it, but exact discovery method doesn't change the vulnerable binding).
3. Attacker POSTs to `/webhooks` with `X-Github-Event: membership`, a body `{"action":"added","team":{"id": <victim_team_github_id>, ...},"organization":{"login":"attacker-org"},"member":{"login":"attacker-login"}}`, signed with `attacker-org`'s own valid webhook secret.
4. `verify_signature` passes (valid signature for `attacker-org`).
5. `find_or_create_team!` finds the existing victim `Team` row by `github_id` and returns it, ignoring the mismatch with `params.organization.login`.
6. `team.add_member` adds the attacker's user as a member of the victim's team.
7. If that team is among `Shipit.github_teams` (used in `User#authorized?`, `app/models/shipit/user.rb:80-82`), the attacker becomes `authorized?` in Shipit — an authorization escalation.

Existing guards do not stop this: `verify_signature` only authenticates the org, not the team-to-org binding; `ExplicitParameters` only validates types (`Integer`, `String`), not ownership; there is no model validation tying `Team#organization` to `Team#github_id` uniqueness per-org, nor any check in `find_or_create_team!` that a found team's `organization` matches `params.organization.login`.

### Impact Explanation
An attacker who administers any Shipit-registered organization can, without any GitHub secrets from the victim, insert themselves as a member of a pre-existing `Shipit::Team` belonging to another organization. If that team is configured in `Shipit.github_teams`, this directly escalates the attacker into Shipit's authorization set (`User#authorized?`), potentially granting them deploy/rollback/merge rights across stacks that check that authorization. This matches the High severity category ("escalation into `Shipit.github_teams` authorization"). It is repeatable for any team whose `github_id` the attacker can learn, and blast radius spans any tenant/org configured in the same Shipit instance since `Team` records are not partitioned by organization in this lookup.

### Likelihood Explanation
Preconditions: the attacker must control at least one org that is registered/valid in Shipit (able to produce a validly-signed webhook) — realistic in multi-tenant Shipit-as-a-service deployments where any GitHub org can self-onboard. The attacker must also know or guess a target `Team`'s numeric GitHub `id`, which is metadata that GitHub often exposes (team URLs/API responses) and is not treated as secret by GitHub itself, making it plausible rather than purely theoretical. No brute forcing of cryptographic secrets is required — only the numeric team id — so attacker cost is low and the attack is fully repeatable.

### Recommendation
Scope the team lookup by both `github_id` and `organization` (e.g., `Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login)`), and additionally verify on every membership event that an existing team's `organization` matches `params.organization.login` before proceeding, raising/dropping the event on mismatch instead of silently reusing the existing record.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/membership_handler_test.rb (conceptual)
test "membership event cannot hijack a team belonging to another organization" do
  victim_team = Shipit::Team.create!(
    github_id: 999, organization: 'victim-org', slug: 'victim-team', name: 'Victim Team', api_url: 'https://x'
  )

  payload = {
    'action' => 'added',
    'team' => { 'id' => 999, 'name' => 'Fake', 'slug' => 'fake', 'url' => 'https://x' },
    'organization' => { 'login' => 'attacker-org' },
    'member' => { 'login' => 'attacker-login' }
  }

  Shipit::User.stubs(:find_or_create_by_login!).with('attacker-login').returns(Shipit::User.create!(login: 'attacker-login', name: 'Attacker'))

  Shipit::Webhooks::Handlers::MembershipHandler.call(payload)

  refute_includes victim_team.reload.members.map(&:login), 'attacker-login',
    "attacker was added to a team belonging to a different organization"
  # Equality claimed broken: params.organization.login ('attacker-org') != found_team.organization ('victim-org'),
  # yet find_or_create_team! returned the victim team and add_member succeeded regardless.
end
```