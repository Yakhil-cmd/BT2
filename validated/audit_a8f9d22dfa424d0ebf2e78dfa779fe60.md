### Title
Team.github_id collision allows cross-organization membership mutation via signed webhook - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`Shipit::WebhooksController#verify_signature` authenticates the webhook only against the organization named in the payload (`repository_owner`), while `MembershipHandler#find_or_create_team!` resolves the target `Team` row solely by `github_id`, with no re-check that the found team's `organization` matches the payload's organization. If a `Team` row with a given `github_id` was already created for organization B, an attacker who legitimately controls organization A (and thus its real `webhook_secret`) can send a signed `membership` webhook naming A but reusing B's `team.id`, causing the existing org‑B `Team` to be mutated (member added/removed).

### Finding Description
The broken binding: the code must guarantee `organization_that_signed_the_payload == organization_owning_the_mutated_team_row`, i.e. `repository_owner (from verify_signature) == team.organization (row mutated by find_or_create_team!)`. This binding is not enforced.

- `Shipit::WebhooksController#verify_signature` (app/controllers/shipit/webhooks_controller.rb:24-49) derives `repository_owner` from `params.dig('organization', 'login')` and verifies the HMAC signature using `Shipit.github(organization: repository_owner)`'s secret. This only proves the request was signed with organization A's secret — it says nothing about which `Team` records may legitimately be touched.
- `MembershipHandler#find_or_create_team!` (app/models/shipit/webhooks/handlers/membership_handler.rb:38-43) does:
```ruby
Team.find_or_create_by!(github_id: params.team.id) do |team|
  team.github_team = params.team
  team.organization = params.organization.login
end
```
The block (which sets `organization`) only executes on **create**. When `github_id: 999` already matches an existing row (created previously for org‑B), `find_or_create_by!` returns that existing row unchanged — `organization` is never re-validated or re-assigned to org‑A. `process` (lines 22-34) then calls `team.add_member(User.find_or_create_by_login!(params.member.login))`, mutating org‑B's team membership using a payload signed only by org‑A.
- Nothing in the `ExplicitParameters` schema (`params do ... end`) or in `Team#github_team=` (app/models/shipit/team.rb:53-58) cross-checks `organization` against the existing row before find; `Team` has no uniqueness validation or DB-level scoping of `github_id` to `organization`.

Attacker request: `POST /webhooks` with header `X-Github-Event: membership`, signed with org‑A's real webhook secret, body:
```json
{"organization":{"login":"org-A"},"team":{"id":999,"name":"n","slug":"s","url":"u"},"member":{"login":"victim-user"},"action":"added"}
```
where `999` is the `github_id` of a pre-existing `Team` row belonging to `org-B`. `verify_signature` passes (org‑A's secret is valid for org‑A), `drop_unhandled_event`/`check_if_ping` do not block it, and `find_or_create_team!` returns org‑B's team, into which `victim-user` is added.

### Impact Explanation
The attacker (who owns/controls only org‑A) can inject or remove members of org‑B's `Team` without ever authenticating as org‑B or possessing org‑B's webhook secret. Since `Shipit.github_teams` and `User#authorized?` (app/models/shipit/user.rb) can gate operator/authorization status on team membership, this can escalate an attacker-controlled GitHub account into privileged Shipit roles associated with a victim organization's team — a cross-tenant authorization/state mutation. This matches the Critical category: "a payload for one repository/organization mutating another's ... team," with potential further escalation into `Shipit.github_teams` authorization (High/Critical blast radius). The attack is repeatable for any `github_id` value the attacker can guess or observe (team IDs are often discoverable/sequential on GitHub), and repeatable against multiple victim teams with a single crafted request each.

### Likelihood Explanation
Preconditions: (1) the target `Team.github_id` must already exist in Shipit's DB for the victim org (true for any org previously synced via `lib/tasks/teams.rake` or prior legitimate webhooks), and (2) the attacker needs a legitimately configured Shipit organization (org‑A) with a known `github_id` collision with org‑B's team — GitHub team IDs are globally unique but not secret, and an attacker can enumerate or is told a target's team ID (e.g., visible via GitHub API/UI to team members, or via prior legitimate org‑B webhook logs if the attacker previously had access). No Shipit secrets beyond the attacker's own org‑A `webhook_secret` are required, and no privileged role is needed — fully within the unprivileged threat model. This is a single, deterministic HTTP POST with no timing dependency, cheap and repeatable.

### Recommendation
In `MembershipHandler#find_or_create_team!`, scope the lookup by both `github_id` and `organization: params.organization.login` (e.g. `Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login)`), and additionally raise/reject if an existing row with that `github_id` belongs to a different organization than the one that signed the request. Add a DB-level uniqueness constraint/index on `(github_id, organization)` (or reject `github_id` collisions across organizations entirely) to prevent silent cross-tenant reuse.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/membership_handler_test.rb (conceptual)
test "membership webhook signed by org-A cannot mutate org-B's team with colliding github_id" do
  victim_team = Shipit::Team.create!(organization: 'org-B', github_id: 999, name: 'n', slug: 's', api_url: 'u')

  payload = {
    'action' => 'added',
    'team' => { 'id' => 999, 'name' => 'n', 'slug' => 's', 'url' => 'u' },
    'organization' => { 'login' => 'org-A' }, # attacker's own org, whose secret they legitimately hold
    'member' => { 'login' => 'victim-user' },
  }

  Shipit::Webhooks::Handlers::MembershipHandler.new(payload).call

  # Binding under test: org that signed (org-A) must equal org owning mutated row (org-B)
  assert_equal 'org-B', victim_team.organization
  refute victim_team.reload.members.exists?(login: 'victim-user'),
    "org-A's signed webhook must not be able to add members to org-B's team"
end
```
This test seeds a `Team` for `org-B` with `github_id: 999`, then invokes the handler with a payload whose `organization.login` is `org-A` (simulating a request that passed `verify_signature` using org-A's secret) but whose `team.id` collides with org-B's row, and asserts that `victim-user` should not end up in org-B's team — demonstrating the cross-tenant mutation when the assertion fails against current code.