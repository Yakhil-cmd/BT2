### Title
Membership webhook verified for one org can write members into another org's `Team` row (github_id collision) - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`MembershipHandler#find_or_create_team!` looks up a `Team` solely by the GitHub-supplied `team.id`, with no check that the row's owning `organization` matches the `organization.login` that the webhook signature was actually verified against. An attacker who controls a GitHub organization with a valid Shipit webhook secret can send a `membership` event whose `team.id` collides with a team belonging to a different organization, and have themselves added as a member of that other organization's team.

### Finding Description
The broken binding, stated as an equality that must hold but isn't checked: `team.organization == params.organization.login` (the organization that produced a passing `verify_webhook_signature`). In `app/controllers/shipit/webhooks_controller.rb#verify_signature`, `repository_owner` is computed as `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`; for `membership` events there is no `repository` key, so `repository_owner` resolves to `params.organization.login` (org B in the attacker's request), and `Shipit.github(organization: repository_owner)` selects org B's app/secret to verify the signature. This only proves the payload came from org B — it says nothing about the `team.id` embedded inside it.

In `app/models/shipit/webhooks/handlers/membership_handler.rb#find_or_create_team!`:
```ruby
def find_or_create_team!
  Team.find_or_create_by!(github_id: params.team.id) do |team|
    team.github_team = params.team
    team.organization = params.organization.login
  end
end
```
The block (which sets `organization`) only executes on the create path of `find_or_create_by!`. If a `Team` with that `github_id` already exists (e.g., created earlier for org A), the existing row is returned untouched — its `organization` remains `org-a`, even though the current request was verified as belonging to `org-b`. `process` then calls `team.add_member(member)` (or `team.members.delete(member)`), mutating org A's team membership based on a signature that only vouches for org B.

Exploit flow:
1. Org A's `membership` webhook fires normally, creating `Team(github_id: 99, organization: 'org-a', ...)`.
2. Attacker, who owns/administers org B (with its own legitimately configured Shipit GitHub App and `webhook_secret`), sends a `membership` webhook: `action: 'added'`, `team: {id: 99, ...}`, `organization: {login: 'org-b'}`, `member: {login: 'attacker'}`, signed with org B's real secret.
3. `verify_signature` passes because it validates against org B's secret using `organization.login == 'org-b'`.
4. `find_or_create_team!` finds the existing `github_id: 99` row (org A's team) and returns it unchanged.
5. `team.add_member(attacker_user)` inserts a `Membership` linking the attacker to org A's team.

No existing guard prevents this: `verify_signature` only authenticates the sender's organization, not the payload's `team.id`/`organization` consistency with stored records; there is no model validation on `Team` tying `github_id` to `organization` beyond initial creation; `ExplicitParameters` only validates shape/types, not cross-tenant ownership.

### Impact Explanation
A GitHub `team.id` is an attacker-influenceable value from the attacker's own organization's perspective is not colliding by attacker choice (`team.id` is assigned by GitHub, not chosen by the org owner), but GitHub team IDs are global sequential integers and organizations cannot control them — however an attacker can still probe/guess IDs of teams already registered in Shipit (they can be observed via existing memberships, prior legitimate webhooks, or informed guessing/brute force since they are monotonically increasing integers), then have their own org emit a colliding `team.id`. Once a match lands, the attacker gains membership in `Shipit.github_teams`-relevant `Team` objects belonging to a different tenant, which is used elsewhere in the app for authorization (`Shipit.github_teams`). This is a cross-tenant authorization escalation: an attacker who is a legitimate operator of org B's GitHub App can write into org A's `Team`/`Membership` records without any credential belonging to org A. It's repeatable against any `github_id` the attacker can guess/observe.

### Likelihood Explanation
Preconditions: attacker needs a real GitHub organization with a Shipit GitHub App configured for it (achievable by any GitHub user who can register a GitHub App and have Shipit configured for them, or by any attacker who already runs one org's Shipit integration) — this is exactly the class of "unprivileged" attacker described (owns a repo/org, no Shipit session/secrets for the victim org). The remaining requirement is guessing/knowing a `team.id` that already exists as a `Shipit::Team` row for a different org, which is feasible since team IDs are sequential and often discoverable (e.g., via GitHub org's public team pages if not private, or via previously observed Shipit behavior). This is a realistic, repeatable attack once the ID is known.

### Recommendation
In `find_or_create_team!`, always re-validate/update the `organization` on every event, or reject the event if the found team's `organization` doesn't match `params.organization.login`:
```ruby
def find_or_create_team!
  team = Team.find_or_create_by!(github_id: params.team.id) do |team|
    team.github_team = params.team
    team.organization = params.organization.login
  end
  raise Shipit::WebhooksController::UnauthorizedTeamOrganization if team.organization != params.organization.login
  team
end
```
and have `process` (or the controller) drop the event with 422 rather than raising an unhandled error, mirroring the `GithubOrganizationUnknown` handling pattern already in `verify_signature`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/membership_handler_test.rb
test "membership webhook verified for org-b cannot mutate a team owned by org-a" do
  team_a = shipit_teams(:org_a_team) # github_id: 99, organization: 'org-a'
  attacker = shipit_users(:attacker)

  payload = {
    'action' => 'added',
    'team' => { 'id' => team_a.github_id, 'name' => 'org-a-team', 'slug' => 'org-a-team', 'url' => 'https://api.github.com/teams/99' },
    'organization' => { 'login' => 'org-b' },
    'member' => { 'login' => attacker.login },
  }

  Shipit::Webhooks::Handlers::MembershipHandler.new(payload.deep_symbolize_keys).call

  # Binding under test: team.organization (owner of mutated row) must equal
  # the org that verified the webhook signature (params.organization.login)
  assert_equal 'org-a', team_a.organization           # unauthorized mutation target
  refute_equal 'org-b', team_a.organization            # signature was verified for org-b

  refute Shipit::Membership.exists?(team: team_a, user: attacker),
    "attacker from org-b should not be added to org-a's team"
end
```
This currently fails (membership is created), demonstrating the cross-organization write.