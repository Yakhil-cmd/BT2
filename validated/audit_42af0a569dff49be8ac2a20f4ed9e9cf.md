### Title
Membership webhook can add attacker as member of an unrelated organization's `Team` via `github_id` collision - (File: `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`MembershipHandler#find_or_create_team!` looks up `Team` records by `github_id` alone with `find_or_create_by!`, and the block that sets `team.organization` only executes on record creation, never on lookup of a pre-existing row. Because GitHub team IDs are sequential/enumerable integers, an attacker who administers their own GitHub organization (with the Shipit GitHub App installed) can trigger a legitimately-signed `membership` webhook whose `team.id` collides with the `github_id` of a `Team` already stored for an unrelated organization, causing the attacker to be added as a member of that unrelated team.

### Finding Description
The broken binding is: `Team.find(by: github_id).organization == params.organization.login` — this equality is never enforced after the initial row is created.

Code path:
- `app/models/shipit/webhooks/handlers/membership_handler.rb:38-43`:
```ruby
def find_or_create_team!
  Team.find_or_create_by!(github_id: params.team.id) do |team|
    team.github_team = params.team
    team.organization = params.organization.login
  end
end
```
`find_or_create_by!` first performs a `find_by(github_id: params.team.id)`. If a row already exists (created earlier for a different organization, e.g. Org A), that row is returned as-is; the block (which sets `organization`) is skipped entirely — it only runs for newly-created records. `process` then does `team.add_member(member)` for `action == 'added'` [1](#0-0) , mutating the pre-existing Org A team using data ostensibly describing an Org B event.

Signature verification does not close this gap. `WebhooksController#verify_signature` resolves the GitHub App/secret to check against using `repository_owner`, which for events without a `repository` key (like `membership`) falls back to `params.dig('organization', 'login')` [2](#0-1) . This means the payload is verified as an authentic webhook **from the organization named in that same payload** (Org B) — it proves the request truly came from GitHub for Org B, but it does nothing to prevent the `team.id` field inside that authentic Org B payload from numerically colliding with an already-persisted Org A `Team.github_id`.

Attacker exploit flow:
1. Attacker administers (or is a member with team-management rights in) their own GitHub organization "OrgB", which has the Shipit GitHub App installed and configured with a real webhook secret known to GitHub/Shipit (not to the attacker).
2. Attacker performs a legitimate action in OrgB — adds themselves to a team — causing GitHub to emit a correctly-signed `membership` `action: added` webhook with `organization.login = "OrgB"` and `team.id` equal to some enumerable integer.
3. If that `team.id` happens to equal the `github_id` already stored for an existing `Team` belonging to unrelated "OrgA" (ids are small sequential GitHub team IDs, easily enumerated/brute-forced by repeatedly creating/deleting teams in OrgB until a colliding id is obtained), `find_or_create_by!` returns OrgA's `Team` row.
4. `team.add_member(member)` adds the attacker as a member of OrgA's team, without ever re-validating `team.organization == "OrgA"` against the payload's `"OrgB"`.

No existing guard (`verify_signature`, `drop_unhandled_event`, `ExplicitParameters` schema) checks organization consistency against the `github_id` collision; the `params` schema only requires field types/presence, not that the target team's owning organization matches `organization.login` [3](#0-2) .

### Impact Explanation
The attacker gains membership in a `Team` belonging to an organization they do not control, using only actions inside their own organization. If that `Team`'s membership feeds into Shipit's authorization model (`Shipit.github_teams` / stack-permission checks based on team membership), this becomes an escalation into a privileged team for a foreign organization — a cross-tenant authorization boundary violation. This is repeatable against any `github_id` the attacker can cause to collide, and is not a one-off race: the attacker can enumerate ids by creating/removing teams in their own org until a live collision is found, and can also target `removed` actions to strip legitimate members from a foreign org's team.

### Likelihood Explanation
Preconditions: the attacker must control a GitHub organization that has the Shipit GitHub App installed and configured in Shipit (so their webhook signature verifies) — this is realistic for public/multi-tenant Shipit deployments where many orgs onboard the app. GitHub team IDs are sequential and not secret, so collision-hunting via repeated team creation in the attacker's own org is straightforward and inexpensive. No Shipit secrets, sessions, or API tokens are required.

### Recommendation
In `find_or_create_team!`, do not trust a `github_id`-only match across organizations. Scope the lookup by both `github_id` and `organization`, and re-validate/update `organization` (or raise) when an existing record's organization does not match the payload's `organization.login`, e.g.:
```ruby
def find_or_create_team!
  team = Team.find_or_initialize_by(github_id: params.team.id)
  if team.persisted? && team.organization != params.organization.login
    raise "Team #{team.github_id} organization mismatch"
  end
  team.github_team = params.team
  team.organization = params.organization.login
  team.save!
  team
end
```

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/membership_handler_test.rb`):
```ruby
test "membership webhook cannot hijack a team belonging to another organization via github_id collision" do
  team_a = Shipit::Team.create!(github_id: 42, organization: "org-a")
  attacker = "evil-attacker"

  payload = {
    'action' => 'added',
    'team' => { 'id' => 42, 'name' => 'Some Team', 'slug' => 'some-team', 'url' => 'https://api.github.com/teams/42' },
    'organization' => { 'login' => 'org-b' },
    'member' => { 'login' => attacker }
  }

  Shipit::Webhooks::Handlers::MembershipHandler.new.call(payload)

  team_a.reload
  assert_equal "org-a", team_a.organization
  refute team_a.members.exists?(login: attacker),
    "attacker must not become a member of org-a's team via an org-b payload"
end
```
Before the fix, `team_a.members.exists?(login: attacker)` is `true` because the pre-existing `org-a` team row is returned and mutated by the `org-b` payload, proving the binding `team.organization == params.organization.login` is broken.

### Citations

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L7-21)
```ruby
        params do
          requires :action, String
          requires :team do
            requires :id, Integer
            requires :name, String
            requires :slug, String
            requires :url, String
          end
          requires :organization do
            requires :login, String
          end
          requires :member do
            requires :login, String
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-34)
```ruby
        def process
          team = find_or_create_team!
          member = User.find_or_create_by_login!(params.member.login)

          case params.action
          when 'added'
            team.add_member(member)
          when 'removed'
            team.members.delete(member)
          else
            raise ArgumentError, "Don't know how to perform action: `#{action.inspect}`"
          end
        end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```
