### Title
Cross-tenant Membership deletion via team.id collision in webhook membership handler - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`MembershipHandler#process` resolves a `Team` solely by the attacker-supplied `team.id` (GitHub team ID) and never verifies that the organization which authenticated the webhook is the same organization that owns that `Team`. An attacker who legitimately administers their own GitHub organization/webhook (and therefore knows that organization's own `webhook_secret`) can sign a `membership` "removed" event naming a `team.id` that collides with a victim organization's `Team#github_id`, causing Shipit to delete a `Membership` row that belongs to a different tenant.

### Finding Description
The binding that should hold is: `authenticated_organization == team.organization` before any `Membership` belonging to `team` is mutated, where `authenticated_organization` is the org whose `webhook_secret` produced a valid `X-Hub-Signature` in `WebhooksController#verify_signature` [1](#0-0)  and `repository_owner` (used to select which org's secret to verify against) is read straight from the JSON payload's `organization.login` for events without a `repository` key [2](#0-1) .

In `MembershipHandler#process`, the team is resolved with `Team.find_or_create_by!(github_id: params.team.id)`, which only sets `team.organization` inside the `create` block — it is never checked against the resolved/existing row [3](#0-2) . The `'removed'` branch then immediately calls `team.members.delete(member)` with no authorization check tying the request's authenticated organization to `team.organization` [4](#0-3) .

Exploit flow:
1. Attacker owns/administers GitHub org `attacker-org`, which is a legitimate, separately-onboarded tenant of the same Shipit instance and therefore knows `attacker-org`'s own `webhook_secret` (this is within the stated attacker capability: "emit webhooks from a repository/org they own").
2. Attacker crafts a `membership` webhook JSON payload: `organization.login = "attacker-org"`, `team.id = <victim Team#github_id>`, `team.name/slug/url` arbitrary, `member.login = <victim's legitimate Shipit user>`, `action = "removed"`.
3. Attacker signs the payload with `attacker-org`'s own `webhook_secret` and POSTs to `/webhooks`.
4. `verify_signature` computes `repository_owner = "attacker-org"` (from `organization.login`, since there is no `repository` key for membership events), looks up `Shipit.github(organization: "attacker-org")`, and the HMAC verifies successfully because it truly was signed with that org's secret [5](#0-4) .
5. `MembershipHandler#process` runs: `find_or_create_team!` looks up the existing `Team` row by `github_id` (the victim's real GitHub team ID) — it finds the victim's `Team`, not the attacker's, because `github_id` collisions/known-victim-IDs are trivially satisfiable by the attacker choosing the number, and no create actually occurs since the row exists [3](#0-2) .
6. `team.members.delete(member)` deletes the `Membership` row linking the victim user to the victim `Team`, with zero check that `attacker-org != team.organization` [6](#0-5) .

Existing guards do not stop this: `verify_signature` only proves the payload was signed by *some* configured organization's secret — it never asserts that organization owns the specific `Team` resource being mutated [5](#0-4) . `drop_unhandled_event` and the `ExplicitParameters` schema only validate shape/presence of fields, not ownership [7](#0-6) . `User#authorized?` is a downstream *consequence* of this bug (it re-evaluates `teams.where(id: Shipit.github_teams...)` and will flip to `false` once the `Membership` is gone), not a guard against it [8](#0-7) .

### Impact Explanation
A single forged webhook lets an operator of any onboarded-but-unrelated organization silently revoke another organization's team membership, causing a legitimate maintainer to lose `Shipit.github_teams`-based authorization (`User#authorized?` becomes `false`) without any interaction from the victim org. This is an unauthorized cross-tenant mutation of an authorization-relevant record (`Membership`) belonging to a `Team` the attacker does not control, matching the "escalation/loss into `Shipit.github_teams` authorization" and cross-repository/cross-tenant mutation categories. It is repeatable against any `Team#github_id` the attacker can enumerate or guess (GitHub team IDs are small sequential integers, discoverable via GitHub's public team API in many cases), and against any member currently in that team, for every request.

### Likelihood Explanation
Preconditions: Shipit must be configured to serve multiple GitHub organizations (multi-tenant), each with its own `GitHubApp`/`webhook_secret` entry, and the attacker must be a legitimate admin/owner of at least one such onboarded organization (satisfying the "emit webhooks from a repo/org they own" capability) — this is a normal, low-cost position for an attacker in a multi-tenant Shipit deployment. No GitHub secrets, sessions, or Shipit-operator access belonging to the *victim* org are required; only the attacker's own org's webhook secret, which they legitimately possess. The `team.id` value is a small integer and can be discovered via GitHub's team API or brute-forced. This makes the attack cheap and repeatable.

### Recommendation
In `find_or_create_team!`/`MembershipHandler#process`, verify that the webhook's authenticated organization (`params.organization.login`, the same value used to select the `webhook_secret` in `verify_signature`) equals the resolved `Team#organization` before performing `add_member`/`delete`. If they differ, drop/reject the event instead of mutating the `Team`. Additionally, scope the `find_or_create_by!` lookup by `(github_id:, organization:)` rather than `github_id` alone, so a `team.id` collision across tenants cannot resolve to a different organization's row.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/membership_handler_test.rb`):
```ruby
test "removed action from a different organization does not delete membership of another org's team" do
  victim_team = shipit_teams(:some_team) # organization: "victim-org", github_id: 4242
  member = shipit_users(:some_member)
  victim_team.add_member(member)
  assert_difference -> { Membership.count }, 0 do
    MembershipHandler.new(
      'action' => 'removed',
      'team' => { 'id' => victim_team.github_id, 'name' => 'x', 'slug' => 'x', 'url' => 'x' },
      'organization' => { 'login' => 'attacker-org' }, # authenticated org != victim_team.organization
      'member' => { 'login' => member.login }
    ).call
  end
  assert Membership.exists?(team: victim_team, user: member)
  assert member.reload.authorized? # unchanged
end
```
Assert both sides of the binding: before the call, `authenticated_org ("attacker-org") != victim_team.organization ("victim-org")`; the fix should keep the equality false → handler must no-op. Currently (without a fix) the same test fails because `Membership.count` decreases by 1 and `member.authorized?` flips to `false`, demonstrating the unauthorized cross-tenant mutation.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L38-43)
```ruby
        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
          end
        end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
