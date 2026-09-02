This vulnerability is confirmed by the code traced.

### Title
Cross-organization Membership write via `MembershipHandler#find_or_create_team!` using webhook signed by a different org - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`Shipit::WebhooksController#repository_owner` falls back to `params.dig('organization', 'login')` when `repository` is absent from the payload, and `verify_signature` only authenticates against that value. `MembershipHandler#find_or_create_team!` looks up a `Team` purely by `params.team.id` (`github_id`), so if a `Team` row already exists (created by a legitimate prior webhook from a victim organization), the `find_or_create_by!` block—which sets `team.organization = params.organization.login`—never executes, and the handler mutates the victim team's `memberships` under a signature that only proved control of the attacker's own organization.

### Finding Description
The broken binding, stated as an equality that should hold but doesn't:
`verified_organization (used by verify_signature) == organization_that_owns_the_mutated_Team_row (team.organization)`.

Trace:
- `repository_owner` at [1](#0-0)  returns `params.dig('repository','owner','login') || params.dig('organization','login')`. For a `membership` event, GitHub never sends a `repository` key, so this always falls to `organization.login`, which is attacker-controlled JSON.
- `verify_signature` at [2](#0-1)  calls `Shipit.github(organization: repository_owner)` and verifies the HMAC signature using **that org's** `webhook_secret` only. It never inspects `params['team']` at all.
- `MembershipHandler#find_or_create_team!` at [3](#0-2)  resolves the `Team` solely by `github_id: params.team.id`. The `organization:` assignment inside the block only executes on **creation** — `find_or_create_by!` will find and return the pre-existing row (created earlier by a legitimate webhook from the victim org) without touching `organization` at all.
- `process` then calls `team.add_member(member)` / `team.members.delete(member)` at [4](#0-3) , mutating `Team#memberships` at [5](#0-4)  — a table belonging to the victim organization, without that organization's webhook signature ever being checked.

Exploit flow: precondition is a multi-org Shipit deployment where the attacker legitimately administers their own GitHub organization/App integration configured in Shipit (thus knows their own `webhook_secret`), and a `Team` row already exists for a victim org's team (`github_id=X`, `organization="victim-org"`). The attacker POSTs to `/webhooks` with `X-Github-Event: membership`, a body with no `repository` key, `organization.login = "attacker-org"`, and `team.id = X` (the victim's github_id), signed with the attacker's own `webhook_secret`. `verify_signature` authenticates successfully against `attacker-org`. `find_or_create_team!` finds the pre-existing victim `Team`, and `add_member`/`members.delete` writes a `Membership` (or removes one) for that victim team, even though the request's verified signature never proved anything about `victim-org`.

Existing guards do not stop this: `verify_signature` checks only `organization.login`/`repository.owner.login`, never `team` contents; the `ExplicitParameters` schema in `MembershipHandler` ( [6](#0-5)  only validates types/presence, not cross-consistency between `team` and `organization`); there is no check that `team.organization == params.organization.login` before or after `find_or_create_by!`.

### Impact Explanation
An attacker who controls (or registers) their own GitHub organization integrated with a multi-org Shipit instance can add or remove arbitrary users to/from any pre-existing `Team` in the Shipit database, as long as they know or can guess the victim team's GitHub `github_id` (a small integer, easily enumerable/guessable across many `membership` events). Since `Team` membership feeds directly into `User#authorized?` ( [7](#0-6) ) which gates access to the entire Shipit UI/deploys when `Shipit.github_teams` is configured, this is escalation into `Shipit.github_teams` authorization — the attacker can add a colluding/attacker-controlled `User` as a member of a team listed in `Shipit.github_teams`, granting that user full authenticated access to stacks, deploys, and rollbacks. This matches the "High" impact category (escalation into `Shipit.github_teams` authorization) and, if the affected team is used for approvals/permissions gating deploys, edges toward unauthorized deploy actions (Critical).

### Likelihood Explanation
Requires: (1) a multi-org Shipit config, satisfied by design; (2) the attacker to control at least one organization/App configured in Shipit with its own `webhook_secret` — a legitimate self-service scenario per the question's stated precondition; (3) a pre-existing `Team` row for the victim org (created by any earlier legitimate `membership` webhook, which is routine in normal operation once teams sync). The attacker's cost is one crafted HTTP POST with a correctly signed body using their own secret; the `team.id` (GitHub numeric team ID) is discoverable via GitHub's public/team API for public orgs. This is repeatable against any `github_id` for as many Team rows as exist, arbitrarily often.

### Recommendation
In `MembershipHandler#find_or_create_team!` (and equivalent handlers), validate that when a `Team` with the given `github_id` already exists, its `organization` matches `params.organization.login` (or better, match `repository_owner`/verified org used in `verify_signature`) before performing any membership mutation; raise/drop the event otherwise. More robustly, `verify_signature` should be changed to authenticate against an organization value that is cryptographically tied to the payload used for the mutation (e.g., require `team.organization` consistency check explicitly in every team-scoped handler, not just rely on `organization.login`).

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/membership_handler_test.rb (conceptual)
test "membership webhook cannot write to a team belonging to another organization" do
  victim_team = Shipit::Team.create!(
    github_id: 4242,
    organization: "victim-org",
    slug: "core",
    name: "Core",
    api_url: "https://api.github.com/teams/4242"
  )

  attacker_payload = {
    "action" => "added",
    "team" => { "id" => 4242, "name" => "Core", "slug" => "core", "url" => victim_team.api_url },
    "organization" => { "login" => "attacker-org" }, # signed org != team's real org
    "member" => { "login" => "attacker_controlled_user" }
  }

  # Simulate verify_signature already passed for "attacker-org" (attacker's own secret)
  Shipit::Webhooks::Handlers::MembershipHandler.new.call(attacker_payload)

  victim_team.reload
  # broken binding: verified org ("attacker-org") != team.organization ("victim-org"),
  # yet the membership was written.
  assert_equal "victim-org", victim_team.organization
  assert victim_team.members.exists?(login: "attacker_controlled_user")
end
```

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
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

**File:** app/models/shipit/team.rb (L41-43)
```ruby
    def add_member(member)
      members.append(member) unless members.include?(member)
    end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
