### Title
`MembershipHandler#process` trusts attacker-supplied `team` payload without binding it to the authenticated webhook organization, allowing cross-tenant escalation into `Shipit.github_teams` - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`MembershipHandler#find_or_create_team!` looks up `Team` records solely by `github_id`, with no check that the team belongs to the organization whose webhook actually authenticated the request (`repository_owner`/`params.organization.login`). An attacker who legitimately owns an org onboarded into Shipit (and thus can produce a validly-signed `membership` webhook for that org) can forge a payload whose `team` block copies the `id`/`slug`/`name`/`url` of a privileged team belonging to a *different* organization, causing `Team.find_or_create_by!(github_id: ...)` to resolve to that existing privileged `Team` row and `team.add_member(member)` to add the attacker as a member.

### Finding Description
The broken binding: `Membership.exists?(team_id: T, user_id: U)` should hold **iff** GitHub itself reported that `U` is a member of the team whose `github_id` is `T`, as verified via a webhook signed by the GitHub organization that actually owns team `T`.

Trace:
- `WebhooksController#verify_signature` resolves the signing org via `repository_owner`, which for a `membership` event falls back to `params.dig('organization', 'login')` [1](#0-0) , and validates the signature using `Shipit.github(organization: repository_owner)`'s configured `webhook_secret` [2](#0-1) . This only proves the request came from *some* org whose webhook secret matches — specifically the attacker's own org, if the attacker owns/controls that org's Shipit integration.
- `MembershipHandler#process` then calls `find_or_create_team!`, which does `Team.find_or_create_by!(github_id: params.team.id)` [3](#0-2) . This lookup uses only `github_id` as the key — there is no comparison against `params.organization.login` or against the record's own `organization` column. If a `Team` row with that `github_id` already exists (e.g., a privileged team already synced into `Shipit.github_teams`), the block is never invoked and the found row is returned unchanged, regardless of which organization the webhook was signed for.
- `process` then unconditionally calls `team.add_member(member)` for `action == 'added'`, and `Team#add_member` simply does `members.append(member) unless members.include?(member)` [4](#0-3) , creating a `Membership` row between the attacker-created `member` (`User.find_or_create_by_login!(params.member.login)` [5](#0-4) ) and the victim `Team`.
- `User#authorized?` checks `teams.where(id: Shipit.github_teams.map(&:id)).exists?` [6](#0-5) . If the victim team's id is among `Shipit.github_teams`, the attacker's own account now satisfies this check.

Existing guards do not close this gap: `verify_signature` only authenticates *which organization* sent the request, not *which team the payload claims to describe*; there is no code anywhere in `MembershipHandler` or `Team.find_or_create_by!` that cross-checks `params.organization.login` against the found team's `organization` attribute before mutating membership.

### Impact Explanation
A successful request creates a `Membership` row binding the attacker's Shipit `User` to a `Team` that is part of `Shipit.github_teams`, which is checked by `User#authorized?` for authorization gating throughout the app. This is a High-severity escalation into `Shipit.github_teams` authorization for the entire instance: any attacker with a validly onboarded organization can add themselves (or an arbitrary GitHub login) to any team known to Shipit by ID, bypassing GitHub's actual team membership. This is repeatable against any team whose `github_id`/`slug`/`name`/`url` the attacker can learn (these are not secret — team metadata is visible via GitHub's API/UI to team members, and `github_id` is a small integer that could also be brute-forced/enumerated), and against arbitrary victim organizations, since nothing in the handler restricts the target team's organization to match the authenticated webhook's organization.

### Likelihood Explanation
Preconditions: the attacker must control (own) at least one GitHub organization that is already onboarded into this Shipit instance with a configured GitHub App/webhook secret — this is exactly the scenario the question stipulates ("through their own organization's verified webhook ... verify_signature passes with attacker's own webhook_secret"). Given that precondition, the attack requires only knowledge of the victim team's `id`/`slug`/`name`/`url`, which are non-secret team metadata, and a single crafted HTTP POST to `/webhooks` with a `membership` event and `action: 'added'`. No GitHub-side interaction with the victim org is required. Cost is very low and the request is trivially repeatable for any known team.

### Recommendation
In `MembershipHandler#find_or_create_team!`, scope the lookup by both `github_id` and `organization` (i.e., `Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login)`), and explicitly reject/raise if an existing `Team` with that `github_id` belongs to a different organization than `params.organization.login`. Additionally, verify that `params.organization.login` matches the record's stored `organization` before calling `add_member`/`delete` on a pre-existing team, so a webhook authenticated for org A can never mutate memberships of a team belonging to org B.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/membership_handler_test.rb
test "membership webhook from attacker's org cannot add member to a team belonging to a different org" do
  victim_team = shipit_teams(:shipit) # a Team already in Shipit.github_teams, organization: 'shopify'
  Shipit.stubs(:github_teams).returns([victim_team])

  attacker_org = 'attacker-org'
  # Simulate a validly signed webhook for the attacker's own org
  GithubHook.any_instance.stubs(:verify_signature).returns(true) # or stub GitHubApp#verify_webhook_signature true

  params = {
    'action' => 'added',
    'team' => {
      'id' => victim_team.github_id,   # copied verbatim from victim team
      'name' => victim_team.name,
      'slug' => victim_team.slug,
      'url' => victim_team.api_url
    },
    'organization' => { 'login' => attacker_org }, # attacker's own org, not victim's
    'member' => { 'login' => 'attacker-user' }
  }

  Shipit::Webhooks::Handlers::MembershipHandler.new.call(ActiveSupport::HashWithIndifferentAccess.new(params))

  attacker_user = Shipit::User.find_by(login: 'attacker-user')

  # Binding check: no such membership should exist on the victim team unless GitHub itself reported it for that team's org
  assert Shipit::Membership.exists?(team_id: victim_team.id, user_id: attacker_user.id),
    "Attacker was added to a team belonging to a different organization"
  assert attacker_user.authorized?,
    "Attacker gained Shipit.github_teams authorization via a cross-org forged webhook"
end
```
This demonstrates that `find_or_create_team!`'s `github_id`-only lookup, combined with the absence of an organization-match check, lets a webhook authenticated for the attacker's own org mutate membership of a `Team` belonging to a different organization and gain `Shipit.github_teams` authorization.

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L24-24)
```ruby
          member = User.find_or_create_by_login!(params.member.login)
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
