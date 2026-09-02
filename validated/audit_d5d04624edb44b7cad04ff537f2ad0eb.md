### Title
Cross-organization Team hijack via `github_id`-only lookup in `find_or_create_team!` - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`MembershipHandler#find_or_create_team!` looks up an existing `Team` solely by `github_id`, without verifying that the team's `organization` matches the organization whose webhook secret validated the request. An attacker who owns their own GitHub organization (with a legitimately registered webhook secret in Shipit) can send a `membership` webhook claiming an arbitrary `team.id` that collides with a victim organization's existing `Team#github_id`, causing themselves to be added as a member of that victim team.

### Finding Description
The broken binding: `params.dig('organization','login')` (the org that produced a valid signature) MUST equal `Team.find_by(github_id: params.team.id).organization` before any membership mutation is allowed. This binding is never checked.

Path:
1. `WebhooksController#verify_signature` computes `repository_owner` via `params.dig('repository','owner','login') || params.dig('organization','login')` [1](#0-0)  and resolves `Shipit.github(organization: repository_owner)` to verify the HMAC signature [2](#0-1) . If the attacker omits `repository` and sets `organization.login = "attacker-org"`, the signature is verified using attacker-org's own legitimate secret — verification succeeds.
2. `MembershipHandler.call` is invoked with attacker-controlled `params.team.id`, `params.organization.login`, `params.member.login`, `params.action` [3](#0-2) .
3. `find_or_create_team!` calls `Team.find_or_create_by!(github_id: params.team.id)` — this matches purely on `github_id`, so if a `Team` row already exists with `github_id == 999` (the victim org's real team), it is returned regardless of the `organization.login` claimed in this request [4](#0-3) .
4. `process` then does `team.add_member(member)` for `action == 'added'`, appending the attacker's `User` record to `team.members` [5](#0-4) , `app/models/shipit/team.rb` `add_member` [6](#0-5) .
5. `User#authorized?` checks `teams.where(id: Shipit.github_teams.map(&:id)).exists?` [7](#0-6)  — if the victim's team is one of `Shipit.github_teams`, the attacker now passes this check.

Why guards fail: `verify_signature` only proves the *request* was signed by attacker-org's secret; it never binds the *content* of `params.team.id`/`params.organization.login` to a specific org's teams. `find_or_create_team!`'s `find_or_create_by!(github_id:)` is the sole lookup and has no `organization:` filter, so an existing victim-org Team row is silently reused for a request that authenticated as a different organization.

### Impact Explanation
An attacker-controlled account is added to `team.members` for a team belonging to a victim organization, without any credential belonging to the victim. If that team is registered in `Shipit.github_teams`, `User#authorized?` returns true for the attacker, granting access gated by team authorization checks (e.g. `require_permission!`/`authorized?`-gated actions such as deploys, depending on how the host app uses `authorized?`). This is a cross-tenant authorization escalation — matches the "High: escalation into `Shipit.github_teams` authorization" impact category. It is repeatable for any known/guessed `team.id` (GitHub team IDs are not secret) and requires only a `removed` follow-up webhook self-service cleanup is unnecessary for repeat abuse.

### Likelihood Explanation
Preconditions: attacker must own a GitHub organization already registered as a Shipit app installation (has its own valid `webhook_secret` configured in `Shipit.github_teams`/app config) — this is stated as given in the scenario and is a low-cost, self-service setup (any GitHub user can create an org and install an app). Attacker must know/guess the victim's team `github_id`, which is not secret (visible via GitHub API/UI for public teams, or brute-forceable since GitHub team IDs are sequential integers). No Shipit session, API token, or victim secret is required. This is a low-cost, fully repeatable attack.

### Recommendation
In `find_or_create_team!`, scope the lookup by both `github_id` and `organization`, and reject/no-op if a `Team` with that `github_id` exists under a different organization than `params.organization.login`:
```ruby
def find_or_create_team!
  existing = Team.find_by(github_id: params.team.id)
  if existing && existing.organization != params.organization.login
    raise ArgumentError, "team github_id #{params.team.id} belongs to a different organization"
  end
  Team.find_or_create_by!(github_id: params.team.id) do |team|
    team.github_team = params.team
    team.organization = params.organization.login
  end
end
```
Additionally, `verify_signature` should validate that `params.organization.login` (when used as the signature-verification org) matches the org actually referenced elsewhere in a `membership` payload, to close the general "claimed org for signature ≠ actual affected resource" pattern.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/membership_handler_test.rb (conceptual addition)
test "does not add member to a team belonging to a different organization" do
  victim_team = Shipit::Team.create!(
    github_id: 999, organization: 'victim-org', name: 'core', slug: 'core',
    api_url: 'https://api.github.com/teams/999'
  )
  attacker_login = 'attacker-user'

  payload = {
    'action' => 'added',
    'team' => { 'id' => 999, 'name' => 'core', 'slug' => 'core', 'url' => victim_team.api_url },
    'organization' => { 'login' => 'attacker-org' },
    'member' => { 'login' => attacker_login }
  }

  assert_raises(ArgumentError) do
    Shipit::Webhooks::Handlers::MembershipHandler.new.call(payload)
  end

  victim_team.reload
  refute victim_team.members.exists?(login: attacker_login)
end
```
Both sides of the equality (`payload['organization']['login']` == `victim_team.organization`) must be asserted unequal before the fix (`'attacker-org' != 'victim-org'`), and the test must show `team.members` unchanged / an exception raised after the fix, versus the attacker being silently added under current code.

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L6-21)
```ruby
      class MembershipHandler < Handler
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
