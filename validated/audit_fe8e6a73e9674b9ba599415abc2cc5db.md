This confirms the finding: `Shipit.github_teams` builds team objects via `Team.find_or_create_by_handle`, and `User#authorized?` checks membership against `Shipit.github_teams.map(&:id)` — so being added as a member to a `Team` row that is (or later becomes) referenced in `Shipit.github_teams` grants `authorized?` truth regardless of which organization's webhook actually created that membership.

### Title
Cross-organization team-membership escalation via `github_id` collision in `MembershipHandler#find_or_create_team!` - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`WebhooksController#verify_signature` selects the verifying GitHub App / `webhook_secret` using `params.dig('organization','login')` [1](#0-0) [2](#0-1) , meaning any organization owner can get their own `membership` webhook validly signed by their own org secret. `MembershipHandler#find_or_create_team!` then looks up/creates a `Team` keyed only by `github_id` [3](#0-2) , and since `github_id` has no unique/scoping constraint tying it to `organization` in the schema [4](#0-3) , an attacker can pick a numeric `team.id` that collides with a victim org's existing `Team` row and get `team.add_member(member)` called on it [5](#0-4) .

### Finding Description
**Binding claimed:** organization whose `webhook_secret` verified the payload == organization that owns the `Team` row identified by `github_id`. This binding is **not enforced** anywhere in the code.

- `WebhooksController#verify_signature` derives `repository_owner` from `params.dig('repository','owner','login') || params.dig('organization','login')` [2](#0-1) . For a `membership` event, there is no `repository` key in GitHub's payload, so `repository_owner` resolves purely to `organization.login`, which is attacker-controlled and belongs to the attacker's own org.
- `Shipit.github(organization: repository_owner)` then picks the attacker's own configured `GitHubApp`, whose `webhook_secret` the attacker legitimately knows (it's their own org's secret) [6](#0-5) [7](#0-6) . Signature verification therefore succeeds using purely the attacker's own credentials.
- Inside `MembershipHandler#process`, `find_or_create_team!` calls `Team.find_or_create_by!(github_id: params.team.id)` [3](#0-2) . The `organization` attribute assignment only happens in the `find_or_create_by!` block, which Rails only runs on **creation**, not when an existing row matches. Since `github_id` is a plain integer column with no organization-scoped uniqueness (only `[organization, slug]` is unique — see schema `add_index "teams", ["organization","slug"], unique: true` [4](#0-3) ), an attacker who sends `team.id` equal to a pre-existing victim `Team`'s `github_id` will match that victim's row instead of creating a new one.
- `process` then unconditionally calls `team.add_member(member)` [5](#0-4) [8](#0-7) , inserting a `Membership` linking the attacker-controlled `User` to the victim organization's `Team` row, with no check that `team.organization == params.organization.login`.
- If that victim `Team` is (or becomes) one of `Shipit.github_teams` (i.e., listed in `github.oauth.teams` config) [9](#0-8) , the attacker's `User#authorized?` check `teams.where(id: Shipit.github_teams.map(&:id)).exists?` [10](#0-9)  now returns true, since it only checks `Team#id` (the local primary key that was fetched/matched), not `organization`.

Existing guards (`verify_signature`, `drop_unhandled_event`, the `ExplicitParameters` schema in `MembershipHandler.params`) do not fail here: signature verification succeeds legitimately (attacker owns that org's secret); the params schema only requires `team.id`, `organization.login`, `member.login` as basic types, with no cross-check between them [11](#0-10) .

### Impact Explanation
The attacker gains membership in an arbitrary pre-existing `Team` row (identified only by guessing/reusing a `github_id`), which — if that team is configured in `Shipit.github_teams` (`github.oauth.teams`) — directly grants `User#authorized?` truth for a Shipit instance the attacker was never invited to. This is a cross-tenant authorization escalation: the attacker's own org's webhook secret is used to write records affecting a completely different organization's team/authorization state. Matches "escalation into `Shipit.github_teams` authorization" (High/Critical per the rules), and is repeatable for any known/guessable numeric GitHub team ID.

### Likelihood Explanation
Preconditions: Shipit must be configured for multi-organization GitHub Apps (`Shipit.github(organization:)` keyed config) with `github.oauth.teams` set for access control, and a victim `Team` row with a known/guessable `github_id` must already exist in Shipit's DB (created e.g. by a legitimate prior webhook or `teams:fetch` rake task). Attacker cost is low: they only need to own any GitHub organization with the Shipit GitHub App installed and configured in Shipit's multi-org secrets, and know or guess the victim team's numeric GitHub team ID (team IDs are visible via GitHub API/UI in many contexts). The attack is fully repeatable (add/remove membership at will) once accomplished.

### Recommendation
In `MembershipHandler#find_or_create_team!`, scope the lookup by both `github_id` AND `organization` (e.g. `Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login)`), and additionally verify/raise if an existing `Team` with that `github_id` belongs to a different organization than `params.organization.login`, rejecting the webhook instead of silently reusing the row.

### Proof of Concept
```ruby
# test/models/webhooks/handlers/membership_handler_test.rb
test "membership webhook from attacker-org cannot add member to a victim-org team sharing the same github_id" do
  victim_team = Shipit::Team.create!(github_id: 999, organization: 'victim-org', slug: 'core', name: 'Core')

  payload = {
    'action' => 'added',
    'team' => { 'id' => 999, 'name' => 'Core', 'slug' => 'core', 'url' => 'https://example.com' },
    'organization' => { 'login' => 'attacker-org' },
    'member' => { 'login' => 'attacker' }
  }

  Shipit::User.stubs(:find_or_create_by_login!).returns(Shipit::User.new(login: 'attacker', name: 'attacker'))

  Shipit::Webhooks::Handlers::MembershipHandler.new.call(payload)

  membership = Shipit::Membership.last
  # BEFORE/AFTER equality that should hold but currently is violated by attacker input:
  assert_equal 'victim-org', membership.team.organization
  assert_not_equal 'attacker-org', membership.team.organization
  # Demonstrates: attacker-org webhook wrote a membership onto victim-org's team.
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

**File:** test/dummy/db/schema.rb (L342-351)
```ruby
  create_table "teams", force: :cascade do |t|
    t.string "api_url", limit: 255
    t.datetime "created_at", null: false
    t.bigint "github_id"
    t.string "name", limit: 255
    t.string "organization", limit: 39
    t.string "slug", limit: 255
    t.datetime "updated_at", null: false
    t.index ["organization", "slug"], name: "index_teams_on_organization_and_slug", unique: true
  end
```

**File:** lib/shipit.rb (L170-181)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end
```

**File:** lib/shipit.rb (L256-258)
```ruby
  def github_teams
    @github_teams ||= github.oauth_teams.map { |t| Team.find_or_create_by_handle(t) }
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
