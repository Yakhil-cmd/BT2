### Title
Cross-tenant team lookup in `MembershipHandler#process` allows a signed webhook from one configured GitHub org to delete/grant `Membership` rows for a team belonging to a different org - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`MembershipHandler#find_or_create_team!` resolves the target `Team` purely by the numeric `params.team.id` (`github_id`), with no check that the team actually belongs to the organization that authenticated the request. Because `verify_signature` only proves the payload was signed with the webhook secret configured for `params.organization.login` (a config lookup keyed by org name, per `Shipit.github_app_config`), a webhook that is validly signed for *one* configured org can carry a `team.id` value belonging to a *different* configured org's `Team` row, causing `team.members.delete(member)` / `team.add_member(member)` to mutate a membership that has nothing to do with the signing org.

### Finding Description
The broken binding is: `Team#organization` (as originally recorded when the team was created) == the organization that GitHub actually reports as owning `team.id` == the organization whose webhook secret verified this specific request. `find_or_create_team!` never checks the second or third of these:

```ruby
def find_or_create_team!
  Team.find_or_create_by!(github_id: params.team.id) do |team|
    team.github_team = params.team
    team.organization = params.organization.login
  end
end
``` [1](#0-0) 

`find_or_create_by!(github_id: ...)` only sets `organization` on the create branch of the block; if a `Team` with that `github_id` already exists (created earlier, e.g. for a legitimate victim org), the existing row is returned unchanged regardless of what `params.organization.login` says. `process` then unconditionally acts on it:

```ruby
case params.action
when 'added'
  team.add_member(member)
when 'removed'
  team.members.delete(member)
``` [2](#0-1) 

`verify_signature` selects the `GitHubApp` config by `repository_owner`, which for a `membership` event falls back to `params.dig('organization', 'login')`:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [3](#0-2) 
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(...)
``` [4](#0-3) 

Each configured org in `secrets.github` has its own independent `webhook_secret`/App credentials (`test/dummy/config/secrets_double_github_app.yml` shows two orgs, `OrgOne`/`OrgTwo`, each with distinct app/secret config), and `Shipit.github(organization:)` looks the config up strictly by name via `github_app_config`: [5](#0-4) 

So signature verification proves only "this request's HMAC matches OrgTwo's secret" — it says nothing about whether the `team.id` in the JSON body is a team that belongs to OrgTwo on GitHub. `Team.find_or_create_by!` has no `organization:` scoping in its lookup, so an existing `Team` row created under OrgOne (the victim org) with `github_id: 48` can be located and mutated purely because the number happens to match, using a signature that only proves the attacker's control of OrgTwo.

Attacker's exact request: attacker administers (or is an authenticated member with webhook-triggering ability of) a second org, `OrgTwo`, that is legitimately configured in this Shipit deployment's `secrets.github`. They cause (or directly POST, matching the current numeric HMAC for `OrgTwo`'s secret) a `membership` event to `/webhooks` with:
- `organization.login = "OrgTwo"` (so `verify_signature` checks against OrgTwo's own webhook secret — passes)
- `team.id = 48` (the victim `Team`'s `github_id`, belonging to `OrgOne`, already present in Shipit's DB and included in `Shipit.github_teams`)
- `action = "removed"`
- `member.login = "victim-operator"` (an existing Shipit operator with a `Membership` on that team)

`find_or_create_team!` returns the existing `OrgOne` team row (matched only by `github_id: 48`), `User.find_or_create_by_login!` resolves the real victim user, and `team.members.delete(member)` deletes the `Membership` row.

None of the documented guards intervene: `verify_signature` only authenticates the org named in the payload against its own secret (by design, for multi-tenant orgs), not the org-to-team binding; `drop_unhandled_event` passes since `membership` is a handled event; the `ExplicitParameters` schema only validates types/presence, not cross-referential integrity between `organization.login` and `team.id`; there is no `require_permission!`/authorization check inside `MembershipHandler` at all.

### Impact Explanation
A signed webhook from an unrelated, legitimately-configured tenant org can flip `victim_user.authorized?` to `false` by deleting a `Membership` row for a team the attacker's org never actually owns on GitHub, deauthorizing a real Shipit operator (`Shipit::User#authorized?` checks `teams.where(id: Shipit.github_teams.map(&:id)).exists?`) [6](#0-5) . The same primitive also permits the inverse: injecting a spurious `Membership`/`added` for a team the attacker doesn't belong to, potentially self-granting authorization if `team.id` collides with a team in `Shipit.github_teams` that the attacker knows the numeric ID of. This is a cross-tenant write (one org's payload mutating another org's `Team`/`Membership` records) and is repeatable per victim membership/team, matching the Critical category "a payload for one repository mutating another's ... team" as well as the High category "escalation into `Shipit.github_teams` authorization" (via forged `added`).

### Likelihood Explanation
This requires a genuine multi-tenant Shipit deployment where more than one GitHub organization is configured in `secrets.github` (each with its own real webhook secret/App), and the attacker must legitimately control one of those configured orgs (able to produce a validly-signed webhook for it) — this is a real, supported deployment topology per `test/dummy/config/secrets_double_github_app.yml` and the multi-org branches in `lib/shipit.rb#github_app_config`. The attacker additionally needs to know or guess a numeric `github_id` corresponding to a target team (these IDs are often discoverable/enumerable via GitHub's public team/org APIs or from prior interactions). No secrets of the victim org are needed; only the attacker's own org's webhook secret (which they legitimately possess as that org's admin) is required, making this fully reachable without compromising any Shipit or victim-org credential.

### Recommendation
Scope the team lookup by the authenticated organization instead of relying solely on `github_id`: pass `repository_owner`/`params.organization.login` into `find_or_create_team!` and require `team.organization == params.organization.login` (case-insensitively) before acting, raising/dropping the event otherwise. Additionally, verify in `process` that the resolved `team.organization` matches the webhook's authenticated organization prior to calling `add_member`/`members.delete`, closing the gap between "who signed this webhook" and "which team it is allowed to mutate."

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (conceptual)
test ":membership from OrgTwo cannot mutate a team belonging to OrgOne" do
  victim_team = Team.create!(organization: 'OrgOne', github_id: 48, name: 'Victim Team', slug: 'victim-team', api_url: 'https://api.github.com/teams/48')
  victim_user = shipit_users(:walrus)
  Membership.create!(team: victim_team, user: victim_user)
  assert victim_user.authorized? # given github_teams includes victim_team

  Shipit.stubs(:github).with(organization: 'OrgTwo').returns(fake_org_two_github_app_with_valid_secret)

  @request.headers['X-Github-Event'] = 'membership'
  # Signed correctly for OrgTwo's own secret, but references OrgOne's team.id and the victim's login
  payload = membership_params.merge(
    action: 'removed',
    organization: { login: 'OrgTwo' },
    team: { id: 48, name: 'Victim Team', slug: 'victim-team', url: 'https://api.github.com/teams/48' },
    member: { login: victim_user.login }
  ).to_json

  assert_difference -> { Membership.count }, -1 do
    post :create, body: payload, as: :json
    assert_response :ok
  end

  refute victim_user.reload.authorized?, "victim was deauthorized by an unrelated org's webhook"
end
```
This demonstrates the equality `Team#organization` == authenticated org from the signature is never checked, so `Membership.count` drops and `victim_user.authorized?` flips false purely from a different, unrelated org's signed request.

### Citations

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L26-30)
```ruby
          case params.action
          when 'added'
            team.add_member(member)
          when 'removed'
            team.members.delete(member)
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

**File:** lib/shipit.rb (L170-200)
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

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
