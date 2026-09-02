### Title
Cross-tenant team hijack via `github_id`-only lookup in `MembershipHandler#find_or_create_team!` - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`MembershipHandler#find_or_create_team!` resolves the target `Team` solely by `params.team.id` (GitHub's numeric team id), never checking that the organization which actually signed the webhook (`params.organization.login`, the same value `WebhooksController#repository_owner` uses for signature verification) matches the `Team#organization` already stored for that `github_id`. In a Shipit instance configured for multiple GitHub organizations (`Shipit.github_app_config`/`secrets.github.<org>`), an attacker who legitimately controls the webhook secret of their own onboarded organization can forge a validly-signed `membership` event that mutates a `Team` belonging to a completely different organization, adding themselves as a member.

### Finding Description
The broken binding: `Membership.team_id ∈ Shipit.github_teams.map(&:id)` should imply that GitHub itself reported that membership for that team's real organization. Instead, the code allows:

`signed_org(webhook) = params.organization.login = "OrgB"` (attacker's own org) while `team.organization = "shopify"` (a pre-existing, unrelated org) for the same `team.github_id`.

Path:
1. `WebhooksController#verify_signature` picks the `GitHubApp` via `repository_owner`, which for membership payloads (no `repository` key) is `params.dig('organization', 'login')` [1](#0-0) [2](#0-1) . Because Shipit supports multiple organizations each with its own `webhook_secret` (`Shipit.github_app_config`) [3](#0-2) , an attacker who administers/owns "OrgB" (already onboarded to the same Shipit instance) legitimately knows OrgB's webhook secret and can produce a valid `X-Hub-Signature` for a payload where `organization.login = "OrgB"`.
2. `MembershipHandler#find_or_create_team!` looks the `Team` up **only** by `github_id`, ignoring `params.organization.login` when a matching record already exists: `Team.find_or_create_by!(github_id: params.team.id) { ... }` [4](#0-3) . If a `Team` row already exists for that `github_id` (e.g. `shopify/developers`, created earlier by legitimate events from the real org), the block is skipped and the existing, unrelated-org `Team` is returned.
3. `process` then does `team.add_member(User.find_or_create_by_login!(params.member.login))` for `action == 'added'` [5](#0-4) , where `params.member.login` is fully attacker-controlled (their own GitHub login).
4. `Team#add_member` unconditionally appends the member [6](#0-5) .

If that `Team`'s `id` (primary key) happens to be one of the entries memoized in `Shipit.github_teams` (built from `secrets.github.oauth.teams` via `Team.find_or_create_by_handle`) [7](#0-6) , the attacker's own account now satisfies `User#authorized?`'s check `teams.where(id: Shipit.github_teams.map(&:id)).exists?` [8](#0-7)  — full application authorization — without ever being a member of the real org's team on GitHub, and without a session, `ApiClient`, or the target org's own webhook secret.

Why guards don't help: `verify_signature` only proves the payload was signed by *some* configured org matching `params.organization.login`; it never proves that org matches the `team.id`/`github_id` being mutated. `ExplicitParameters` (`params do ... end`) only validates types/presence of `action`, `team.id/name/slug/url`, `organization.login`, `member.login` — it enforces no cross-field consistency [9](#0-8) . `find_or_create_by_handle`/`find_team_on_github` are bypassed entirely once the `Team` row already exists.

### Impact Explanation
A payload validly signed for one organization ("OrgB") can mutate a `Team`/`Membership` record that actually belongs to a different, unrelated organization ("shopify"), matching the Critical impact category "a payload for one repository/organization mutating another's ... team." Practically, this lets an attacker who controls any org onboarded to the Shipit instance escalate their own account into any `Shipit.github_teams` authorization group whose GitHub team id they can learn or guess, gaining full access to the Shipit UI/API as an "authorized" user (High: escalation into `Shipit.github_teams` authorization) — repeatable against any team id, and blast radius spans all tenants sharing the same Shipit instance.

### Likelihood Explanation
Requires: (a) Shipit configured for multiple GitHub organizations (multi-tenant `secrets.github` mapping), (b) attacker legitimately controls the webhook secret for at least one onboarded org distinct from the target team's org, (c) knowledge/guess of the target team's numeric GitHub `id` (team ids are small sequential integers and often discoverable via public GitHub APIs or prior webhook traffic). Cost is low once (a)/(b) hold; the request is a single POST to `/webhooks` and is fully repeatable for any team id.

### Recommendation
In `MembershipHandler#find_or_create_team!`, verify that `params.organization.login` matches the existing `Team#organization` (case-insensitively) before allowing mutation, and raise/drop the event on mismatch instead of silently reusing the record. Additionally, `verify_signature` should be based on `params.team`'s claimed organization consistently, and the handler should re-derive/validate the organization against the authenticated `GitHubApp` context rather than trusting attacker-supplied `organization.login` for record identification.

### Proof of Concept
```ruby
test ":membership from an unrelated org cannot hijack a team belonging to another org" do
  target_team = shipit_teams(:shopify_developers) # organization: 'shopify', github_id: 1
  Shipit.stubs(:github_teams).returns([target_team])

  @request.headers['X-Github-Event'] = 'membership'
  GithubHook.any_instance.stubs(:verify_signature).returns(true) # simulate a valid signature for "cyclimse" org

  assert_no_difference -> { Team.count } do
    post :create, as: :json, body: {
      action: 'added',
      team: { id: target_team.github_id, name: target_team.name, slug: target_team.slug, url: target_team.api_url },
      organization: { login: 'cyclimse' }, # attacker's own, unrelated org
      member: { login: 'attacker' }
    }.to_json
    assert_response :ok
  end

  attacker = User.find_by!(login: 'attacker')
  # Broken binding: membership created for a Shipit.github_teams id without GitHub
  # ever reporting this membership on the team's real ('shopify') organization.
  assert_includes Shipit.github_teams.map(&:id), target_team.id
  assert_includes attacker.teams.pluck(:id), target_team.id
  assert_equal 'shopify', target_team.reload.organization
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

**File:** lib/shipit.rb (L256-258)
```ruby
  def github_teams
    @github_teams ||= github.oauth_teams.map { |t| Team.find_or_create_by_handle(t) }
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
