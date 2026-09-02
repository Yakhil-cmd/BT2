### Title
Cross-organization team-membership escalation via unscoped `github_id` lookup in `MembershipHandler#find_or_create_team!` - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`WebhooksController#verify_signature` verifies a webhook's HMAC using the GitHub App config selected by the *claimed* `organization`/`repository.owner.login` in the payload itself, and `GitHubApp#verify_webhook_signature` trivially returns `true` when that org's `webhook_secret` is unset. `MembershipHandler#find_or_create_team!` then resolves the target `Shipit::Team` solely by `github_id`, with no check that the found team's `organization` matches the org whose signature was just "verified", so a webhook honestly attributable only to `attacker-org` can mutate membership of a team that actually belongs to a different, victim organization.

### Finding Description
Broken binding: `verified_organization(payload) == team.organization` is assumed but never checked; in reality `verified_organization` can be `'attacker-org'` while `team.organization` is the victim org, and the code still executes `team.add_member(member)`.

Path:
1. `WebhooksController#verify_signature` calls `Shipit.github(organization: repository_owner)` where `repository_owner` is read straight from attacker-controlled JSON (`params.dig('repository','owner','login') || params.dig('organization','login')`) — [1](#0-0) [2](#0-1) .
2. `Shipit.github` resolves per-org config via `github_app_config(organization)`, which requires the org key to already exist in the multi-org `secrets.github` map, else it raises `GithubOrganizationUnknown` (422) — [3](#0-2) . So this path is only reachable when Shipit is running the multi-org config schema and `attacker-org` is one of the pre-configured org keys (e.g. a legitimately onboarded but attacker-controlled tenant org).
3. `GitHubApp#verify_webhook_signature` short-circuits to `true` when that org's `webhook_secret` is blank — [4](#0-3) . This lets the attacker's unsigned POST pass `verify_signature` entirely.
4. `Shipit::Webhooks.for_event('membership')` dispatches to `Handlers::MembershipHandler` — [5](#0-4) .
5. `MembershipHandler#process` calls `find_or_create_team!`, which does `Team.find_or_create_by!(github_id: params.team.id)` — matching **only** on `github_id`, with `organization` only assigned inside the `create` block (never checked/updated for existing records) — [6](#0-5) . Since the victim team already exists with `github_id == victim_team_github_id`, this line returns the existing victim `Team` record regardless of the fact that the request was only authenticated for `attacker-org`.
6. `team.add_member(User.find_or_create_by_login!('attacker-user'))` then persists the membership via `Team#add_member` / the `memberships` association — [7](#0-6) [8](#0-7) .

No guard rejects this: `verify_signature` only authenticates *that org's* payload, it does not (and structurally cannot, since the handler is org-agnostic) confirm that every object ID referenced inside the payload belongs to that org; `ExplicitParameters` schema in `MembershipHandler.params` only validates types/presence, not organization ownership of `team.id` — [9](#0-8) ; and `Team.find_or_create_by!` has no `organization:` scoping in its lookup.

`Shipit.github_teams` (used by authorization checks such as `deployable?`/`require_permission!`) is built from `Team.find_or_create_by_handle` off `github.oauth_teams` config, and trusts the `Team#members` association populated by this handler — [10](#0-9) .

### Impact Explanation
A `User` row is added to `memberships` of a `Team` the attacker does not control, and that `Team` may be one of the privileged teams configured in `Shipit.github_teams` used for authorization decisions elsewhere in the app. This is a cross-tenant write: a request authenticated (or trivially unauthenticated, if `attacker-org`'s secret is unset) for `attacker-org` mutates state belonging to a different organization's team. It is repeatable against any team whose `github_id` the attacker knows or can guess/enumerate, for as long as `attacker-org` remains configured with a missing/absent `webhook_secret`. This matches the "escalation into `Shipit.github_teams` authorization" High-severity category.

### Likelihood Explanation
Requires: (1) Shipit deployed with the multi-org GitHub config schema (`secrets.github` keyed by organization) rather than the single-org schema — in the single-org schema `Shipit.github(organization: ...)` ignores the passed org entirely and always uses the one global `secrets.github` config, so this specific bypass does not apply; (2) `attacker-org` must already be a configured org key in that map (an operator must have onboarded it, e.g. a multi-tenant Shipit instance); (3) that org's entry must be missing `webhook_secret` (a real, documented misconfiguration state, since `webhook_secret` is commented as optional/`nil` in example configs) — [11](#0-10) ; (4) attacker must know the victim's numeric GitHub team `id`. Given these preconditions, the attack is a single unauthenticated HTTP POST, trivially repeatable.

### Recommendation
In `MembershipHandler#find_or_create_team!`, scope the lookup/update by both `github_id` and `organization` (e.g. `Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login)`) and reject/raise if a team with that `github_id` exists under a different organization. Additionally, verify in `WebhooksController#verify_signature` (or in the handler layer) that every organization-scoped GitHub App config actually has a non-blank `webhook_secret` before accepting webhooks for that org, rather than silently trusting unsigned payloads.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (conceptual addition)
test "membership webhook from an unconfigured org cannot add members to another org's team" do
  victim_team = shipit_teams(:shopify_developers) # organization: 'shopify', github_id: X
  Shipit.stubs(:github_app_config).with('attacker-org').returns({}) # configured, no webhook_secret

  @request.headers['X-Github-Event'] = 'membership'
  body = {
    action: 'added',
    team: { id: victim_team.github_id, name: 'Victim Deployers', slug: 'victim-deployers', url: 'http://example.com' },
    organization: { login: 'attacker-org' },
    member: { login: 'attacker-user' },
    repository: { owner: { login: 'attacker-org' } }
  }.to_json

  assert_no_difference -> { victim_team.members.count } do
    post :create, body:, as: :json
  end
  refute victim_team.reload.members.exists?(login: 'attacker-user')
end
```
This asserts the binding `verified_org('attacker-org') == team.organization('shopify')` must hold before mutation; currently it does not, and the test (as written against current code) would fail, confirming the vulnerability.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks.rb (L19-20)
```ruby
          'status' => [Handlers::StatusHandler],
          'membership' => [Handlers::MembershipHandler],
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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-43)
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

        private

        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
          end
        end
```

**File:** app/models/shipit/team.rb (L7-8)
```ruby
    has_many :memberships
    has_many :members, class_name: :User, through: :memberships, source: :user
```

**File:** app/models/shipit/team.rb (L41-43)
```ruby
    def add_member(member)
      members.append(member) unless members.include?(member)
    end
```

**File:** config/secrets.development.example.yml (L8-16)
```yaml
github:
  app_id:
  installation_id:
  webhook_secret: # nil
  private_key:
  oauth:
    id:
    secret:
    teams: # Optional
```
