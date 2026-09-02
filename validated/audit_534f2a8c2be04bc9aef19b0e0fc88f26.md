### Title
Cross-tenant Team-hijack via `Team.find_or_create_by!(github_id:)` collision in `MembershipHandler#find_or_create_team!` - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`WebhooksController#verify_signature` authenticates a webhook against the GitHub App configured for `repository_owner` (falling back to `organization.login` when no `repository` key is present, e.g. `membership` events), and only proves that the *sender* controls that organization's `webhook_secret`. `MembershipHandler#find_or_create_team!` then looks up a `Team` purely by the attacker-supplied `team.id` integer via `find_or_create_by!(github_id:)`, with no check that the found team's `organization` matches the org that was actually verified. If a `Team` row with that `github_id` already exists for a different (victim) organization, the attacker's chosen member login is added to that victim team.

### Finding Description
The broken binding is: `verified_organization == team.organization` for the `Team` record mutated by `MembershipHandler#process`. This is never enforced.

Path:
- `WebhooksController#repository_owner` at [1](#0-0)  returns `params.dig('organization', 'login')` when no `repository` key is present (true for `membership` events).
- `verify_signature` at [2](#0-1)  resolves `Shipit.github(organization: repository_owner)` and checks the HMAC signature against **that** organization's `webhook_secret`. In a multi-tenant Shipit deployment (`docs/setup.md` "Using Multiple Github Applications", `lib/shipit.rb` `github_app_config`), each organization has its own independent `webhook_secret` [3](#0-2) . This only proves the sender knows the secret for the org named in the payload (`attacker-org`) — it says nothing about any other org's teams.
- `MembershipHandler#find_or_create_team!` at [4](#0-3)  does `Team.find_or_create_by!(github_id: params.team.id)`. `params.team.id` is a fully attacker-controlled integer in the JSON payload (schema only requires it to be an `Integer`, see the `params do ... end` block at [5](#0-4) ). `find_or_create_by!` performs a `find_by(github_id:)` first; if a row already exists (e.g. `victim-org`'s real team, `github_id: 42`, `organization: 'victim-org'`), that existing row is returned **unchanged**, and the `organization:` assignment inside the block is only applied on the create path, never on the find path.
- `process` then does `team.add_member(User.find_or_create_by_login!(params.member.login))` [6](#0-5) , mutating `victim-org`'s team with an attacker-chosen GitHub login, with no comparison of `team.organization` to `params.organization.login`/`repository_owner`.

Attacker request: a `membership` webhook with header `X-Github-Event: membership`, signed (`X-Hub-Signature`) with `attacker-org`'s own `webhook_secret` (known to the attacker because they are the legitimate admin of that tenant org in a multi-org Shipit setup), and body:
```json
{"action":"added","team":{"id":42,"name":"x","slug":"x","url":"https://example.com"},"organization":{"login":"attacker-org"},"member":{"login":"attacker-login"}}
```
No `repository` key is needed. Because `victim-org`'s team happens to have `github_id: 42` (a normal, small, discoverable/GitHub-assigned team ID), the attacker's `attacker-login` user is added as a member of `victim-org`'s team.

Why existing guards fail: `verify_signature`/`Shipit::GitHubApp#verify_webhook_signature` only proves the signer knows `attacker-org`'s secret, not `victim-org`'s; `ExplicitParameters` schema only enforces types, not cross-org consistency; there is no `require_permission!`/scope check in `MembershipHandler`; `Team`'s only DB constraint is uniqueness of `(organization, slug)`, not of `github_id` alone, so a github_id collision across orgs is architecturally reachable, and `Team.find_or_create_by!` never re-verifies `organization`.

### Impact Explanation
If the attacker's login is then added to a `Team` referenced by `Shipit.github_teams` (configured via `oauth.teams` and consumed in `User#authorized?` at [7](#0-6)  and `Authentication#force_github_authentication` at [8](#0-7) ), the attacker becomes an authorized Shipit user for the victim's tenant configuration without ever being a real GitHub member of that team. This matches "High - escalation into `Shipit.github_teams` authorization" from the severity list. The attack is repeatable against any `github_id` the attacker guesses/knows and is cross-tenant (one org's webhook mutates another org's `Team` row), which is out-of-scope for a single-tenant install but directly in-scope where multiple GitHub orgs/tenants share one Shipit instance, as the engine explicitly documents and supports.

### Likelihood Explanation
Requires: (1) a multi-organization Shipit deployment (`secrets.github` keyed by org, per `docs/setup.md`), which is a supported, documented configuration; (2) the attacker controls one of the configured tenant organizations (and thus legitimately possesses that org's own `webhook_secret` — no victim or Shipit secret is needed); (3) a `Team` row already exists in the shared `teams` table for the victim org with a `github_id` the attacker can supply (team IDs are just GitHub's auto-incrementing integers, and are visible via the GitHub API/UI for any team the attacker can view, or brute-forceable given their small numeric range). Given those, the exploit is a single unauthenticated-looking HTTP POST to `/webhooks`, fully repeatable and requiring no elevated Shipit privileges.

### Recommendation
In `MembershipHandler#find_or_create_team!`, scope the lookup to the verified organization, e.g. `Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login)`, and additionally verify `params.organization.login == repository_owner`/the org used in `verify_signature` before performing any mutation, raising/discarding the event on mismatch. Consider also adding a uniqueness constraint on `github_id` scoped per organization (or globally, if `github_id` should be globally unique per organization pairing) to prevent silent collisions.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (new test)
test ":membership cannot add attacker as member of a team belonging to another organization" do
  victim_team = Shipit::Team.create!(organization: 'victim-org', slug: 'devs', name: 'Devs', github_id: 42, api_url: 'https://example.com')

  # Simulate a multi-org config where 'attacker-org' has its own webhook_secret known to the attacker.
  Shipit.stubs(:github).with(organization: 'attacker-org').returns(
    Shipit::GitHubApp.new('attacker-org', webhook_secret: 'attacker-secret')
  )

  payload = {
    action: 'added',
    team: { id: 42, name: 'x', slug: 'x', url: 'https://example.com' },
    organization: { login: 'attacker-org' },
    member: { login: 'attacker-login' }
  }.to_json

  signature = 'sha1=' + OpenSSL::HMAC.hexdigest('sha1', 'attacker-secret', payload)
  @request.headers['X-Github-Event'] = 'membership'
  @request.headers['X-Hub-Signature'] = signature

  post :create, body: payload, as: :json
  assert_response :ok

  victim_team.reload
  # BEFORE fix: this assertion passes, proving the vulnerability (attacker joined victim's team)
  # AFTER fix: this assertion should fail / the request should be rejected instead
  refute victim_team.members.exists?(login: 'attacker-login'),
    "attacker-login should not have been added to victim-org's team via a webhook signed by attacker-org"
end
```
Binding checked explicitly: before the request, `victim_team.organization == 'victim-org'` and the verified webhook organization is `'attacker-org'` (`'victim-org' != 'attacker-org'`); after the (vulnerable) request, `victim_team.members.map(&:login)` includes `'attacker-login'` even though the equality never held — demonstrating the missing check.

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

**File:** app/controllers/concerns/shipit/authentication.rb (L20-34)
```ruby
    def force_github_authentication
      if current_user.logged_in? && current_user.requires_fresh_login?
        Rails.logger.warn("User #{current_user.id} requires a fresh login, logging out...")
        reset_session
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
      elsif Shipit.authentication_disabled? || current_user.logged_in?
        unless current_user.authorized?
          team_handles = Shipit.github_teams.map(&:handle)
          team_list = team_handles.to_sentence(two_words_connector: ' or ', last_word_connector: ', or ')
          render(plain: "You must be a member of #{team_list} to access this application.", status: :forbidden)
        end
      else
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
      end
    end
```
