### Title
Unsigned `organization.login` trusted for both webhook signature verification and `Team#organization` write in `membership` events allows unauthenticated `Team`/`Membership` row forgery - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`WebhooksController#verify_signature` selects which `GitHubApp` (and thus which `webhook_secret`) to use for signature verification via `repository_owner`, which for `membership` events falls back to the unsigned `params.dig('organization','login')` field. `MembershipHandler#find_or_create_team!` trusts that exact same unsigned field to set `team.organization` on newly created `Team` rows. When the resolved app's `webhook_secret` is absent/nil, `GitHubApp#verify_webhook_signature` short-circuits to `true`, so an attacker can pick any organization name, get "verified", and have arbitrary `Team`/`Membership` rows created for that org name.

### Finding Description
Binding claimed broken: `repository_owner` (used in `Shipit.github(organization: repository_owner)` at `app/controllers/shipit/webhooks_controller.rb:25`) == `params.organization.login` (used in `team.organization =` at `app/models/shipit/webhooks/handlers/membership_handler.rb:41`). Both are read from `params.dig('organization', 'login')` [1](#0-0) , and this value is never part of any HMAC-covered secret comparison distinct from the org it names — `verify_webhook_signature` only checks the raw body against whatever secret belongs to the org named by that same field [2](#0-1) , and `find_or_create_team!` writes `team.organization = params.organization.login` unconditionally on record creation [3](#0-2) .

Trace confirmed: `before_action :check_if_ping, :drop_unhandled_event, :verify_signature` runs before `create` [4](#0-3) . For `membership`, there is no `repository` key, so `repository_owner` falls back to `organization.login`. `Shipit.github(organization: repository_owner)` resolves a `GitHubApp` instance whose `webhook_secret` comes from config [5](#0-4) . `verify_webhook_signature` returns `true` immediately `unless webhook_secret` [6](#0-5) . In the single-app config schema (the default/dummy test setup), `github_default_organization` returns `nil` and `Shipit.github(organization:)` ignores the passed org name entirely, using the single global config [7](#0-6)  — and that config's `webhook_secret` is `null` in the dummy test secrets [8](#0-7) . So for this schema, no signature is ever required for any org name, confirmed. In the multi-org schema (`github_app_config`), if `organization` doesn't match a configured org key, `GithubOrganizationUnknown` is raised and the request is rejected with 422 [9](#0-8) , but if the org name *does* match a configured org whose `webhook_secret` happens to be blank (documented as commonly left blank, e.g. `config/secrets.development.shopify.yml:9,18`), the same bypass applies.

`MembershipHandler#process` then calls `find_or_create_team!`, keyed by `github_id: params.team.id` (also fully attacker-supplied) [10](#0-9) . If no `Team` row already has that `github_id`, a brand-new row is created with attacker-chosen `organization`, `slug`, `name`, `api_url` (via `team.github_team = params.team`) [11](#0-10) , and a `Membership` is created linking an attacker-named user login (auto-vivified via `User.find_or_create_by_login!`) to that team [12](#0-11) . This is exactly what the repo's own controller tests demonstrate (no signature header at all is even sent) [13](#0-12) .

No existing guard closes this: `drop_unhandled_event` only checks the event has a registered handler (membership does) [14](#0-13) ; `ExplicitParameters` schema in `MembershipHandler.params` only validates types/presence, not provenance [15](#0-14) ; `Team` model has a DB unique index on `(organization, slug)` but no validation preventing arbitrary organization names [16](#0-15) .

### Impact Explanation
Per request, an unauthenticated attacker can create an arbitrary `Team` row (attacker-chosen `organization`, `slug`, `name`, `github_id`) plus a `Membership` linking an attacker-named GitHub login to it, with no valid webhook signature, as long as the resolved `GitHubApp` for that org name has no `webhook_secret` configured (true for the default/dummy single-app schema, and possible in multi-org schemas per the documented setup examples that leave `webhook_secret` blank). This is repeatable against any org name and any team `github_id` not already present in the DB. If an operator later adds `"<attacker-org>/<attacker-slug>"` to `github.oauth.teams`, `Team.find_or_create_by_handle` does `find_by(organization:, slug:) || fetch_and_create_from_github(...)` [17](#0-16)  — it will find the attacker-planted row first (matching on the unique `organization`/`slug` pair) instead of fetching the real team from GitHub, and `User#authorized?` gates access purely on membership in `Shipit.github_teams` [18](#0-17) . This is a direct path to `Shipit.github_teams` authorization escalation (High), contingent on that specific config coincidence; the unconditional part of the finding (unauthenticated Team/Membership row creation for arbitrary org names when `webhook_secret` is absent) is a confirmed authentication-bypass on the webhook endpoint.

### Likelihood Explanation
Requires only that the org named in the webhook payload resolves (via `Shipit.github`) to a `GitHubApp` config with no `webhook_secret`. This is the actual behavior of the default/documented single-app config schema (`github_default_organization` nil path), and is explicitly present in the shipped dummy/test secrets and in documented example multi-org configs that leave `webhook_secret` blank. No GitHub credentials, no Shipit session, and no prior webhook delivery are needed — the attacker only needs to know (or guess) the org name Shipit is configured for, which is typically public (repository owner name). Cost is a single unauthenticated `POST /webhooks` request; fully repeatable.

### Recommendation
Do not let the same untrusted payload field simultaneously select the verification secret and populate persisted data. Require a `webhook_secret` to be present for every configured organization (fail closed instead of `return true unless webhook_secret`), and/or verify `organization.login` against a known/allow-listed set of orgs (e.g., ones with existing `GithubHook::Organization` records with matching `secret`) rather than trusting the payload field directly for both authentication and mutation.

### Proof of Concept
```ruby
test "membership webhook creates forged Team without a valid signature when webhook_secret is absent" do
  # binding under test: repository_owner (verification) == params.organization.login (mutation)
  assert_nil Shipit.github(organization: 'shopify').send(:webhook_secret)

  @request.headers['X-Github-Event'] = 'membership'
  # no X-Hub-Signature header sent at all
  payload = {
    action: 'added',
    team: { id: 999_999, name: 'Evil Team', slug: 'evil-team', url: 'https://example.com' },
    organization: { login: 'shopify' },
    member: { login: 'attacker' }
  }.to_json

  assert_difference -> { Shipit::Team.count }, 1 do
    assert_difference -> { Shipit::Membership.count }, 1 do
      post :create, body: payload, as: :json
      assert_response :ok
    end
  end

  team = Shipit::Team.find_by(github_id: 999_999)
  assert_equal 'shopify', team.organization
  assert_equal 'evil-team', team.slug
end
```

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L4-16)
```ruby
  class WebhooksController < ActionController::Base
    skip_before_action :verify_authenticity_token, raise: false
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature

    respond_to :json

    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end

```

**File:** app/controllers/shipit/webhooks_controller.rb (L19-22)
```ruby
    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** lib/shipit/github_app.rb (L44-57)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]

      oauth = (@config[:oauth] || {}).with_indifferent_access
      @oauth_id = oauth[:id]
      @oauth_secret = oauth[:secret]
      @oauth_teams = Array.wrap(oauth[:teams])
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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L36-43)
```ruby
        private

        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
          end
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

**File:** lib/shipit.rb (L196-200)
```ruby
  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
```

**File:** test/dummy/config/secrets.test.json (L7-12)
```json
  "github": {
    "domain": null,
    "app_id": 42,
    "installation_id": 43,
    "bot_login": "shipit[bot]",
    "webhook_secret": null,
```

**File:** app/models/shipit/team.rb (L18-21)
```ruby
      def find_or_create_by_handle(handle)
        organization, slug = handle.split('/').map(&:downcase)
        find_by(organization:, slug:) || fetch_and_create_from_github(organization, slug)
      end
```

**File:** app/models/shipit/team.rb (L53-58)
```ruby
    def github_team=(github_team)
      self.name = github_team.name
      self.slug = github_team.slug
      self.api_url = github_team.url
      self.github_id = github_team.id
    end
```

**File:** test/controllers/webhooks_controller_test.rb (L129-140)
```ruby
    test ":membership creates the mentioned team on the fly" do
      @request.headers['X-Github-Event'] = 'membership'
      assert_difference -> { Team.count }, 1 do
        post :create, as: :json, body: membership_params.merge(team: {
                                                                 id: 48,
                                                                 name: 'Ouiche Cooks',
                                                                 slug: 'ouiche-cooks',
                                                                 url: 'https://example.com'
                                                               }).to_json
        assert_response :ok
      end
    end
```

**File:** db/migrate/20140226233935_create_baseline.rb (L148-158)
```ruby
    create_table "teams", force: :cascade do |t|
      t.integer  "github_id",    limit: 4
      t.string   "api_url",      limit: 255
      t.string   "slug",         limit: 50
      t.string   "name",         limit: 255
      t.string   "organization", limit: 39
      t.datetime "created_at",               null: false
      t.datetime "updated_at",               null: false
    end

    add_index "teams", ["organization", "slug"], name: "index_teams_on_organization_and_slug", unique: true, using: :btree
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
