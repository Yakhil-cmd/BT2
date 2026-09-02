### Title
Webhook Signature Verification Is Silently Disabled When No `webhook_secret` Is Configured, Enabling Unauthenticated Forgery of GitHub Events (Including Team-Membership Grants) - ([File: app/controllers/shipit/webhooks_controller.rb], [File: lib/shipit/github_app.rb])

### Summary
`WebhooksController#verify_signature` delegates HMAC verification to `GitHubApp#verify_webhook_signature`, which unconditionally returns `true` whenever no `webhook_secret` is configured for the organization the *attacker's own payload* claims to belong to. Because `webhook_secret` is an optional config key (and is left blank in the engine's own installation template), an unprivileged network attacker can send a crafted, unsigned POST to the webhooks endpoint and have it treated as an authentic GitHub event — including `membership` events that create `Team`/`Membership` records used to authorize access to the whole Shipit UI.

### Finding Description
`WebhooksController#verify_signature` selects which GitHub App/secret to check against using data taken directly from the unauthenticated request body: [1](#0-0) [2](#0-1) 

`repository_owner` is derived from `params.dig('repository', 'owner', 'login')` or `params.dig('organization', 'login')` — both attacker-controlled fields inside the very JSON body being validated. This value is passed into `Shipit.github(organization: repository_owner)`, which looks up the corresponding app config and secret: [3](#0-2) 

The actual signature check is: [4](#0-3) 

`return true unless webhook_secret` means that if the resolved organization's config has no `webhook_secret` set, **verification is completely bypassed** — regardless of the actual `X-Hub-Signature` header or its correctness. Since `webhook_secret` is never enforced as mandatory anywhere in config loading (`TOP_LEVEL_GH_KEYS`, `github_app_config`), and the engine's own scaffolding leaves it blank by default: [5](#0-4) 

any deployment that hasn't explicitly populated `webhook_secret` (single-org or per-org in multi-org mode) accepts **arbitrary, unsigned webhook payloads** from anyone who can reach the `/webhooks` endpoint — no GitHub App private key, no `api_clients_secret`, no session, and no prior repository access is required.

This breaks the intended binding: *the GitHub organization that cryptographically authenticated the request* vs. *the organization identifier taken from the unverified payload used to decide whether authentication is even required*. Once bypassed, `WebhooksController#create` dispatches the forged payload to all registered handlers for the claimed event type: [6](#0-5) 

Among the built-in handlers is the `membership` handler, which creates `Team`/`Membership`/`User` records straight from payload contents with no further authentication (demonstrated by the existing test suite): [7](#0-6) 

`Shipit::Authentication#force_github_authentication` grants full application access based purely on team membership matching `Shipit.github_teams`: [8](#0-7) [9](#0-8) 

By forging a `membership` webhook that adds a controlled/known `User` (login) to a `Team` matching one of `Shipit.github_teams`, an attacker who already has *any* legitimate Shipit user account (or can trigger creation of one via the same forged event, per the `:membership creates the mentioned user on the fly` test) can grant themselves `authorized?` status and gain unrestricted access to the Shipit web application — including triggering deploys, rollbacks, and viewing/altering stack configuration.

### Impact Explanation
This is an authentication-bypass class issue: the webhook signature check — the only barrier protecting the `/webhooks` endpoint — can be entirely disabled by an unauthenticated attacker by simply omitting a valid signature and having the resolved organization's config lack a `webhook_secret` (which is the out-of-the-box state produced by `template.rb`). The consequence is direct escalation into `Shipit.github_teams` authorization (granting full application access to an attacker-controlled login) as well as forgery of other trust-sensitive events (`status`, `push`, `pull_request`, `merge`), satisfying the "High — escalation into `Shipit.github_teams` authorization" (and potentially "Critical — authentication bypass") impact bar defined in scope.

### Likelihood Explanation
Likelihood is high for any deployment that follows the shipped `template.rb` scaffolding without explicitly filling in `webhook_secret` (a config key with no presence validation anywhere in the engine), and for any multi-organization configuration where even one organization's app config omits the field. No credentials, GitHub App keys, repository write access, or Shipit sessions are needed to send the forged request — only network reachability of the `/webhooks` route.

### Recommendation
- Make `webhook_secret` a required, validated configuration value (fail closed) instead of silently accepting unsigned requests when it is absent, i.e., change `verify_webhook_signature` to reject the request when `webhook_secret` is blank rather than returning `true`.
- Do not resolve which organization/secret to use for signature verification from unauthenticated payload fields; if multi-tenant verification is needed, verify against all configured secrets or bind the mapping through a source not controlled by the request body.
- Update `template.rb` to generate a mandatory random `webhook_secret` by default, matching the treatment already given to `secret_key_base`.

### Proof of Concept
1. Deploy Shipit using the default `template.rb`-generated `secrets.yml`, or any config where `github.webhook_secret` (or the relevant org config) is left blank.
2. Send an unauthenticated POST to `/webhooks` with header `X-Github-Event: membership` and no valid `X-Hub-Signature`, with a body such as:
```json
{
  "action": "added",
  "organization": { "login": "<configured-org-without-secret>" },
  "team": { "id": 48, "name": "Developers", "slug": "developers", "url": "https://example.com" },
  "member": { "login": "attacker-controlled-login" }
}
```
3. Because `repository_owner`/`organization.login` resolves to an org whose config has no `webhook_secret`, `verify_webhook_signature` returns `true` unconditionally (`lib/shipit/github_app.rb:76-83`), the request passes `verify_signature`, and the `membership` handler creates the `Team`/`Membership` record exactly as shown in `test/controllers/webhooks_controller_test.rb:129-173` — without any legitimate GitHub-signed request ever having been sent.
4. If `Shipit.github_teams` includes the targeted team, the attacker's account is now authorized to log in and use the full Shipit application per `app/models/shipit/user.rb:80-82`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** template.rb (L61-113)
```ruby
%w(config/secrets.yml config/secrets.example.yml).each do |path|
  create_file path, <<~CODE, force: true
    development:
      app_name: My Shipit
      secret_key_base: #{SecureRandom.hex(64)}
      host: 'http://localhost:3000'
      redis_url: redis://localhost
      github:
        domain: # defaults to github.com
        bot_login:
        app_id:
        installation_id:
        webhook_secret:
        private_key:
        oauth:
          id:
          secret:
          # team: MyOrg/developers # Enable this setting to restrict access to only the member of a team

    test:
      app_name: My Shipit
      secret_key_base: #{SecureRandom.hex(64)}
      host: 'http://localhost:4000'
      redis_url: redis://localhost
      github:
        domain: # defaults to github.com
        bot_login:
        app_id:
        installation_id:
        webhook_secret:
        private_key:
        oauth:
          id: <%= ENV['GITHUB_OAUTH_ID'] %>
          secret: <%= ENV['GITHUB_OAUTH_SECRET'] %>
          # teams: MyOrg/developers # Enable this setting to restrict access to only the member of a team

    production:
      app_name: My Shipit
      secret_key_base: <%= ENV['SECRET_KEY_BASE'] %>
      host: <%= ENV['SHIPIT_HOST'] %>
      redis_url: <%= ENV['REDIS_URL'] %>
      github:
        domain: # defaults to github.com
        app_id: <%= ENV['GITHUB_APP_ID'] %>
        installation_id: <%= ENV['GITHUB_INSTALLATION_ID'] %>
        webhook_secret:
        private_key:
        oauth:
          id: <%= ENV['GITHUB_OAUTH_ID'] %>
          secret: <%= ENV['GITHUB_OAUTH_SECRET'] %>
          # teams: MyOrg/developers # Enable this setting to restrict access to only the member of a team
      env:
        # SSH_AUTH_SOCK: /foo/bar # You can set environment variable that will be present during deploys.
```

**File:** test/controllers/webhooks_controller_test.rb (L129-173)
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

    test ":membership creates the mentioned user on the fly" do
      @request.headers['X-Github-Event'] = 'membership'
      Shipit.github.api.expects(:user).with('george').returns(george)
      assert_difference -> { User.count }, 1 do
        post :create, body: membership_params.merge(member: { login: 'george' }).to_json, as: :json
        assert_response :ok
      end
    end

    test ":membership can delete an user membership" do
      @request.headers['X-Github-Event'] = 'membership'
      assert_difference -> { Membership.count }, -1 do
        post :create, body: membership_params.merge(action: 'removed').to_json, as: :json
        assert_response :ok
      end
    end

    test ":membership can append an user membership" do
      @request.headers['X-Github-Event'] = 'membership'
      assert_difference -> { Membership.count }, 1 do
        post :create, body: membership_params.merge(member: { login: 'bob' }).to_json, as: :json
        assert_response :ok
      end
    end

    test ":membership can append an user twice" do
      @request.headers['X-Github-Event'] = 'membership'
      assert_no_difference -> { Membership.count } do
        post :create, body: membership_params.to_json, as: :json
        assert_response :ok
      end
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

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
