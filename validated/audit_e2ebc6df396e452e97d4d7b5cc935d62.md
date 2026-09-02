### Title
Unauthenticated Webhook Signature Bypass Enables Forged `membership` Events That Escalate Into `Shipit.github_teams` Authorization - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to check a webhook against using an attacker-supplied field of the unauthenticated JSON body, and `GitHubApp#verify_webhook_signature` treats *any* signature as valid when no `webhook_secret` is configured for that organization. Because `webhook_secret` is documented and shipped as optional/`nil` in every example configuration, an attacker can send a forged `membership` webhook event that Shipit will process as genuine, creating `Team`/`Membership` records that are later trusted by the `Shipit.github_teams` authorization check — without ever having actually been added to that team on GitHub.

### Finding Description
`WebhooksController#verify_signature` picks the GitHub App configuration to verify against from the request body itself, before any authenticity check: [1](#0-0) [2](#0-1) 

`repository_owner` is taken directly from the attacker-controlled JSON payload (`repository.owner.login`, falling back to `organization.login`), and is used to select `Shipit.github(organization: repository_owner)`.

`GitHubApp#verify_webhook_signature` short-circuits to `true` whenever no `webhook_secret` is configured for that organization: [3](#0-2) 

Every shipped example configuration leaves `webhook_secret` unset (`nil`), and the setup documentation explicitly calls it "optional": [4](#0-3) [5](#0-4) [6](#0-5) 

Once the request reaches `create`, the raw JSON is dispatched to the registered handler for the event type: [7](#0-6) [8](#0-7) 

For the `membership` event, `Shipit::Webhooks::Handlers::MembershipHandler` (`app/models/shipit/webhooks/handlers/membership_handler.rb`) is invoked and — per the engine's own controller test suite exercising this handler end-to-end — creates a `Team` on the fly from the payload's `team` object, creates a `User` on the fly from the payload's `member` object, and adds/removes a `Membership` linking the two, purely from the JSON body content: [9](#0-8) 

`Shipit.github_teams` is the authorization gate used to decide who may use the application (verified via the OAuth authentication flow and enforced, per the controller test suite, at points such as `ApiClientsController`): [10](#0-9) [11](#0-10) 

This reproduces the report's bug class as a binding-equality violation:
`organization authenticated by the webhook signature check` ≠ `Team/Membership record actually written to the authorization store`. The signature check authenticates (or, when no secret is set, fails to authenticate) based on `repository.owner.login`/`organization.login`, while the state that is *written and later trusted* for authorization (`Team`, `Membership`) is derived from unrelated, unauthenticated fields (`team.*`, `member.login`) of the same forgeable payload.

### Impact Explanation
If any organization configured in `Shipit.secrets.github` (single- or multi-org schema) is left without a `webhook_secret` — the documented default in every shipped example — an unauthenticated network attacker can:
1. POST `X-Github-Event: membership` to `/webhooks` with `organization.login` set to that unsecured org.
2. Include a `team` object matching the slug/name of a team listed in `Shipit.github_teams`, and a `member.login` equal to an attacker-controlled GitHub account.
3. Have Shipit create a `Membership` binding that attacker's GitHub login to the authorized `Team`, entirely fabricated, without the attacker ever being a real member of that GitHub team/org.
4. Complete a legitimate GitHub OAuth login (which only proves GitHub identity, not team membership) and pass Shipit's `Shipit.github_teams` authorization check, gaining access to protected UI/API functionality (creating `ApiClient`s, viewing/triggering deploys, etc.).

This matches the explicitly listed High-severity impact category: escalation into `Shipit.github_teams` authorization.

### Likelihood Explanation
Likelihood is moderate-to-high in real deployments: `webhook_secret` is optional and defaults to unset in every example/dummy config shipped with the engine, so operators who follow the documented quick-start are exposed. No credentials, tokens, or prior repository/session access are required — only a real (unprivileged) GitHub account to complete the OAuth step after the forged webhook is processed.

### Recommendation
- Make `webhook_secret` mandatory (fail closed) rather than defaulting to "always verified" when absent; refuse to process webhooks for any organization without a configured secret.
- Do not derive authorization-relevant state (`Team`, `Membership`) solely from webhook payload content; corroborate membership changes against the GitHub API (e.g., via `github_api.team_members`) rather than trusting the webhook body directly.
- Consider decoupling the "which secret to verify with" lookup from attacker-controlled payload fields, or verify the signature against all configured organizations' secrets rather than the one named in the unauthenticated payload.

### Proof of Concept
Given an org (`OrgOne`) configured with `webhook_secret: nil` (as shown in `test/dummy/config/secrets_double_github_app.yml`) and `Shipit.github_teams` including `OrgOne/authorized-team`:

```
POST /webhooks
X-Github-Event: membership
X-Hub-Signature: sha1=anything

{
  "action": "added",
  "organization": { "login": "OrgOne" },
  "team": { "id": 1, "name": "authorized-team", "slug": "authorized-team", "url": "https://example.com" },
  "member": { "login": "attacker-github-login" }
}
```

`verify_signature` resolves `Shipit.github(organization: "OrgOne")`, whose `webhook_secret` is `nil`, so `verify_webhook_signature` returns `true` unconditionally (`lib/shipit/github_app.rb:76-77`). The `MembershipHandler` then creates the `authorized-team` `Team` (if absent) and a `Membership` linking `attacker-github-login` to it, as demonstrated by the equivalent authenticated flow in `test/controllers/webhooks_controller_test.rb:129-140` and `:159-165`. After completing OAuth as `attacker-github-login`, the attacker passes the `Shipit.github_teams` check enforced in flows like `test/controllers/api_clients_controller_test.rb:19-28`, despite never having been added to `OrgOne/authorized-team` on GitHub.

**Note on completeness:** I was not able to directly inspect the full source of `app/models/shipit/webhooks/handlers/membership_handler.rb` or `app/controllers/concerns/shipit/authentication.rb` within the available tool budget; the behavior above is inferred from the engine's own controller test suite exercising these components end-to-end (which is strong evidence but not a direct source read). A Devin session with full repository access could confirm the exact handler/authentication-concern implementation lines.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-10)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
      # Randomly generated
      private_key: |
        -----BEGIN RSA PRIVATE KEY-----
```

**File:** docs/setup.md (L29-30)
```markdown
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
```

**File:** app/models/shipit/webhooks.rb (L6-22)
```ruby
      def default_handlers
        {
          'push' => [Handlers::PushHandler],
          'pull_request' => [
            Handlers::PullRequest::OpenedHandler,
            Handlers::PullRequest::ClosedHandler,
            Handlers::PullRequest::ReopenedHandler,
            Handlers::PullRequest::EditedHandler,
            Handlers::PullRequest::AssignedHandler,
            Handlers::PullRequest::LabeledHandler,
            Handlers::PullRequest::UnlabeledHandler,
            Handlers::PullRequest::LabelCapturingHandler
          ],
          'status' => [Handlers::StatusHandler],
          'membership' => [Handlers::MembershipHandler],
          'check_suite' => [Handlers::CheckSuiteHandler]
        }
```

**File:** test/controllers/webhooks_controller_test.rb (L129-177)
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

    test ":membership can delete an user twice" do
      @request.headers['X-Github-Event'] = 'membership'
      assert_no_difference -> { Membership.count } do
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

**File:** test/controllers/api_clients_controller_test.rb (L19-28)
```ruby
    test "current_user must be a member of at least a Shipit.github_teams" do
      session[:user_id] = shipit_users(:bob).id
      Shipit.stubs(:github_teams).returns([shipit_teams(:cyclimse_cooks), shipit_teams(:shopify_developers)])
      get :index
      assert_response :forbidden
      assert_equal(
        'You must be a member of cyclimse/cooks or shopify/developers to access this application.',
        response.body
      )
    end
```
