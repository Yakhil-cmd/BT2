### Title
Signature Verification Silently No-Ops for Any GitHub Organization Without a Configured `webhook_secret`, Allowing Unauthenticated Forgery of `membership` Events That Escalate `Shipit.github_teams` Authorization - (File: `lib/shipit/github_app.rb`, `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` delegates the "is this request really from GitHub" decision entirely to `GitHubApp#verify_webhook_signature`, which unconditionally returns `true` (bypassing HMAC verification) whenever `webhook_secret` is not configured for the resolved organization. Because `webhook_secret` is an optional per-organization config value, any organization onboarded without one causes the trust binding "GitHub HMAC signature verified == request originated from GitHub" to collapse to "always true," letting an unauthenticated network client post arbitrary webhook JSON (including `membership` events) that Shipit processes as legitimate, up to creating teams and granting/adding arbitrary logins to `Shipit.github_teams`-authorized teams.

### Finding Description
`verify_signature` computes the `github_app` for the request's claimed organization and asks it to verify the signature header against the raw body: [1](#0-0) 

`GitHubApp#verify_webhook_signature` is the sole authenticity check, and it explicitly short-circuits to `true` when no `webhook_secret` was configured for that organization: [2](#0-1) 

`webhook_secret` is read straight from the deployment's config with no enforced presence check: [3](#0-2) 

Once "verified," `WebhooksController#create` parses the raw JSON and dispatches to whatever handler is registered for the attacker-supplied `X-Github-Event` header, with zero further authentication: [4](#0-3) 

The `membership` event is wired to a handler that creates `Team` and `Membership` records straight from payload data — behavior exercised in the test suite by posting arbitrary `team`/`member` JSON and asserting `Team`/`Membership`/`User` rows are created or deleted: [5](#0-4) [6](#0-5) 

The binding the mitigation in the analog report protects ("funds flushed only after being verified as owed to the correct claimant") maps here to: "an event is dispatched to state-mutating handlers only if the delivering party's identity (GitHub) was cryptographically verified." That binding is broken whenever `webhook_secret` is absent for an organization: verification silently degrades to "always pass," so the identity check that authorization decisions downstream (e.g., team membership, which directly feeds `User#authorized?` via `Shipit.github_teams`) depend on is never actually performed. [7](#0-6) 

### Impact Explanation
This breaks the equality "verified webhook signature == request authenticated by GitHub" whenever an org's `webhook_secret` is unset, letting an unprivileged, unauthenticated network attacker POST a crafted `membership` webhook to the public `/github/webhooks` endpoint. Because the `MembershipHandler` creates/mutates `Team` and `Membership` rows straight from attacker-controlled JSON, this is a direct escalation into `Shipit.github_teams` authorization — explicitly listed as a High-severity impact in this engine's rules (bypassing the team-membership gate that `force_github_authentication` relies on to grant application access) via `User#authorized?`. [8](#0-7) 

### Likelihood Explanation
Exploitability depends entirely on operator configuration: any organization/GitHub App installation that does not set `github.webhook_secret` in Shipit's deployment secrets (an optional field per the setup documentation and per the code path that treats it as merely `.presence`-checked) is exposed with no additional attacker capability required — no session, no `ApiClient` token, no GitHub App private key, and critically, no knowledge of any secret at all, since the vulnerability is the *absence* of a secret to guess, not the possession of one.

### Recommendation
Require `webhook_secret` to be present for every configured organization/app and fail closed (reject the request) if it is missing, rather than treating an absent secret as an implicit "trust everyone" bypass in `GitHubApp#verify_webhook_signature`.

### Proof of Concept
1. Deploy Shipit with a GitHub organization configured without `github.webhook_secret` (a valid, documented configuration).
2. As an unauthenticated network client, `POST /github/webhooks` with header `X-Github-Event: membership` and a JSON body such as `{"action":"added","team":{...},"organization":{"login":"<that org>"},"member":{"login":"attacker-controlled-login"}}` and any (or no) `X-Hub-Signature` value.
3. `verify_signature` resolves `Shipit.github(organization: "<that org>")`, whose `verify_webhook_signature` returns `true` unconditionally because `webhook_secret` is blank.
4. `create` dispatches to `MembershipHandler`, which creates/updates the `Membership`/`Team` records exactly as demonstrated in `test/controllers/webhooks_controller_test.rb` lines 129-181, without any cryptographic proof the request came from GitHub.
5. If the targeted team is one of `Shipit.github_teams`, the newly-created membership record grants application authorization to the attacker-chosen login the next time that user (or a user record matched to that login) authenticates.

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

**File:** lib/shipit/github_app.rb (L44-51)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]
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

**File:** app/models/shipit/webhooks.rb (L6-23)
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
      end
```

**File:** test/controllers/webhooks_controller_test.rb (L129-181)
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
        post :create, body: membership_params.merge(action: 'removed', member: { login: 'bob' }).to_json, as: :json
        assert_response :ok
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
