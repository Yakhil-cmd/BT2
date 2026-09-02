### Title
Optional/absent `webhook_secret` disables GitHub webhook signature verification, allowing authentication bypass of the `/webhooks` endpoint - ([File: lib/shipit/github_app.rb])

### Summary
The engine's inbound-webhook trust boundary is: `signature_valid? == payload_is_authentically_from_GitHub`. `GitHubApp#verify_webhook_signature` implements this check, but silently degrades to `true` whenever no `webhook_secret` is configured for the organization being addressed, collapsing the equality to `true == (anything the requester sends)`. This mirrors the Aave finding's pattern of a "security" `require`/check that can be trivially neutralized, except here the neutralization is a built-in code branch rather than an on-chain balance manipulation.

### Finding Description
`WebhooksController` gates all webhook processing behind a single `before_action`: [1](#0-0) 

That action resolves the GitHub App config for the organization named in the payload and delegates verification to it: [2](#0-1) 

The verification method itself is: [3](#0-2) 

`return true unless webhook_secret` means that for any organization configured without a `webhook_secret` (an explicitly optional field, per the app config schema which just does `@webhook_secret = @config[:webhook_secret].presence`), **every** POST to `/webhooks` claiming that organization is accepted as genuine, regardless of the `X-Hub-Signature` header content or absence. `params = JSON.parse(request.raw_post)` is then dispatched unmodified to the registered handlers: [4](#0-3) 

The default handler set processes security-relevant events without any further authenticity check, including `status` (CI status), `membership` (org team membership), `pull_request`, and `check_suite`: [5](#0-4) 

The `membership` handler creates/removes `Team`/`Membership`/`User` records straight from the forged payload (observed behavior, not a privileged action): [6](#0-5) 

Team membership is exactly what gates the whole application's authorization model: [7](#0-6) [8](#0-7) 

Similarly, forged `status` events feed directly into the CI-gating logic used to decide whether a commit/PR is deployable or mergeable: [9](#0-8) [10](#0-9) 

**Binding broken (as an equality):** `signature_verified(request) == authentic_GitHub_event` is supposed to hold before any handler mutates state. When `webhook_secret` is unset for an organization, the left side is hard-coded to `true`, so the equality degenerates to `true == request_from_anyone`, i.e. no verification occurs at all.

### Impact Explanation
An unauthenticated, unprivileged network attacker who knows (or guesses) a valid organization/repository name configured in the target Shipit instance can:
- Forge `membership` events to add themselves (or any GitHub login) to a `Team` that matches `Shipit.github_teams`, escalating into the application's authorization gate (`current_user.authorized?`), which is explicitly a listed High-severity outcome ("escalation into `Shipit.github_teams` authorization").
- Forge `status`/`check_suite` events to mark arbitrary commits as passing required CI checks, which feed `Merge_request#any_status_checks_failed?`/`Commit#deployable?` and can enable an unauthorized merge or deploy of unreviewed code — a Critical-severity outcome per the rules ("an unauthorized deploy, rollback or merge").

No Shipit session, ApiClient token, `webhook_secret`, `api_clients_secret`, or GitHub App private key is required by the attacker — the flaw is precisely that the secret the app is supposed to check against does not need to be known because the check is skipped.

### Likelihood Explanation
The `webhook_secret` field is optional in the GitHub App configuration schema (`@config[:webhook_secret].presence`), and nothing in the engine enforces its presence at boot, in `Shipit.github_app_config`, or before mounting `resources :webhooks, only: :create` in the routes. Any deployment that installs a GitHub App and does not additionally set a webhook secret (or that configures a second/legacy organization without one, since multi-org secrets are configured independently per-organization) is exposed with zero additional attacker effort beyond sending a POST request with a spoofed `X-Github-Event` header and JSON body.

### Recommendation
Fail closed instead of failing open: `verify_webhook_signature` should reject the request (return `false`/`422`) when `webhook_secret` is blank instead of returning `true`, and/or the engine should refuse to boot / refuse to route `/webhooks` for any organization whose GitHub App config lacks a `webhook_secret`. At minimum, `WebhooksController#verify_signature` should treat a missing secret as "cannot verify" and reject rather than "verified".

### Proof of Concept
1. Configure Shipit with a GitHub App for organization `acme` but leave `webhook_secret` unset (permitted by the config schema).
2. As an unauthenticated attacker, send:
```
POST /webhooks
X-Github-Event: membership
Content-Type: application/json

{"action":"added","organization":{"login":"acme"},
 "team":{"id":1,"name":"Deployers","slug":"deployers","url":"https://example.com"},
 "member":{"login":"attacker-controlled-login"}}
```
`verify_signature` calls `Shipit.github(organization: "acme").verify_webhook_signature(nil, body)`, which returns `true` because `webhook_secret` is `nil`, bypassing `head(422)`. The `membership` handler then creates the team/membership as if it came from GitHub, exactly as demonstrated functionally in `test/controllers/webhooks_controller_test.rb:129-165` (that test only differs in that a real deployment's secret check would normally block an unsigned request — here it doesn't).
3. Repeat with a `status` event forging `state: "success"` for a target `sha`, satisfying `required_statuses` used by `deploy_spec.rb`/`merge_request.rb`, to force an unauthorized deploy or merge.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L6-6)
```ruby
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature
```

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

**File:** test/controllers/webhooks_controller_test.rb (L129-165)
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
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```

**File:** app/controllers/concerns/shipit/authentication.rb (L25-30)
```ruby
      elsif Shipit.authentication_disabled? || current_user.logged_in?
        unless current_user.authorized?
          team_handles = Shipit.github_teams.map(&:handle)
          team_list = team_handles.to_sentence(two_words_connector: ' or ', last_word_connector: ', or ')
          render(plain: "You must be a member of #{team_list} to access this application.", status: :forbidden)
        end
```

**File:** app/models/shipit/deploy_spec.rb (L194-204)
```ruby
    def required_statuses
      (Array.wrap(config('ci', 'require')) + blocking_statuses).uniq
    end

    def soft_failing_statuses
      Array.wrap(config('ci', 'allow_failures'))
    end

    def blocking_statuses
      Array.wrap(config('ci', 'blocking'))
    end
```

**File:** app/models/shipit/merge_request.rb (L193-206)
```ruby
    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end

    def any_status_checks_failed?
      status = StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec)
      status.failure? || status.error?
    end

    def any_status_checks_missing?
      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).missing?
    end
```
