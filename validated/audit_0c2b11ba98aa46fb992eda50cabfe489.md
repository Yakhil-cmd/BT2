### Title
Unauthenticated webhook forgery escalates into `Shipit.github_teams` authorization when `webhook_secret` is unset - ([File: lib/shipit/github_app.rb])

### Summary
`GitHubApp#verify_webhook_signature` treats a missing `webhook_secret` as "signature check passed," and this is the value shown in every shipped configuration example (`config/secrets.development.example.yml`, `test/dummy/config/secrets.yml`, `test/dummy/config/secrets_double_github_app.yml` all show `webhook_secret: # nil`). Combined with the `membership` webhook handler, which mutates `Shipit::Team`/`Shipit::Membership` records directly from the untrusted payload, an unprivileged network attacker can forge a GitHub `membership` webhook that adds an arbitrary GitHub login to a team listed in `Shipit.github_teams`, satisfying `User#authorized?` without ever being a real member of that GitHub team.

### Finding Description
Just as the reward-token bug trusted an un-validated relationship between `amount` and `allocatedTokensPerEpoch`, `WebhooksController` trusts a relationship between "the organization the payload claims" and "the fact the request was actually signed by that organization" — but the signature check is a no-op whenever `webhook_secret` is absent: [1](#0-0) 

`verify_signature` only rejects requests when `verified` is `false`; if `webhook_secret` is `nil`, `verify_webhook_signature` unconditionally returns `true`, and the controller proceeds to dispatch the raw, attacker-controlled JSON body to every registered handler for the claimed event type: [2](#0-1) 

The only gate is that `repository_owner` (taken straight from the payload) must resolve to a *configured* organization name — a value that is typically public (it is the GitHub org name), not secret. The `membership` event is one of the default handlers: [3](#0-2) 

and, per `test/controllers/webhooks_controller_test.rb`, this handler creates `Team` records on the fly and adds/removes `Membership` rows purely from the JSON body, with no re-verification against GitHub's actual team membership: [4](#0-3) 

`Shipit::User#authorized?` — the gate used by `Authentication#force_github_authentication` for every privileged UI/action in the engine — is computed purely from local `Membership` rows: [5](#0-4) [6](#0-5) 

So the binding that should hold is:
`organization that cryptographically signed the webhook == organization whose membership/team state gets mutated`
but because `webhook_secret` defaults to unset, the left side collapses to "anyone who can reach the `/webhooks` endpoint and knows a configured org's login," breaking the binding entirely.

### Impact Explanation
An attacker who (a) can sign in through the engine's normal GitHub OAuth flow with their own real GitHub account (an intentionally unprivileged, self-service action — no `Shipit` session, `ApiClient` token, or secret required) and (b) knows the configured GitHub organization's login (public information) can POST a forged `membership` webhook naming their own login as `member.login` and a `team.slug` matching one of `Shipit.github_teams`. This satisfies `authorized?` and grants them full access to the engine's privileged web UI/actions — this is the "escalation into `Shipit.github_teams` authorization" High-severity outcome explicitly called out in scope.

### Likelihood Explanation
Every configuration file shipped with the engine (development example, test dummy, multi-org example) ships `webhook_secret` unset, and nothing in `Shipit::GitHubApp` or `WebhooksController` warns or refuses to start when it is absent — the no-signature path is a normal, silently-accepted runtime state, not a misuse of an undocumented API. Any operator who follows the documented config templates without explicitly adding a webhook secret is exposed, and the `/webhooks` route is unauthenticated by design (it must accept unauthenticated GitHub traffic), so no additional privilege is required to reach it.

### Recommendation
- Make `Shipit::GitHubApp#verify_webhook_signature` fail closed: reject the request (or require an explicit, loud opt-out flag) when `webhook_secret` is blank, instead of returning `true`.
- Have `WebhooksController` refuse to boot/serve if no organization in the configuration has a `webhook_secret` configured, and log/alert prominently in this state.
- For `membership` events specifically, cross-check the claimed membership against a live GitHub API call (or otherwise require corroboration) before mutating `Shipit::Team`/`Shipit::Membership`, rather than trusting the webhook body outright.

### Proof of Concept
1. Deploy the engine with the documented example config (`webhook_secret` left unset for the target organization), which the docs and code both allow.
2. Sign in normally via `/github/auth/github` with a throwaway GitHub account (no team membership required) so `session[:user_id]` is set to this attacker-controlled `User`.
3. POST directly to `/webhooks` with header `X-Github-Event: membership` and no valid `X-Hub-Signature`, with a body such as:
```json
{
  "action": "added",
  "scope": "team",
  "member": { "login": "<attacker-github-login>" },
  "team": { "id": 1, "name": "Developers", "slug": "developers", "url": "https://example.com" },
  "organization": { "login": "<configured-org>" }
}
```
4. Because `verify_webhook_signature` returns `true` (no secret configured), `MembershipHandler` processes the event and creates/attaches a `Membership` linking the attacker's `User` to the `developers` team.
5. If `Shipit.github_teams` includes that team, the attacker's next request to any authenticated page now passes `User#authorized?`, granting full engine access without ever holding real GitHub team membership.

### Citations

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L10-49)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end

    private

    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
    end

    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
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

**File:** test/controllers/webhooks_controller_test.rb (L129-149)
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
