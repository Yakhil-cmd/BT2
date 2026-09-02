### Title
Webhook Signature Verification Is Fully Bypassed When `webhook_secret` Is Unset, Allowing Forged `membership` Events to Grant `Shipit.github_teams` Access - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
The reported bug class is "an action is taken on a field/entity that was never actually covered by the verifying check" (bank account not checked against `whitelisted_tokens`). The equivalent binding in this engine is: *the organization whose webhook secret authenticated the request* == *the organization whose membership/team data is mutated by the event handler*. `WebhooksController#verify_signature` and `GithubApp#verify_webhook_signature` implement this check only when a `webhook_secret` is configured for that organization; when it is not (an explicitly documented, supported configuration), the check silently returns `true` for **any** payload, so the `membership` event handler acts on unauthenticated, attacker-supplied data that ultimately controls `Shipit.github_teams` authorization.

### Finding Description
`WebhooksController#verify_signature` resolves the GitHub App config for the organization named in the payload and asks it to verify the `X-Hub-Signature` header: [1](#0-0) 

The actual cryptographic check lives in `GithubApp#verify_webhook_signature`, which unconditionally trusts the request the moment no `webhook_secret` is configured for that organization: [2](#0-1) 

`webhook_secret` is explicitly documented and shipped as an *optional* setting (`webhook_secret: # nil`) in every secrets template shown to operators: [3](#0-2) [4](#0-3) 

Once signature verification is a no-op, `WebhooksController#create` dispatches the attacker-controlled JSON body directly to the registered handler for whatever `X-Github-Event` header the attacker supplies: [5](#0-4) 

The `membership` event handler trusts the payload to create/delete `Team` records and to add/remove `User` records from those teams — this is demonstrated by the engine's own test suite, which shows a `membership` webhook mutating `Team.count`, `User.count`, and `Membership.count` purely from POSTed JSON: [6](#0-5) 

`Team` membership is precisely the authorization primitive gating access to the whole application: `Authentication#force_github_authentication` only allows a logged-in GitHub user through if they belong to one of `Shipit.github_teams`: [7](#0-6) 

So the binding that should be enforced is: *"the request was verified as originating from GitHub for the organization named in the payload"* == *"the request is allowed to add a user to a `Shipit.github_teams`-controlling `Membership`"*. Because `verify_webhook_signature` returns `true` whenever `webhook_secret` is blank, this equality is never checked in that (documented, supported) configuration, and the handler acts on the unverified `member.login`/`team` fields regardless.

### Impact Explanation
An unprivileged internet attacker who knows (a) the organization login used by the target Shipit deployment (public information — it's the GitHub org name) and (b) that no `webhook_secret` is configured (the default/unset state shown in every shipped secrets template) can POST a forged `membership` event. This lets them add an arbitrary GitHub login (including their own) as a member of a team listed in `Shipit.github_teams`, which is exactly the authorization gate checked by `current_user.authorized?` in `Authentication#force_github_authentication`. This is an authentication-bypass / escalation into `Shipit.github_teams` authorization — one of the explicitly listed High-impact categories — achieved without any GitHub App private key, webhook secret, or Shipit session.

### Likelihood Explanation
Likelihood is high in any deployment that follows the documented, default secrets template without explicitly filling in `webhook_secret` (the field is presented as optional/nil in `config/secrets.development.example.yml` and `docs/setup.md`), since no compensating control exists elsewhere in the request path — `verify_signature`'s only other failure mode is an unknown organization, which does not apply to legitimately configured organizations that simply omitted the secret.

### Recommendation
- Do not allow `verify_webhook_signature` to return `true` when `webhook_secret` is blank; either require a webhook secret to be configured, or refuse to process privilege-sensitive events (`membership`, `pull_request`, `push`) without one.
- Independently validate `membership` (and other identity/authorization-relevant) webhook payloads against `Shipit.github_teams` state fetched from the GitHub API rather than trusting the payload's `team`/`member` fields verbatim, mirroring the recommended fix of validating the "bank account" against a trusted whitelist instead of trusting the caller-supplied account.

### Proof of Concept
1. Deploy Shipit with the documented secrets template, leaving `webhook_secret` unset for organization `acme` (as shown by `config/secrets.development.example.yml`/`docs/setup.md`).
2. As an unauthenticated actor, `POST /webhooks` with header `X-Github-Event: membership` and a JSON body such as `{"action":"added","organization":{"login":"acme"},"team":{"id":1,"name":"Developers","slug":"developers"},"member":{"login":"attacker"},"sender":{"login":"attacker"}}`.
3. `WebhooksController#verify_signature` calls `Shipit.github(organization: "acme").verify_webhook_signature(...)`, which returns `true` immediately because `webhook_secret` is blank [2](#0-1) .
4. The membership handler creates/updates `Membership` for user `attacker` in team `acme/developers`, matching the behavior demonstrated in `test/controllers/webhooks_controller_test.rb:129-180`.
5. If `Shipit.github_teams` includes `acme/developers`, the attacker's GitHub account, once OAuth-authenticated, now passes `current_user.authorized?` in `app/controllers/concerns/shipit/authentication.rb:20-34`, gaining full access to the Shipit UI/API for that deployment.

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

**File:** docs/setup.md (L29-30)
```markdown
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
```

**File:** test/controllers/webhooks_controller_test.rb (L129-180)
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
