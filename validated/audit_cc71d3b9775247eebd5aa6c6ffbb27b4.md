### Title
Webhook signature verification is bypassed when no `webhook_secret` is configured, allowing forged `membership` events to escalate into `Shipit.github_teams` authorization - (File: `lib/shipit/github_app.rb`)

### Summary
`WebhooksController#verify_signature` delegates trust entirely to `GithubApp#verify_webhook_signature`, which short-circuits to `true` whenever no `webhook_secret` is configured for the organization derived from the unauthenticated request body itself. Because `webhook_secret` is explicitly documented as *optional*, a deployment following the documented setup can leave signature verification permanently disabled, letting anyone POST a forged `membership` webhook that grants themselves team membership used to gate application authorization.

### Finding Description
`WebhooksController#verify_signature` looks up the GitHub App config from the **unverified** payload (`repository_owner`) and asks it to verify the signature: [1](#0-0) 

The actual verification, in `GithubApp#verify_webhook_signature`, returns `true` unconditionally when no `webhook_secret` was configured for that organization — it never falls back to rejecting the request: [2](#0-1) 

The setup documentation explicitly marks `webhook_secret` as optional, so a deployment built exactly as documented can end up with signature verification effectively disabled: [3](#0-2) [4](#0-3) 

Once verification passes (trivially, with no secret set), `Shipit::Webhooks.for_event('membership')` handlers run directly on attacker-controlled JSON, creating teams, creating users, and adding/removing `Shipit::Membership` records — confirmed by the controller's own behavioral tests: [5](#0-4) 

Team membership recorded this way is exactly what gates application-wide authorization in `Authentication#force_github_authentication`, via `current_user.authorized?` checked against `Shipit.github_teams`: [6](#0-5) 

**Binding broken:** *"organization authenticated by a verified GitHub webhook signature" == "organization/team-membership state trusted to grant `Shipit.github_teams` authorization"*. Because the signature check can be a no-op for any organization without a configured secret, an unprivileged, unauthenticated attacker can supply the "authenticated organization" side of that equality for free, while still fully controlling the membership payload that feeds the authorization side.

### Impact Explanation
This is a High-impact escalation into `Shipit.github_teams` authorization: an attacker with no Shipit session, no `ApiClient` token, and no GitHub credentials can add their own GitHub login to a `Shipit::Membership`/`Team` combination that `force_github_authentication` treats as sufficient to access the entire application (stacks, deploys, tasks, API client management), effectively bypassing the authentication gate described in `app/controllers/concerns/shipit/authentication.rb`.

### Likelihood Explanation
Likelihood is high in any deployment that follows the documented, optional-secret configuration (shown as the default in `docs/setup.md` and the example secrets file). No GitHub App private key, installation access, or session is required — only knowledge of the target org login and a POST to `/webhooks` with `X-Github-Event: membership`.

### Recommendation
Require `webhook_secret` to be present and reject (422) any webhook when it is not configured, instead of treating a missing secret as an automatic pass in `GithubApp#verify_webhook_signature`. Additionally, do not trust `repository_owner`/`organization.login` extracted from the unverified body to select which secret/config to verify against without an independent binding (e.g., per-installation ID validated from GitHub, not user-supplied JSON).

### Proof of Concept
1. Deploy Shipit with a GitHub App configuration that omits `webhook_secret` (as permitted/documented in `docs/setup.md`).
2. As an unauthenticated attacker, send:
```
POST /webhooks
X-Github-Event: membership

{
  "action": "added",
  "organization": {"login": "<target-org>"},
  "team": {"id": 1, "name": "Ouiche Cooks", "slug": "ouiche-cooks", "url": "https://example.com"},
  "member": {"login": "<attacker-login>"}
}
```
3. `WebhooksController#verify_signature` calls `GithubApp#verify_webhook_signature`, which returns `true` because `webhook_secret` is blank (`lib/shipit/github_app.rb:76-77`).
4. The membership handler processes the event and creates a `Shipit::Membership` for `<attacker-login>` in the specified team, matching the behavior verified in `test/controllers/webhooks_controller_test.rb:129-165`.
5. `<attacker-login>` logs into Shipit via OAuth; `force_github_authentication` now finds them a member of a team in `Shipit.github_teams` and grants full application access.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** docs/setup.md (L29-30)
```markdown
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
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
