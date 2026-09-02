### Title
Unauthenticated Webhook Signature Bypass Escalates into `Shipit.github_teams` Authorization - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and therefore which `webhook_secret`) to verify a webhook against using an attacker-controlled field of the unauthenticated JSON body, and `GitHubApp#verify_webhook_signature` unconditionally accepts any payload when that configuration has no `webhook_secret` set. Because the org used for this selection is not bound to the org/team/repository actually acted upon by the event handlers, an unauthenticated caller can pick any "empty-secret" org name to sail through signature verification, then supply a completely different `organization`/`team`/`member` payload that is processed as legitimate. Since `membership` webhook events feed directly into `Shipit::Team`/`Shipit::Membership` records used by `User#authorized?`, this can be leveraged to grant an attacker's own GitHub account membership in a `Shipit.github_teams`-authorized team, escalating from zero credentials to full application access.

### Finding Description
`verify_signature` derives the org used to pick a `GitHubApp` config purely from the untrusted body: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` resolves per-org config from `secrets.github`, one of potentially many configured organizations in a multi-tenant install: [3](#0-2) 

Crucially, signature verification is a no-op when that org's `webhook_secret` is blank: [4](#0-3) 

The binding that should hold is: *"the org whose secret authenticated this payload" == "the org/team/repository the payload's handler actually mutates."* That binding is never enforced — `repository_owner`/`organization.login` (used only to pick a secret) and the deeper payload fields (`team`, `member`, `repository.full_name`) consumed by the handlers are independent, attacker-supplied values inside the same unauthenticated JSON body. Handlers resolve their target purely from these payload fields, e.g. `Handler#repository_name`: [5](#0-4) 

The `membership` event handler creates `Team`/`Membership`/`User` records directly from attacker-supplied `team`/`member`/`organization` payload fields (confirmed by the passing test suite behavior): [6](#0-5) 

These `Membership` records are exactly what gates application-wide authorization: [7](#0-6) [8](#0-7) 

### Impact Explanation
If any org configured in `secrets.github` (a legitimate, documented "optional" field) has no `webhook_secret`, an unauthenticated attacker can:
1. POST to `/webhooks` with `X-Github-Event: membership` and `organization.login` set to that secretless org — `verify_webhook_signature` returns `true` unconditionally, so no valid `X-Hub-Signature` is needed at all.
2. In the same payload, set `team` to the handle of a team listed in `Shipit.github_teams` and `member.login` to the attacker's own GitHub username.
3. `MembershipHandler` creates/updates a `Membership` linking the attacker's `User` record to that authorized `Team`.
4. On next OAuth login, `User#authorized?` returns `true` for the attacker, since it only checks local `Membership` rows against `Shipit.github_teams` — granting full access to deploy, rollback, and merge through the Shipit UI.

This directly matches the High-impact category "escalation into `Shipit.github_teams` authorization," and depending on subsequent actions (deploy/rollback), can lead to unauthorized deploys.

### Likelihood Explanation
No credentials, session, `ApiClient` token, or `webhook_secret` are required — only that the deployment has at least one organization/app configuration without a `webhook_secret` set, which the project's own setup documentation calls out as optional. The attack requires only a single unauthenticated HTTP POST with a crafted JSON body and correct `X-Github-Event` header; no timing races or destructive side effects are needed.

### Recommendation
- Never short-circuit signature verification (`return true unless webhook_secret`) — require a configured secret in production, or fail closed.
- Bind the org/repo resolved for **authentication** (`repository_owner`) to the org/repo/team actually **acted upon** by each handler, rejecting payloads where these diverge.
- Make `Team`/`Membership` mutations driven by webhooks additionally verify that the event's authenticated organization matches the team's/organization's expected identity before writing.

### Proof of Concept
Given a multi-org `secrets.github` configuration where org `foo` has no `webhook_secret`:
```
POST /webhooks
X-Github-Event: membership

{
  "action": "added",
  "organization": { "login": "foo" },
  "team": { "id": 1, "slug": "developers", "name": "Developers", "url": "https://example.com" },
  "member": { "login": "attacker-github-login" }
}
```
`verify_signature` looks up `Shipit.github(organization: "foo")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` regardless of any (or missing) `X-Hub-Signature` header (`lib/shipit/github_app.rb:76-77`). The `membership` handler then creates a `Membership` linking `attacker-github-login` to team `developers` (`test/controllers/webhooks_controller_test.rb:159-165` demonstrates this exact code path being exercised by a stub). If `developers` is one of `Shipit.github_teams`, the attacker is now authorized on next login (`app/models/shipit/user.rb:80-82`).

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L36-38)
```ruby
        def repository_name
          payload.dig('repository', 'full_name')
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
