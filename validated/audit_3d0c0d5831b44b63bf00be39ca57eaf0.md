### Title
Webhook Signature Verified Against `repository.owner.login` While All Handlers Act on the Unbound `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which `GitHubApp` (and therefore which `webhook_secret`) is used to authenticate an inbound webhook based solely on `params.dig('repository','owner','login')` (falling back to `organization.login`). Every downstream `Shipit::Webhooks::Handlers::Handler` instead resolves the repository to act on using a *different* field of the same payload, `payload.dig('repository', 'full_name')`. These two fields are never cross-validated against each other, so the organization whose credentials authenticated the request is not guaranteed to be the organization whose repository/stack is actually mutated.

### Finding Description
`Shipit.github(organization:)` looks up a `GitHubApp` per configured organization key in `secrets.github`, each with its own optional `webhook_secret` [1](#0-0) . `WebhooksController#verify_signature` derives that organization purely from the payload's `repository.owner.login` and calls `verify_webhook_signature` on that org's `GitHubApp`: [2](#0-1) 

Critically, `GitHubApp#verify_webhook_signature` treats a missing/blank `webhook_secret` as an automatic pass: `return true unless webhook_secret`, i.e. no HMAC check is performed at all for an organization configured without a webhook secret. The docs explicitly call the webhook secret "optional": [3](#0-2) [4](#0-3) 

Once `verify_signature` passes, the entire raw JSON body (`params`) — not just the `repository.owner.login` sub-field used for authentication — is dispatched unmodified to every handler for the event: [5](#0-4) 

Every handler, however, resolves the target `Repository`/`Stack` using an entirely different field, `repository.full_name`, via `Handler#repository_name` and `Repository.from_github_repo_name`: [6](#0-5) [7](#0-6) 

This is the exact binding break called out by the rules: **the organization that authenticated (`repository.owner.login`, checked against org X's `GitHubApp`) is not equal to the repository that is written (`repository.full_name`, resolved to any org's `Repository`/`Stack` row in the database)**. Nothing ties these two payload fields together, and when the authenticating organization has no `webhook_secret` configured, no cryptographic binding exists at all — any unprivileged caller can `POST` an arbitrary JSON body to `/webhooks` with `repository.owner.login` set to the unsecured org (auto-verified) and `repository.full_name` set to a *different*, secured organization's repository, and the request will be dispatched to that repository's handlers as if it were a legitimate signed GitHub event.

Concretely reachable handlers include:
- `PushHandler`, which calls `stack.sync_github(expected_head_sha:)` for every non-archived stack matching the spoofed `repository.full_name`/branch [8](#0-7) .
- `MembershipHandler`, which creates/removes `Team`/`Membership`/`User` records purely from payload content (as shown creating teams/users/memberships on the fly in the controller tests) [9](#0-8) , which is significant because `Shipit.github_teams` (built from `oauth_teams`) gates who is `authorized?` to use the whole application via `force_github_authentication` [10](#0-9) .

### Impact Explanation
This breaks the "organization authenticated vs. repository written" binding named in scope. Depending on which handler is reached, the impact ranges from unauthorized state changes on a stack belonging to a different, unrelated GitHub organization configured on the same Shipit instance (triggering `GithubSyncJob`, forcing resync of arbitrary commits/branches) up to manipulation of `Team`/`Membership` records that feed directly into `Shipit.github_teams` authorization checks — i.e. escalation into the authorization system, which is explicitly listed as a High-severity impact category.

### Likelihood Explanation
This requires a Shipit deployment configured with the multi-organization `secrets.github` schema where at least one configured organization omits `webhook_secret` (documented as optional in `docs/setup.md`). Given that condition, exploitation requires nothing more than an unauthenticated `POST` to the public `/webhooks` endpoint with a crafted JSON body — no session, API token, or GitHub credentials of any kind are needed, matching the "unprivileged attacker" requirement. The likelihood is conditional on this configuration pattern (single-org deployments where `github_default_organization` is `nil` are not affected the same way, since there is only one `GitHubApp`/secret to check against), but the code contains no safeguard preventing it, and the "optional" framing in the setup docs makes the vulnerable configuration foreseeable/likely in real multi-tenant deployments.

### Recommendation
- Make `webhook_secret` mandatory for every configured GitHub organization (fail closed rather than `return true unless webhook_secret`).
- In `WebhooksController#verify_signature`, after verifying the signature for the organization derived from `repository.owner.login`, additionally assert that `repository.owner.login` matches the owner embedded in `repository.full_name` before dispatching to handlers, so the authenticated organization and the organization whose repository is mutated are provably the same value.

### Proof of Concept
1. Configure Shipit with two organizations in `secrets.github`, e.g. `orgA` (no `webhook_secret` set) and `orgB` (with a `webhook_secret`, hosting a real tracked `Stack`).
2. As an anonymous attacker, `POST /webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "orgA" },
    "full_name": "orgB/tracked-repo"
  }
}
```
3. `verify_signature` calls `Shipit.github(organization: 'orgA')`; since `orgA` has no `webhook_secret`, `verify_webhook_signature` returns `true` unconditionally without checking any `X-Hub-Signature` header.
4. `WebhooksController#create` dispatches the full payload to `PushHandler`, which resolves `Repository.from_github_repo_name('orgb/tracked-repo')` and calls `stack.sync_github(expected_head_sha: ...)` on `orgB`'s real stack — a write performed on `orgB`'s data despite the request only ever being "authenticated" (trivially, via the absent-secret bypass) against `orgA`.

### Citations

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

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
```ruby
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-39)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
      end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
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
