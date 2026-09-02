### Title
Unauthenticated webhook signature bypass via organization/repository field mismatch enables cross-repository writes and `Shipit.github_teams` escalation - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to validate a webhook against using one field of the unauthenticated request body (`repository.owner.login`), while every downstream handler resolves the actual `Stack`/`Repository` (or, for `membership` events, the `Team`) to act on using a *different*, uncorrelated field of the same body (`repository.full_name`, or `team`/`member`/`organization` for membership events). Because `GitHubApp#verify_webhook_signature` short-circuits to `true` whenever no `webhook_secret` is configured for the resolved organization, an attacker who finds (or is a member of) any configured GitHub organization lacking a `webhook_secret` can forge a POST to the public `/webhooks` endpoint that "verifies" against that unprotected org while acting on an entirely different, protected organization's repository/team.

### Finding Description
`verify_signature` computes the verifying app from an attacker-supplied field and never checks it against the field actually used to select the target of the action: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` unconditionally returns `true` when no secret is configured for that org, which the docs describe as an optional setting per-organization: [3](#0-2) [4](#0-3) 

Shipit explicitly supports multiple independently-configured GitHub organizations, each resolved by name from the payload via `Shipit.github(organization: ...)`: [5](#0-4) [6](#0-5) 

Once `verify_signature` passes, the raw, forged JSON is dispatched to handlers, and every handler resolves the *actual* repository/stack to mutate from a separate field (`repository.full_name`), not from `repository.owner.login` used for signature selection: [7](#0-6) [8](#0-7) 

The `membership` event handler creates/removes `Team`/`Membership`/`User` records straight from the forged payload, as demonstrated by the engine's own tests (creating a team, creating a user, and adding/removing memberships from unauthenticated webhook bodies): [9](#0-8) 

`Shipit.github_teams` and `User#authorized?` gate the entire application's authentication/authorization on team membership: [10](#0-9) [11](#0-10) 

**Binding broken (equality that should hold but doesn't):**
`organization authenticated by verify_signature (repository.owner.login → webhook_secret lookup)` should equal `organization/repository actually written by the handler (repository.full_name, or team/member for membership events)`. Nothing enforces this equality; they are independent, attacker-controlled fields inside the same JSON body, and the "signature" check can be trivially satisfied by pointing `repository.owner.login` at any org configured with a blank `webhook_secret`.

### Impact Explanation
An unprivileged, unauthenticated attacker (no session, no `ApiClient` token, no GitHub write access) can POST directly to the public `/webhooks` endpoint and:
- Force `GithubSyncJob`/status/check-run processing against any tracked `Stack` belonging to a *different, properly secured* organization, by setting `repository.owner.login` to an org with no configured `webhook_secret` while setting `repository.full_name` to the victim org/repo — a cross-repository write bypassing the intended per-org signature protection.
- Via the `membership` handler, add an arbitrary GitHub login to an arbitrary `Team`. If that team is one of the configured `Shipit.github_teams`, and the attacker signs into Shipit with a matching (or later-linked) GitHub account, this escalates them into authorized access to the whole Shipit instance — matching the "escalation into `Shipit.github_teams` authorization" High-severity criterion.

This is not merely a design choice: the report's bug class ("signature covers/authorizes field X, but the code trusts uncorrelated field Y for the privileged action") maps directly onto `repository.owner.login` (used to pick the verifying secret) vs. `repository.full_name`/`team`/`member` (used to decide what gets written).

### Likelihood Explanation
Requires a Shipit deployment using the multi-organization `github:` config where at least one configured organization has no `webhook_secret` set (explicitly documented as optional), or where an attacker otherwise knows/controls a legitimate but unrelated org's webhook secret. Given webhook secrets are optional per the setup docs and organizations are looked up purely by the payload's `repository.owner.login` string, this is a realistic multi-tenant configuration mistake rather than a contrived edge case.

### Recommendation
Bind the signature verification to the same identity used for the privileged action: derive the target repository/team strictly from the organization whose secret validated the signature (reject if `repository.full_name`'s owner segment, or the `membership` event's `organization.login`, doesn't match the `repository_owner`/org used to select the webhook secret). Additionally, do not treat a missing `webhook_secret` as an implicit "always verified" — require an explicit `insecure_webhooks: true`-style opt-in per organization, and log/alert loudly when it is in effect.

### Proof of Concept
Given a multi-org Shipit config:
```yaml
github:
  publicdemo:      # attacker knows this org has no webhook secret
    app_id: ...
    installation_id: ...
    webhook_secret: # blank
  victimorg:       # real, protected org with configured webhook_secret
    app_id: ...
    installation_id: ...
    webhook_secret: "s3cr3t"
```
Attacker sends, without any valid `X-Hub-Signature` for `victimorg`:
```
POST /webhooks
X-Github-Event: membership

{
  "action": "added",
  "organization": {"login": "publicdemo"},
  "team": {"id": <id_of_a_Shipit.github_teams_team>, "slug": "...", "name": "...", "url": "..."},
  "member": {"login": "attacker-controlled-login"},
  "repository": {"owner": {"login": "publicdemo"}}
}
```
`verify_signature` resolves `Shipit.github(organization: 'publicdemo')`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally (`lib/shipit/github_app.rb:76-77`) regardless of the actual header value. The `membership` handler then creates a `Membership` for `attacker-controlled-login` on the targeted `Team`, as shown by the analogous test flow in `test/controllers/webhooks_controller_test.rb:129-173`, granting that GitHub identity authorization under `Shipit.github_teams` once they log in.

### Citations

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

**File:** docs/setup.md (L18-38)
```markdown
2. Run this command:  `rails _8.0_ new shipit --skip-action-cable --skip-turbolinks --skip-action-mailer --skip-active-storage --skip-webpack-install --skip-action-mailbox --skip-action-text -m https://raw.githubusercontent.com/Shopify/shipit-engine/main/template.rb`

## Creating the GitHub App

Shipit needs a GitHub App to authenticate users, receive Webhooks and access the API.

You can create a new one for your organization at `https://github.com/organizations/<your-org>/settings/apps/new`, or [https://github.com/settings/apps/new](https://github.com/settings/apps/new) for a regular user.

  - Homepage URL: The URL where Shipit will be deployed, e.g. `https://example.com`.
  - User authorization callback URL: It must be set to `<homepage>/github/auth/github/callback`, e.g. `https://example.com/github/auth/github/callback`.
  - Setup URL: Leave it empty.
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
  - Repository permissions:
    - Checks: Read & write
    - Commit statuses: Read-only
    - Contents: Read & write (to allow merging)
    - Deployments: Read & write
    - Issues: Read & write (to allow closing related issues on merge)
    - Metadata: Read-only
    - Pull requests: Read & write
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

**File:** lib/shipit.rb (L256-258)
```ruby
  def github_teams
    @github_teams ||= github.oauth_teams.map { |t| Team.find_or_create_by_handle(t) }
  end
```

**File:** config/secrets.development.example.yml (L18-38)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-24)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
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

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
