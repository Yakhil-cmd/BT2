### Title
Webhook signature verification silently no-ops when `webhook_secret` is unset, allowing unauthenticated forged GitHub events to escalate team authorization and forge CI status - (File: `lib/shipit/github_app.rb`)

### Summary
`GitHubApp#verify_webhook_signature` returns `true` unconditionally whenever no `webhook_secret` is configured for the organization, and `WebhooksController` relies on this method as its only authenticity check before dispatching handlers that mutate authorization-relevant state (`Team`/`Membership`) and commit CI status. Since the setup docs describe the webhook secret as *optional*, an installation that follows the documented/example configuration is fully exposed: any unauthenticated internet client can POST arbitrary JSON to `/webhooks` and have it processed as if GitHub had sent it.

### Finding Description
`verify_webhook_signature` is the sole gate protecting the public `/webhooks` endpoint: [1](#0-0) 

```
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
```

`WebhooksController#verify_signature` calls this and dispatches to handlers if it returns truthy, with no other authentication: [2](#0-1) 

The organization used to pick the `GitHubApp` (and thus whether a secret exists) is taken straight from the unauthenticated request body: [3](#0-2) 

The `webhook_secret` field is explicitly documented as **optional** both in the example secrets file and the setup guide: [4](#0-3) [5](#0-4) 

This breaks the trust binding the report's bug-class targets: *"organization that authenticated" versus "the repository/state that is written"*. Here, the equality that should hold is:

`(request accepted by /webhooks) == (request cryptographically proven to originate from GitHub via HMAC-SHA1 over webhook_secret)`

When `webhook_secret` is blank, the left side is always true while the right side never gets evaluated meaningfully — the check is fail-open, not fail-closed.

Handlers reachable this way include ones that directly mutate authorization state, e.g. the `membership` handler which creates `Team` and `Membership` records purely from unauthenticated JSON (verified in the test suite, where `verify_signature` is stubbed to `true` and a crafted `membership` payload creates teams/users/memberships): [6](#0-5) 

Because `Shipit.github_teams` authorization (`app/controllers/concerns/shipit/authentication.rb`) is driven by `Team`/`Membership` records, forging membership webhooks lets an attacker add arbitrary GitHub logins to a team that Shipit trusts for access control: [7](#0-6) 

Additionally the `status` handler creates `Status` rows tied to a commit purely from the forged payload, which is used to satisfy `ci.require`/blocking-status gates that guard deploys and the merge queue: [8](#0-7) 

### Impact Explanation
- Escalation into `Shipit.github_teams` authorization: forging a `membership` event lets an unauthenticated actor add any GitHub login (including their own) to a `Team` Shipit trusts, granting them login access to the Shipit UI/API as an "authorized" user. This matches the High-impact bucket explicitly listed in scope ("escalation into `Shipit.github_teams` authorization").
- Forging `status`/`check_suite` events lets the attacker mark arbitrary commits as passing CI (`ci.require`, blocking statuses), which can enable an unauthorized deploy/merge of a commit that never actually passed CI — matching "an unauthorized deploy, rollback, or merge" impact.
- Because the endpoint is unauthenticated and public by design (it must be reachable by GitHub), this requires no session, `ApiClient` token, GitHub App private key, or repository write access — satisfying the "unprivileged attacker" requirement.

### Likelihood Explanation
The vulnerable behavior is triggered by the documented, supported configuration ("Webhook secret (optional)"), meaning any deployment that follows the shipped example config (`config/secrets.development.example.yml`, which ships with `webhook_secret: # nil`) or otherwise chooses to skip the optional secret is exploitable by any internet client with no prerequisite compromise. This is a configuration-dependent but engine-native fail-open behavior in `lib/shipit/github_app.rb`, not a third-party gem defect or a documentation/best-practice-only issue.

### Recommendation
Make `webhook_secret` mandatory rather than optional, and fail closed (reject with 422/401) when it is not configured, instead of `return true unless webhook_secret`. If backward compatibility must be preserved, at minimum emit a hard startup error/warning and refuse to process authorization-sensitive events (`membership`, `status`, `check_suite`) when no secret is present.

### Proof of Concept
1. Deploy Shipit using the example configuration where `github.webhook_secret` is left blank (as shown in `config/secrets.development.example.yml`, and explicitly allowed as "optional" per `docs/setup.md`).
2. As an unauthenticated attacker, send:
```
POST /webhooks
X-Github-Event: membership
Content-Type: application/json

{
  "action": "added",
  "scope": "team",
  "member": { "login": "attacker" },
  "team": { "id": 1, "name": "some-authorized-team", "slug": "some-authorized-team", "url": "https://example.com" },
  "organization": { "login": "the-org" }
}
```
3. `verify_webhook_signature` returns `true` (no `webhook_secret` configured), so the request bypasses `head(422)` and is dispatched to the `membership` handler.
4. A `Membership` record is created binding `attacker` to `some-authorized-team`, and if that team is in `Shipit.github_teams`, `attacker` can now log in and pass `force_github_authentication`'s `current_user.authorized?` check.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L4-30)
```ruby
  class WebhooksController < ActionController::Base
    skip_before_action :verify_authenticity_token, raise: false
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature

    respond_to :json

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
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** test/controllers/webhooks_controller_test.rb (L42-59)
```ruby
    test ":state create a Status for the specific commit" do
      request.headers['X-Github-Event'] = 'status'

      commit = shipit_commits(:first)

      body = JSON.parse(payload(:status_master)).merge(repository_params).to_json
      assert_difference 'commit.statuses.count', 1 do
        post :create, body:, as: :json
      end

      status = commit.statuses.last
      status_payload = JSON.parse(payload(:status_master))
      assert_equal status_payload['target_url'], status.target_url
      assert_equal status_payload['state'], status.state
      assert_equal status_payload['description'], status.description
      assert_equal status_payload['context'], status.context
      assert_equal status_payload['created_at'], status.created_at.iso8601
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
