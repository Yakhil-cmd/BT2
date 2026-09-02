### Title
Webhook membership events with no configured `webhook_secret` bypass signature verification and grant `Shipit.github_teams` authorization - ([File: lib/shipit/github_app.rb])

### Summary
`Shipit::GithubApp#verify_webhook_signature` unconditionally returns `true` when no `webhook_secret` is configured for the organization the incoming payload claims to belong to. Combined with the `membership` webhook handler creating `Team`/`User`/`Membership` records directly from the unverified payload, this lets a completely unprivileged, unauthenticated requester forge a webhook that adds an arbitrary GitHub login to a team Shipit treats as authorized, bypassing the `Shipit.github_teams` gate in `Shipit::Authentication`.

### Finding Description
The report's root cause pattern is "a value used to change privileged state is never covered by the mechanism meant to attest to it." The same pattern exists in `WebhooksController`'s trust chain:

- `verify_webhook_signature` is the only gate protecting `WebhooksController#create`:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [1](#0-0) 

If the organization resolved from the payload (`repository_owner`) has no `webhook_secret` configured, verification is skipped entirely — the request is accepted regardless of whether it ever came from GitHub: [2](#0-1) 

- `WebhooksController#create` then dispatches the raw, unverified JSON body straight to event handlers:
```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
  head(:ok)
end
``` [3](#0-2) 

- The `membership` event is routed to `Handlers::MembershipHandler`: [4](#0-3) 

- The existing test suite confirms this handler mutates authorization-relevant state directly from payload content, with no independent call back to the GitHub API to confirm the claimed membership: it creates a `Team` on the fly, creates a `User` on the fly, and appends/removes `Membership` rows purely from `team`, `member.login`, and `action` fields in the JSON body: [5](#0-4) 

- `Team#add_member` simply appends the member with no re-verification against GitHub: [6](#0-5) 

- Authorization to use the entire Shipit UI (triggering deploys, rollbacks, tasks, etc.) is gated solely on team membership:
```ruby
def authorized?
  @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
end
``` [7](#0-6) 
and enforced in the session-based authentication concern: [8](#0-7) 

**Binding broken (equality that should hold, but doesn't for orgs without a secret):**
`payload.team/member data that grants authorization == data cryptographically attested by GitHub via HMAC signature`. When `webhook_secret` is unset for an organization, the left side is fully attacker-controlled while the right side is a no-op, so the equality collapses — any POST body is accepted as if it came from GitHub.

### Impact Explanation
An attacker with no Shipit credentials at all (no session, no `ApiClient` token, no `webhook_secret`) can POST a forged `membership` event naming a team matching one of `Shipit.github_teams` and a `member.login` equal to their own GitHub login (which they can already authenticate to Shipit with via normal OAuth, since `User#authorized?` is the only additional gate). This creates a `Membership` row that satisfies `authorized?`, granting them full use of the Shipit web application (deploy/rollback triggering, task execution, stack settings) despite never actually belonging to the required GitHub team/org. This is a direct escalation into `Shipit.github_teams` authorization, one of the explicitly listed High-impact categories.

### Likelihood Explanation
The precondition is that at least one configured GitHub organization has no `webhook_secret` set. This is not a hypothetical misconfiguration invented for this report — the engine's own example/dev configuration ships this exact state (`webhook_secret: # nil`) as a documented, apparently supported configuration: [9](#0-8) 
The code path (`return true unless webhook_secret`) exists specifically to accommodate this configuration, so it is a first-class behavior of the engine rather than an operator error outside the engine's control. Any deployment that leaves `webhook_secret` blank for convenience or during initial setup is immediately exploitable by any unauthenticated internet client that can reach the `/webhooks` endpoint.

### Recommendation
- Short term: make `verify_webhook_signature` fail closed — reject (422) requests when `webhook_secret` is blank instead of treating a missing secret as "verification passed." At minimum, require `webhook_secret` to be present for any organization that registers `membership`/authorization-relevant hooks, and refuse to process such events without one.
- Long term: don't let a single unauthenticated webhook payload directly mutate authorization state. Have `MembershipHandler` re-fetch and confirm team membership from the GitHub API (as `Team#refresh_members!` already does) rather than trusting the webhook body's `team`/`member`/`action` fields verbatim, so a compromised or unauthenticated delivery channel cannot forge authorization grants.

### Proof of Concept
1. Deploy Shipit with an organization configured without `webhook_secret` (a state the shipped example config explicitly allows, see `config/secrets.development.shopify.yml`).
2. As an unauthenticated client, POST to `/webhooks` with header `X-Github-Event: membership` and no valid `X-Hub-Signature` (or any arbitrary value), with a JSON body such as:
```json
{
  "action": "added",
  "team": { "id": 48, "name": "Authorized Team", "slug": "authorized-team", "url": "https://example.com" },
  "member": { "login": "attacker-github-login" },
  "organization": { "login": "the-org-with-no-secret" }
}
```
3. `verify_signature` calls `verify_webhook_signature(nil_or_garbage, raw_post)`, which returns `true` because `webhook_secret` is blank for that org (`lib/shipit/github_app.rb` lines 76-83).
4. `MembershipHandler` creates the `Team` (matching `Shipit.github_teams`) and a `Membership` linking `attacker-github-login`'s eventual `User` record to it, exactly as exercised by `test/controllers/webhooks_controller_test.rb` lines 129-165.
5. The attacker then completes the normal GitHub OAuth login flow to Shipit as `attacker-github-login`; `User#authorized?` now returns `true` due to the forged `Membership`, granting full access to the Shipit UI and its deploy/rollback/task capabilities.

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

**File:** app/models/shipit/team.rb (L41-43)
```ruby
    def add_member(member)
      members.append(member) unless members.include?(member)
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

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
```
