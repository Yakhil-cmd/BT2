### Title
Unsigned `membership` webhooks are accepted and write `Team`/`Membership` records when an organization's `webhook_secret` is unset - ([File: lib/shipit/github_app.rb], [File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`GitHubApp#verify_webhook_signature` unconditionally returns `true` when `webhook_secret` is blank, so `WebhooksController#verify_signature` treats any request as authentic for organizations configured without a `webhook_secret`. This lets an unauthenticated attacker POST a forged `membership`/`added` payload that `MembershipHandler#process` will use to create a `Team` and write a `Membership` row, without any GitHub-signed request ever occurring.

### Finding Description
The binding claimed by `verify_signature` is: `verify_webhook_signature(sig, body) == true` implies "a webhook GitHub actually produced and signed with this org's secret." In `lib/shipit/github_app.rb`: [1](#0-0) 

the very first line, `return true unless webhook_secret`, breaks this binding whenever an organization entry in the app config has no `webhook_secret` set (the config schema explicitly allows this — see `test/dummy/config/secrets_double_github_app.yml` and `config/secrets.development.shopify.yml`, both showing `webhook_secret: # nil` as a supported configuration, and `docs/setup.md` describing it as optional, "if you've set a webhook secret ... copy it here").

`WebhooksController#verify_signature` resolves the app purely from the attacker-controlled payload field `repository.owner.login` / `organization.login`, then trusts whatever `verify_webhook_signature` returns: [2](#0-1) [3](#0-2) 

No other guard exists in the request path: `check_if_ping` and `drop_unhandled_event` do not check authenticity, and `Handler` (base class of `MembershipHandler`) has no signature or authorization logic of its own — it just parses the payload and calls `process`: [4](#0-3) 

`MembershipHandler#process` then unconditionally trusts `params.team.id`, `params.organization.login`, and `params.member.login` to create/find a `Team` and add a member: [5](#0-4) 

Exploit flow: attacker sends `POST /webhooks` with header `X-Github-Event: membership`, no valid `X-Hub-Signature` (or an arbitrary garbage value), and a JSON body `{ "action": "added", "team": { "id": <any Shipit.github_teams id>, "name": ..., "slug": ..., "url": ... }, "organization": { "login": "<org-with-no-webhook_secret>" }, "member": { "login": "<attacker-controlled-login>" } }`. Because that organization's `webhook_secret` is unset, `verify_webhook_signature` returns `true` regardless of the signature header/body, the request passes `verify_signature`, and `MembershipHandler` writes a real `Membership` row associating the attacker-chosen `member.login` (via `User.find_or_create_by_login!`) with the targeted `Team`. This is directly demonstrated by the existing test suite's own membership tests using no meaningful signature verification stubbing: [6](#0-5) .

Existing guards (`drop_unhandled_event`, `ExplicitParameters` schema, `Handler#stacks`) only shape/validate payload structure; none of them re-establish authenticity once `verify_webhook_signature` short-circuits to `true`.

### Impact Explanation
An attacker who knows (or guesses) the login of an organization configured in Shipit without a `webhook_secret` can forge arbitrary `membership` events. If the targeted `team.id` corresponds to an entry referenced by that org's `Shipit.github_teams`/`oauth.teams` configuration (used to gate access, per `GitHubApp#oauth_teams`), the attacker can insert an arbitrary GitHub login (which they can also control by creating that GitHub account) into that team's membership in Shipit's database — a `Membership` row is created for a repository/organization that never authenticated the request. Since team membership can back authorization decisions (`Shipit.github_teams` gating), this is an escalation path into Shipit's authorization boundary, and more broadly an authentication-bypass on the webhook endpoint itself for any organization lacking a secret (affecting other event types too, e.g., `push`, `status`, `pull_request`, `check_suite` — not just membership). This matches the Critical category "authentication bypass (forged webhook ... accepted)" and, if used to gain team membership backing authorization, the High category "escalation into `Shipit.github_teams` authorization." Repeatable indefinitely against any organization in the config missing `webhook_secret`.

### Likelihood Explanation
The only precondition is that a given organization entry in the app's `github:` config has `webhook_secret` unset/blank — which the codebase's own sample configs and test fixtures show as a valid, unremarkable configuration state (not merely a theoretical misconfiguration), and which the setup docs describe as optional rather than mandatory. No secrets, sessions, or privileged roles are required by the attacker; only knowledge of the target organization's GitHub login (public information) and the ability to send an HTTP POST. This makes exploitation low-cost and fully repeatable.

### Recommendation
Fail closed instead of failing open: `GitHubApp#verify_webhook_signature` should return `false` (or the app should refuse to boot / reject all webhooks for that org) when `webhook_secret` is blank, rather than treating missing configuration as "trust everything." Additionally, enforce presence of `webhook_secret` for every configured GitHub organization at startup/config-load time.

### Proof of Concept
```ruby
# test/unit/github_app_test.rb (new test)
test "verify_webhook_signature returns false, not true, when webhook_secret is blank" do
  app = Shipit::GitHubApp.new('some-org', { app_id: 1, installation_id: 1, private_key: nil, webhook_secret: nil })
  refute app.verify_webhook_signature('sha1=deadbeef', '{"anything":"goes"}')
end

# test/controllers/webhooks_controller_test.rb (new test)
test "membership webhook with no webhook_secret configured and garbage signature still writes a Membership" do
  Shipit.stubs(:github).with(organization: 'no-secret-org').returns(
    Shipit::GitHubApp.new('no-secret-org', { app_id: 1, installation_id: 1, private_key: nil, webhook_secret: nil })
  )
  @request.headers['X-Github-Event'] = 'membership'
  @request.headers['X-Hub-Signature'] = 'sha1=totally-bogus'

  body = {
    action: 'added',
    team: { id: shipit_teams(:shopify_developers).github_id, name: 'x', slug: 'x', url: 'http://example.com' },
    organization: { login: 'no-secret-org' },
    member: { login: 'attacker-controlled-login' }
  }.to_json

  assert_difference -> { Shipit::Membership.count }, 1 do
    post :create, body:, as: :json
    assert_response :ok # currently passes despite invalid/no signature -> proves the bypass
  end
end
```
Both assertions are expected to fail against the fix (post-fix: `verify_webhook_signature` returns `false`, and the controller responds `422` with no `Membership` created), demonstrating the current bypass.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L15-24)
```ruby
        def self.call(params)
          new(params).process
        end

        attr_reader :params, :payload

        def initialize(payload)
          @payload = payload
          @params = self.class.param_parser.parse!(payload)
        end
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-43)
```ruby
        def process
          team = find_or_create_team!
          member = User.find_or_create_by_login!(params.member.login)

          case params.action
          when 'added'
            team.add_member(member)
          when 'removed'
            team.members.delete(member)
          else
            raise ArgumentError, "Don't know how to perform action: `#{action.inspect}`"
          end
        end

        private

        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
          end
        end
```

**File:** test/controllers/webhooks_controller_test.rb (L129-140)
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
```
