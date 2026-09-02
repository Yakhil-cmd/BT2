This confirms the finding is genuine and reachable through this engine's own code, with no mitigating guard elsewhere (`force_github_authentication` only gates the web login flow in `app/controllers/concerns/shipit/authentication.rb`, not the `/webhooks` endpoint).

### Title
Webhook signature verification is bypassed when `github.webhook_secret` is unset, allowing unauthenticated `membership` events to grant `Shipit.github_teams` access - (File: `lib/shipit/github_app.rb`)

### Summary
`GitHubApp#verify_webhook_signature` returns `true` whenever `@webhook_secret` is blank, and `WebhooksController#verify_signature` treats that `true` as proof the request came from GitHub. Since `github.webhook_secret` is an optional config field, any organization that leaves it unset accepts unsigned, unauthenticated POST `/webhooks` requests, letting an attacker fabricate a `membership` event that adds an arbitrary GitHub login to any team listed in `Shipit.github_teams`.

### Finding Description
The broken binding is: `verify_webhook_signature(signature, body) == true` is treated by `WebhooksController#verify_signature` as equivalent to "this HTTP request was sent by GitHub for `repository_owner`'s organization" [1](#0-0) . That equivalence only holds when an HMAC secret is configured and checked; when it is not configured, the method unconditionally returns `true` without inspecting the request at all: [2](#0-1) 

`@webhook_secret` is set from `@config[:webhook_secret].presence` in `GitHubApp#initialize`, so any organization entry lacking (or leaving blank) `webhook_secret` in the secrets config produces `webhook_secret => nil` [3](#0-2) . The field is explicitly documented as optional ("If you've set a webhook secret during the App creating, you should copy it here"), and the shipped multi-org sample config leaves it blank for both sample orgs [4](#0-3) .

Exploit flow: attacker sends `POST /webhooks` with `X-Github-Event: membership`, no (or garbage) `X-Hub-Signature`, and body `{"action":"added","organization":{"login":"<org-with-no-secret>"},"team":{"id":<id>,"name":...,"slug":...,"url":...},"member":{"login":"<attacker>"}}`. `WebhooksController#verify_signature` calls `Shipit.github(organization: repository_owner)` which resolves the org's `GitHubApp` instance, whose `verify_webhook_signature` returns `true` unconditionally, so the request passes [1](#0-0) . Control flows into `MembershipHandler#process`, which resolves/creates the team by `params.team.id` and calls `team.add_member(member)`, inserting a `Membership` row [5](#0-4) . `Team#add_member` performs no additional authorization check [6](#0-5) .

None of the listed guards intervene: `ExplicitParameters` only validates JSON shape, not origin; `drop_unhandled_event` only checks the event is registered; `force_github_authentication` only affects the browser OAuth login flow in `app/controllers/concerns/shipit/authentication.rb`, not the webhooks endpoint. `verify_signature`'s only real defense — signature comparison — is skipped entirely for orgs with no secret.

### Impact Explanation
An attacker who knows (or guesses) an unprivileged, secret-less organization's login and the numeric `github_id` of a team referenced in `Shipit.github_teams` (used for OAuth authorization gating, per `Shipit#github_teams` in `lib/shipit.rb:256-258`) can add themselves — or anyone — as a member of that team via forged, unsigned webhook requests. This is a direct escalation into `Shipit.github_teams` authorization without ever authenticating to GitHub or Shipit, matching the High-severity category "escalation into `Shipit.github_teams` authorization." The action is repeatable for any organization configured without a `webhook_secret`, and each POST can add arbitrary members to arbitrary known teams.

### Likelihood Explanation
The only precondition is that the target organization's `github.webhook_secret` is left blank — a state the shipped documentation and sample config explicitly present as valid/optional, so it is a realistic real-world deployment configuration, not a contrived edge case. No GitHub App private key, HMAC secret, session, or API token is needed; the attacker only needs network access to `POST /webhooks` and knowledge of the organization login and a team's GitHub `id`/`slug`/`name`/`url` (public GitHub org information). Cost is a single unauthenticated HTTP request.

### Recommendation
Do not allow signature verification to silently no-op. Either require `webhook_secret` to be present for every configured organization (raise/fail closed at boot or at verification time when absent) or reject webhooks with `head(422)` when `webhook_secret` is blank instead of returning `true` from `verify_webhook_signature`.

### Proof of Concept
In `test/lib/shipit/github_app_test.rb`-style / `test/controllers/webhooks_controller_test.rb`-style minitest:
```ruby
test "membership webhook is accepted and mutates Membership with no secret configured" do
  org = "unsecuredorg"
  Shipit.stubs(:github).with(organization: org).returns(Shipit::GitHubApp.new(org, { app_id: 1, installation_id: 1, private_key: nil, webhook_secret: nil }))

  @request.headers['X-Github-Event'] = 'membership'
  # deliberately NOT setting X-Hub-Signature
  body = {
    action: 'added',
    team: { id: 999, name: 'Evil Team', slug: 'evil-team', url: 'https://example.com/evil' },
    organization: { login: org },
    member: { login: 'attacker' }
  }.to_json

  assert_difference -> { Shipit::Membership.count }, 1 do
    post :create, body:, as: :json
    assert_response :ok
  end
end
```
Before: expected equality `verify_webhook_signature(nil, body) == false` (no valid HMAC ⇒ not GitHub). After tracing: `verify_webhook_signature` returns `true` because `webhook_secret` is `nil`, so the equality is violated (`true != false`), `Membership.count` increases, and no valid signature was ever supplied — confirming the authentication bypass.

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

**File:** lib/shipit/github_app.rb (L44-50)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-34)
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
```

**File:** app/models/shipit/team.rb (L41-43)
```ruby
    def add_member(member)
      members.append(member) unless members.include?(member)
    end
```
