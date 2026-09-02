### Title
Unauthenticated webhook processing when `GitHubApp#webhook_secret` is unset - (File: lib/shipit/github_app.rb)

### Summary
`GitHubApp#verify_webhook_signature` unconditionally returns `true` when no `webhook_secret` is configured for an organization, so `WebhooksController#verify_signature` accepts any inbound payload for that org with no signature check at all. Any unauthenticated internet client can then trigger full handler execution (`Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`), including stack/team/user-mutating handlers, for any organization whose `GitHubApp` config omits `webhook_secret`.

### Finding Description
The binding that should hold is: `verified == (signature is a valid HMAC-SHA1 of the raw payload using the org's webhook_secret)`. Instead, at [1](#0-0) , when `@webhook_secret` is blank the method short-circuits with `return true unless webhook_secret`, making `verified` always `true` regardless of the `X-Hub-Signature` header or payload content.

The controller flow is: `before_action :check_if_ping, :drop_unhandled_event, :verify_signature` then `create` dispatches to handlers [2](#0-1) . `verify_signature` resolves the `GitHubApp` purely from `repository_owner` (`params.dig('repository','owner','login')`) — an attacker-controlled field in the raw JSON body — via `Shipit.github(organization: repository_owner)`, then calls `verify_webhook_signature` [3](#0-2) . If that org's `GitHubApp` has no `webhook_secret` set (`@config[:webhook_secret].presence` is `nil`) [4](#0-3) , `verify_signature` always passes, and `create` runs every registered handler for the event with fully attacker-supplied `params`, with no other authentication check anywhere in the request path.

Existing guards do not mitigate this: `check_if_ping` only short-circuits `ping` events and does not validate signatures at all (so it cannot be used to "discover" secret presence via a differing response), `drop_unhandled_event` only filters by event type, and there is no code path anywhere in this engine that requires `webhook_secret` to be present for a configured `GitHubApp`.

### Impact Explanation
For any organization configured without `webhook_secret`, an attacker can POST arbitrary JSON to `/webhooks` with `X-Github-Event` set to any handled event (e.g. `pull_request`) and `repository.owner.login` set to that organization's name, and the payload will be processed as if it came from GitHub — no signature, no session, no API token required. Depending on which handlers are registered for that event (e.g. `ReviewStack` creation, membership/team synchronization), this can result in unauthorized record creation/mutation for that organization's stacks/teams, matching the Critical category of "authentication bypass (forged webhook ... accepted)". This is repeatable per request and applies to every organization lacking a configured `webhook_secret`, not just one.

### Likelihood Explanation
Exploitability strictly requires that the target organization's `GitHubApp` entry has `webhook_secret` unset/blank in the host application's Shipit config — this is an operator configuration state, not something the attacker can force. Where that precondition holds, the attack is trivial: a single unauthenticated HTTP POST with a crafted JSON body, no secrets, tokens or GitHub interaction needed at all.

### Recommendation
Do not allow signature verification to trivially pass when `webhook_secret` is blank. Either require every configured `GitHubApp` to declare a `webhook_secret` (fail fast at boot/config-load time if missing) or make `verify_webhook_signature` reject (return `false`) requests when no secret is configured, forcing operators to explicitly configure a secret before webhooks are accepted for that organization.

### Proof of Concept
In a minitest `WebhooksControllerTest` under `test/controllers/webhooks_controller_test.rb` (already scoped in this engine's test suite), add a test that:
1. Registers/stubs a `GitHubApp` for organization `victim-org` with `webhook_secret: nil` via the app's github config lookup (e.g. `Shipit.github(organization: 'victim-org')` returning a `GitHubApp.new('victim-org', { app_id: ..., installation_id: ..., private_key: ... })` without `webhook_secret`).
2. POST to `/webhooks` with `X-Github-Event: pull_request` header, no `X-Hub-Signature` header, and a JSON body with `repository.owner.login == 'victim-org'` plus a minimal valid `pull_request` payload.
3. Assert the response is `200 OK` (not `422`) and assert that the corresponding handler executed — e.g. assert a `Shipit::ReviewStack` or related record was created/attempted — proving `verify_webhook_signature` returned `true` and `handler#process` ran with zero authentication, i.e. `verified == true` even though `signature header present == false` and `webhook_secret == nil`.

### Citations

**File:** lib/shipit/github_app.rb (L50-50)
```ruby
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

**File:** app/controllers/shipit/webhooks_controller.rb (L6-14)
```ruby
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature

    respond_to :json

    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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
