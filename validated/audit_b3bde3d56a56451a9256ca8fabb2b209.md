### Title
Unauthenticated webhook signature bypass when a configured GitHub org has no `webhook_secret` - (File: `lib/shipit/github_app.rb`)

### Summary
`GitHubApp#verify_webhook_signature` returns `true` whenever the resolved organization has no `webhook_secret` configured, without performing any HMAC check. Since `WebhooksController#verify_signature` resolves the `GitHubApp` from attacker-controlled `repository.owner.login` / `organization.login` fields in the JSON body, an attacker can pick any configured org lacking a `webhook_secret` to make `verify_webhook_signature` "pass" with no signature at all, letting the payload's event reach handlers such as `PushHandler`.

### Finding Description
The broken binding is: `verify_webhook_signature(signature, message) == true` should hold **iff** an HMAC computed with the resolved org's `webhook_secret` matches `signature`. Instead, in [1](#0-0)  the method does:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
```
so `verified == true` even when zero cryptographic validation occurred, provided the resolved `GitHubApp`'s `@webhook_secret` is blank (`@config[:webhook_secret].presence`, set at [2](#0-1) ).

The controller resolves this `GitHubApp` purely from attacker-supplied JSON, before any authentication: [3](#0-2) 
and `repository_owner` is taken directly from the untrusted request body: [4](#0-3) 

Exploit flow:
1. Attacker crafts a JSON body for `X-Github-Event: push` with `repository.owner.login` (or `organization.login`) set to any GitHub organization configured in `Shipit.github(organization:)` that has no `webhook_secret` set.
2. Attacker sends `POST /webhooks` with no `X-Hub-Signature` header (or a garbage one).
3. `verify_signature` resolves `Shipit.github(organization: <that org>)`, calls `verify_webhook_signature(nil_or_garbage, raw_body)`, which returns `true` because `webhook_secret` is blank for that org — no `head(422)` is raised.
4. `create` then parses the body and dispatches to `Shipit::Webhooks.for_event('push')`, running `PushHandler#process`, which calls `stack.sync_github(expected_head_sha: params.after)` on any matching stacks — [5](#0-4) .

This confirms the described bypass on the signature check itself: no HMAC validation happened, yet `verified` was `true`, letting an unauthenticated request through `check_if_ping` → `drop_unhandled_event` → `verify_signature` all the way to handler execution.

### Impact Explanation
An attacker who can send arbitrary HTTP POSTs (no session, no token, no secrets) can trigger `stack.sync_github` (and potentially other handlers keyed on other events, e.g. `status`, `check_suite`, `membership`) for any stack, as long as they can find/guess one configured GitHub organization without a `webhook_secret`. This is an authentication bypass on the webhook endpoint matching the Critical category ("authentication bypass (forged webhook ... accepted)"). Because the org used purely for signature resolution (`repository.owner.login`/`organization.login`) is decoupled from what stacks/handlers actually act on (branch/repository matching inside handlers, e.g. `PushHandler`'s `stacks.not_archived.where(branch:)`), the blast radius is not limited to the "unsecured" org's own repositories — it depends on how `Handler#stacks` scopes stacks (by repository full_name from the same untrusted payload), which was not fully confirmed in this pass, but the underlying signature-bypass primitive itself is proven in the engine's own code independent of that follow-on scoping question.

### Likelihood Explanation
The precondition is operational, not code-level: at least one GitHub organization configured in the host app's `Shipit.github` config must be missing a `webhook_secret`. Given `@webhook_secret = @config[:webhook_secret].presence` at [2](#0-1) , this is a plausible misconfiguration (e.g., an org added without setting up its webhook secret yet, or a secondary/legacy org entry). No secrets, sessions, or privileged roles are needed by the attacker — only knowledge that such an org exists in the deployment's config, and the org name itself (often discoverable, e.g. GitHub org names are public).

### Recommendation
Change `verify_webhook_signature` to fail closed when no secret is configured:
```ruby
def verify_webhook_signature(signature, message)
  return false if webhook_secret.blank?
  return false if signature.blank?

  algorithm, signature = signature.split("=", 2)
  return false unless algorithm == 'sha1'

  SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
end
```
Additionally, treat a missing `webhook_secret` for any configured org as a configuration error (raise at boot / fail loudly), rather than silently disabling signature verification for that org.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (new test)
test "push webhook is accepted without any signature when resolved org has no webhook_secret" do
  request.headers['X-Github-Event'] = 'push'

  unsecured_org_app = Shipit::GitHubApp.new('unsecured-org', {}) # no webhook_secret in config
  Shipit.stubs(:github).with(organization: 'unsecured-org').returns(unsecured_org_app)

  body = JSON.parse(payload(:push_master))
  body['repository']['owner']['login'] = 'unsecured-org'
  # No X-Hub-Signature header set at all

  Shipit::Webhooks::Handlers::PushHandler.any_instance.expects(:call).at_least_once

  post :create, body: body.to_json, as: :json

  assert_response :ok # NOT :unprocessable_entity (422), proving bypass
end
```
Both sides of the equality diverge: `verify_webhook_signature(nil, body) == true` (actual) vs. the required binding `verify_webhook_signature == true` iff HMAC(webhook_secret, body) matches `signature` (expected) — here no secret and no signature existed, yet verification "passed."

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
