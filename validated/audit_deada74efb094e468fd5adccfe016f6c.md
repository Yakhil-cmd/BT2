### Title
`GithubApp#verify_webhook_signature` fails open (`return true unless webhook_secret`), allowing forged webhooks for orgs missing a configured secret - ([File: lib/shipit/github_app.rb])

### Summary
`GitHubApp#verify_webhook_signature` returns `true` when no `webhook_secret` is configured for an organization instead of rejecting the request, so `WebhooksController#verify_signature` treats any unsigned, attacker-forged POST to `/webhooks` for that organization as authentic. This lets an unauthenticated internet attacker dispatch `Shipit::Webhooks` handlers (e.g. `OpenedHandler`) with arbitrary payload content, creating/mutating a `ReviewStack` and driving execution of attacker-controlled `shipit.yml` steps.

### Finding Description
The broken binding: `verify_webhook_signature(signature, message) == true` should hold **iff** `HMAC-SHA1(webhook_secret, message) == signature` for a cryptographically confirmed sender. Instead, at [1](#0-0)  the method returns `true` unconditionally when `webhook_secret` is blank, before any signature comparison occurs.

Path: `WebhooksController#create` runs `before_action :check_if_ping, :drop_unhandled_event, :verify_signature` [2](#0-1) . `verify_signature` resolves the org from the payload's `repository.owner.login` (or `organization.login`), fetches the corresponding `GitHubApp` via `Shipit.github(organization: repository_owner)`, and calls `verify_webhook_signature` [3](#0-2) . If that org's config in `secrets.github` (`app_id`, `installation_id`, `webhook_secret`, etc., see `TOP_LEVEL_GH_KEYS`/`github_app_config`) has no `webhook_secret` key, `@webhook_secret` is `nil` [4](#0-3) , and `verify_webhook_signature` short-circuits to `true` regardless of the `X-Hub-Signature` header or body content. `create` then parses the raw body and dispatches to registered handlers for the event type without any further authentication check [5](#0-4) .

None of the other guards mitigate this: `drop_unhandled_event` only filters by event type, not authenticity; `check_if_ping` just no-ops pings; there is no session/API-token check on this controller (it's a public webhook endpoint by design, relying entirely on signature verification for authenticity). The multi-org config schema in `lib/shipit.rb` (`github_app_config`, `TOP_LEVEL_GH_KEYS`) makes per-organization `webhook_secret` an operator-supplied, easily-omitted field — there is no validation anywhere that raises/fails startup if `webhook_secret` is missing for a configured org, and no fallback that treats missing secret as "reject all."

### Impact Explanation
For any organization whose `secrets.github` entry lacks `webhook_secret`, any internet client can POST an arbitrary JSON body to `/webhooks` with the correct `X-Github-Event` header and a `repository.owner.login` (or `organization.login`) matching that org, with any (or no) `X-Hub-Signature` value, and have it processed as a genuine GitHub webhook. This is a full authentication bypass on the webhook ingestion path: attacker-controlled `pull_request opened` payloads can be routed through `OpenedHandler`-style handlers to create a `ReviewStack`, whose eventual task execution runs `shipit.yml` steps from the attacker's fork/branch. The blast radius is scoped to whichever organization is misconfigured, but it is fully repeatable and requires no credentials, satisfying the Critical "authentication bypass (forged webhook accepted)" category.

### Likelihood Explanation
This requires an operator misconfiguration precondition: the org's `secrets.github[org]` entry must omit `webhook_secret` (or set it blank). This is not enforced by any validation, so it's a plausible operational error — the config schema treats `webhook_secret` as optional (`@config[:webhook_secret].presence`), and nothing fails loudly if it's absent, unlike missing `app_id`/`installation_id` which are accessed via `fetch` and would raise. Attacker cost is trivial (a single unauthenticated HTTP POST); once a misconfigured org exists, exploitation is repeatable indefinitely against that org's repositories.

### Recommendation
Change `verify_webhook_signature` to fail closed: if `webhook_secret` is blank, return `false` (or raise/log a configuration error) rather than `true`. Additionally, validate at boot/config-load time that every configured GitHub org has a non-blank `webhook_secret`, so misconfiguration is caught before the app accepts traffic.

### Proof of Concept
```ruby
# test/lib/shipit/github_app_test.rb (conceptual, no live GitHub)
test "#verify_webhook_signature rejects unsigned payloads when webhook_secret is not configured" do
  app = Shipit::GitHubApp.new('acme', { app_id: 1, installation_id: 1, private_key: 'x' }) # no webhook_secret
  message = { action: 'opened', repository: { owner: { login: 'acme' } } }.to_json

  # BEFORE fix: this currently returns true (bug)
  refute app.verify_webhook_signature(nil, message), "must not accept unsigned payload when no secret is configured"
end
```
```ruby
# test/controllers/webhooks_controller_test.rb (conceptual)
test "create rejects forged pull_request payload for org without webhook_secret" do
  # stub Shipit.github(organization: 'acme') to return a GitHubApp with no webhook_secret
  post :create,
       body: { action: 'opened', pull_request: {}, repository: { owner: { login: 'acme' } } }.to_json,
       headers: { 'X-Github-Event' => 'pull_request' } # no X-Hub-Signature

  assert_response :unprocessable_entity # currently succeeds and dispatches handler - bug
end
```

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

**File:** app/controllers/shipit/webhooks_controller.rb (L4-6)
```ruby
  class WebhooksController < ActionController::Base
    skip_before_action :verify_authenticity_token, raise: false
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature
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
