### Title
`GitHubApp#verify_webhook_signature` returns `true` for any payload when an organization has no `webhook_secret` configured, allowing unsigned webhook forgery - ([File: lib/shipit/github_app.rb])

### Summary
`Shipit::GitHubApp#verify_webhook_signature` short-circuits to `true` when `webhook_secret` is blank, meaning `Shipit::WebhooksController#verify_signature` accepts any POST to `/webhooks` naming that organization, with any (or no) `X-Hub-Signature` header. This lets an unprivileged internet attacker forge push/status/pull_request/membership events for that organization's stacks without ever possessing the (nonexistent) secret.

### Finding Description
The broken binding is: **authenticity(payload) == (HMAC(webhook_secret, raw_post) matches X-Hub-Signature)**. For an organization whose config lacks `webhook_secret`, this equality is never evaluated — `verify_webhook_signature` returns `true` unconditionally instead of `false`, per [1](#0-0) .

Path: `WebhooksController#create` runs `before_action :check_if_ping, :drop_unhandled_event, :verify_signature` [2](#0-1) . `verify_signature` resolves the org purely from attacker-controlled JSON (`params.dig('repository','owner','login')`), fetches the corresponding `GitHubApp` via `Shipit.github(organization: repository_owner)`, and calls `verify_webhook_signature` [3](#0-2) [4](#0-3) . If that org's config has no `webhook_secret`, `verified` is `true` regardless of signature, so `head(422)` is never invoked, and `create` proceeds to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [5](#0-4) , dispatching to real handlers (`PushHandler`, `StatusHandler`, `PullRequest::*Handler`, etc.) against that organization's actual stacks.

Attacker request: `POST /webhooks` with header `X-Github-Event: push` (or `status`/`pull_request`) and a JSON body whose `repository.owner.login` is the victim organization's name, with `X-Hub-Signature` omitted or arbitrary. No existing guard catches this: `drop_unhandled_event` only filters unknown event types, and `verify_signature`'s only failure path is `GithubOrganizationUnknown`, which requires the org name to be *unrecognized* — here it is recognized but simply missing a secret.

### Impact Explanation
An attacker can inject fully forged GitHub webhook events (push, status, pull_request, membership, check_suite) attributed to any organization whose `webhook_secret` is unset, causing Shipit to act on fabricated data as if it came from GitHub — e.g., enqueuing `GithubSyncJob`, writing fake commit `Status` records, mutating team membership, or driving pull_request/review-stack handlers — all without needing any secret. This matches the Critical "authentication bypass (forged webhook)" category and is fully repeatable against every stack under that organization.

### Likelihood Explanation
The only precondition is a misconfiguration: an organization entry in the GitHub config that omits `webhook_secret` (default when a `secrets.github` entry doesn't set it). This is a plausible, low-effort operator error since the field is optional in the schema; once present, exploitation costs nothing beyond a single unauthenticated HTTP POST, is fully repeatable, and requires no session, token, or credentials.

### Recommendation
Change `verify_webhook_signature` to fail closed when `webhook_secret` is absent (`return false unless webhook_secret`), and/or enforce at boot/config-validation time that every configured GitHub organization must define a non-blank `webhook_secret`.

### Proof of Concept
```ruby
# test/unit/github_app_test.rb (new test)
test "#verify_webhook_signature rejects payloads when no webhook_secret is configured" do
  app_without_secret = GitHubApp.new('acme', { app_id: 'x', installation_id: 'y', private_key: 'z' })
  assert_equal false, app_without_secret.verify_webhook_signature(nil, '{"any":"payload"}')
end

# test/controllers/webhooks_controller_test.rb (new test)
test "rejects unsigned webhook for org with no webhook_secret configured" do
  Shipit.stubs(:github).with(organization: 'acme').returns(
    Shipit::GitHubApp.new('acme', { app_id: 'x', installation_id: 'y', private_key: 'z' })
  )
  @request.headers['X-Github-Event'] = 'push'
  body = JSON.parse(payload(:push_master))
  body['repository']['owner']['login'] = 'acme'
  post :create, body: body.to_json, as: :json
  assert_response :unprocessable_entity
end
```
Both assertions currently fail against the present code (`verify_webhook_signature` returns `true`, controller responds `:ok`), demonstrating the bypass.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```
