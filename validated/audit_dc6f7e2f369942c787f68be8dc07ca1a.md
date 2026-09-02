### Title
Webhook signature verification fails open when an organization's `webhook_secret` is unset - ([File: lib/shipit/github_app.rb])

### Summary
`GitHubApp#verify_webhook_signature` returns `true` unconditionally whenever `webhook_secret` is blank for the resolved organization, and `WebhooksController#verify_signature` treats that `true` as proof of authenticity. Any org configured in `Shipit.github`'s multi-org config without a `webhook_secret` therefore accepts any POST to `/webhooks` for that org's login with no signature at all, letting an unauthenticated attacker drive `MembershipHandler#process` (and any other event handler) for that org.

### Finding Description
The intended binding is: *a request is accepted only if `X-Hub-Signature` is a valid HMAC-SHA1 of the raw body using that organization's `webhook_secret`* — i.e. `verified == true` should imply `HMAC(webhook_secret, raw_post) == signature`.

The actual code breaks this for any org without a configured secret: [1](#0-0) 
`return true unless webhook_secret` makes `verify_webhook_signature` succeed with no HMAC comparison at all when `@webhook_secret` (set from `@config[:webhook_secret].presence` at line 50) is `nil`.

`WebhooksController#verify_signature` resolves the org purely from attacker-controlled JSON (`params.dig('organization', 'login')`), calls `Shipit.github(organization: repository_owner)`, and accepts the request if `verify_webhook_signature` returns truthy: [2](#0-1) 
`repository_owner` is read straight from the payload with no cross-check against a legitimate signer: [3](#0-2) 

`Shipit.github_app_config` lowercases both the configured org keys and the requested organization string before lookup, so an attacker only needs `organization.login` to match a configured key case-insensitively: [4](#0-3) 

If that matched org's config omits `webhook_secret` (e.g. an org onboarded without a secret, a misconfiguration, or an intentionally "unverified" internal org), `verify_signature` passes with **no** `X-Hub-Signature` header, a garbage header, or any header at all, and `create` runs the event handlers against attacker-supplied JSON: [5](#0-4) 

No other guard intervenes: `drop_unhandled_event` only filters unknown event types, `check_if_ping` only special-cases `ping`, and there is no additional authentication on `/webhooks`. `GithubOrganizationUnknown` is only raised for orgs that don't exist in config at all — it does not fire for orgs that exist but lack a secret, so the "unknown org → 422" guard the question hypothesizes as a barrier is irrelevant here; the actual bypass requires the org to exist in config, not be unknown.

Attacker's request: `POST /webhooks` with header `X-Github-Event: membership` and JSON body `{"action":"added","organization":{"login":"<org-with-no-secret>"},"team":{...},"member":{"login":"attacker-controlled"},"repository":{"owner":{"login":"<org-with-no-secret>"}}}`, no `X-Hub-Signature` header (or any bogus value). Because `verify_webhook_signature` short-circuits `true`, this reaches the `membership` handler and mutates `Team`/`Membership` rows for that org without any proof the request came from GitHub.

### Impact Explanation
An attacker can forge arbitrary webhook events for any organization configured without a `webhook_secret`, not just `membership` — the same `verify_signature` gate protects every event type (`push`, `status`, `check_suite`, `pull_request`, etc.). For `membership` events this means unauthenticated creation/deletion of `Team` and `Membership` rows, which is an authorization-relevant table (`Shipit.github_teams`). For `push` this can enqueue `GithubSyncJob` with attacker-chosen SHAs; for `status`/`check_suite` this can forge CI state used for deploy gating. This is repeatable indefinitely against any org lacking a secret and constitutes an authentication bypass on the webhook ingestion pipeline for that tenant, matching the Critical category ("authentication bypass (forged webhook ... accepted)").

### Likelihood Explanation
Exploitability is entirely conditioned on Shipit operator configuration: at least one organization entry in the multi-org `secrets.github` config must have `webhook_secret` blank/unset. If every configured org has a non-blank secret, this path is not reachable and the code behaves correctly (HMAC comparison enforced). The attacker needs zero credentials and a network path to `/webhooks`; the only "cost" is the operator's misconfiguration. This is a fail-open code defect (should fail closed when no secret is configured), not something requiring a secret leak.

### Recommendation
Change `GitHubApp#verify_webhook_signature` to fail closed instead of open: if `webhook_secret` is blank, return `false` (or raise/log and reject) rather than `true`, unless there is a deliberate, explicitly-opt-in "unauthenticated org" mode that is documented and gated separately from ordinary misconfiguration. At minimum, `Shipit.github_app_config`/`GitHubApp.new` should refuse to boot (or should log a loud warning and mark the org as verification-required-but-unconfigured) when an org is present in config without a `webhook_secret`.

### Proof of Concept
In `test/controllers/webhooks_controller_test.rb` (illustrative, not to be added under `test/` per scope rules but describing the reproducible check):
```ruby
test ":membership is accepted with no signature when org has no webhook_secret" do
  # Arrange: stub multi-org config so 'target-org' resolves with webhook_secret == nil
  Shipit.stubs(:github).with(organization: 'target-org').returns(
    Shipit::GitHubApp.new('target-org', { app_id: 1, installation_id: 1, private_key: 'k' }) # no webhook_secret key
  )
  @request.headers['X-Github-Event'] = 'membership'
  # No X-Hub-Signature header set at all

  body = {
    action: 'added',
    team: { id: shipit_teams(:shopify_developers).id, slug: 'developers', name: 'Developers', url: 'http://example.com' },
    organization: { login: 'target-org' },
    member: { login: 'walrus' },
    repository: { owner: { login: 'target-org' } }
  }.to_json

  assert_difference -> { Membership.count }, 1 do
    post :create, body:, as: :json
  end
  assert_response :ok
end
```
Assert both sides of the binding: `request.headers['X-Hub-Signature']` is absent/invalid (left side: no valid HMAC), yet `assert_response :ok` and a persisted `Membership` row (right side: payload action accepted) — demonstrating the equality the question describes is broken specifically because `webhook_secret` is nil for `target-org`.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** lib/shipit.rb (L196-200)
```ruby
  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
```
