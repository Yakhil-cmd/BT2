### Title
Webhook signature verification unconditionally bypassed when `webhook_secret` is blank - (File: `lib/shipit/github_app.rb`)

### Summary
`Shipit::GitHubApp#verify_webhook_signature` returns `true` without performing any HMAC comparison whenever the configured `webhook_secret` is blank. Since `Shipit::WebhooksController#verify_signature` treats this `true` as proof the sender possesses the shared secret, any organization configured (intentionally per the docs, as "optional") without a `webhook_secret` accepts completely unsigned/forged webhook payloads.

### Finding Description
The binding the controller relies on is: `verified == true` implies `sender possesses webhook_secret`. In code, `WebhooksController#verify_signature` calls `Shipit.github(organization: repository_owner).verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)` and treats a `true` result as authenticated [1](#0-0) . But `GitHubApp#verify_webhook_signature` breaks that binding explicitly:

```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [2](#0-1) 

`@webhook_secret` is set from config at initialization via `@config[:webhook_secret].presence`, so a blank/nil value in secrets yields `webhook_secret` as `nil`, and the guard clause short-circuits verification entirely, regardless of the `X-Hub-Signature` header content [3](#0-2) .

An attacker who knows (or guesses) the target organization login can `POST /webhooks` with a crafted `pull_request`, `push`, or `status` JSON body and any `X-Github-Event` header, with no `X-Hub-Signature` header at all (or a garbage one) — `verify_webhook_signature` never inspects it when the secret is blank, so `verified` is always `true`, and processing proceeds to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` in `create` [4](#0-3) .

Existing guards do not prevent this: `drop_unhandled_event` only filters by event type, not authenticity; `check_if_ping` is irrelevant; `repository_owner` merely picks the target org from the attacker-controlled payload to select which `GitHubApp` instance to check against — it does not add any authentication.

### Impact Explanation
This is a genuine authentication bypass matching the "Critical" category (forged webhook accepted) — but it is entirely conditional on the operator leaving `webhook_secret` blank for that organization's GitHub App config. Once that misconfiguration exists, an attacker can forge `pull_request`, `push`, `check_suite`, `status`, and `membership` webhooks for that specific organization, causing the corresponding handlers to run (e.g., creating `Stack`/`ReviewStack` records, teams, users) as if GitHub itself had sent them. The blast radius is scoped to organizations sharing that specific blank-secret `GitHubApp` config; organizations with a properly configured secret are unaffected because `verify_webhook_signature` performs the real HMAC `SecureCompare.secure_compare` check for them [2](#0-1) .

### Likelihood Explanation
This is documented, intended behavior, not a logic defect: `docs/setup.md` explicitly labels the webhook secret as "**Webhook secret (optional)**: Fill it with some randomly generated string..." [5](#0-4) , and the multi-org example config in the same doc shows `webhook_secret:` left blank as a valid template [6](#0-5) . The repo's own development sample `config/secrets.development.shopify.yml` also ships with `webhook_secret: # nil` for both configured orgs [7](#0-6) . Per the audit rules, "Assume the host app mounts this engine as documented" — and the documentation itself presents omitting the secret as a supported, optional configuration, not a misuse. That said, exploitation strictly requires this operator/deployment choice (blank secret); it is not exploitable against a properly configured production instance with a set `webhook_secret`.

### Recommendation
Fail closed instead of fail open: when `webhook_secret` is blank, `verify_webhook_signature` should return `false` (reject) rather than `true`, and/or the app should refuse to boot / log a loud warning when a GitHub App is configured without a `webhook_secret`. At minimum, update `docs/setup.md` to state the webhook secret is required, not optional, and remove the blank-secret example from the multi-org documentation.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (conceptual addition)
test "unsigned webhook is accepted when webhook_secret is blank" do
  # Arrange: organization's GitHubApp configured with webhook_secret = nil
  Shipit.stubs(:github).with(organization: 'no-secret-org').returns(
    Shipit::GitHubApp.new('no-secret-org', { app_id: 1, installation_id: 1, webhook_secret: nil })
  )

  payload = {
    'action' => 'opened',
    'pull_request' => { ... },
    'repository' => { 'owner' => { 'login' => 'no-secret-org' }, 'full_name' => 'no-secret-org/repo' }
  }.to_json

  @request.headers['X-Github-Event'] = 'pull_request'
  # No X-Hub-Signature header set at all

  assert_difference -> { Shipit::ReviewStack.count }, 1 do
    post :create, body: payload, as: :json
    assert_response :ok
  end
end
```
Both sides of the binding diverge here: `verified` is `true` (per `GitHubApp#verify_webhook_signature` line 77) while "sender possesses webhook_secret" is `false` (no secret exists / no signature sent), demonstrating the bypass.

### Citations

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

**File:** docs/setup.md (L30-30)
```markdown
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
```

**File:** docs/setup.md (L188-209)
```markdown
```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
```

**File:** config/secrets.development.shopify.yml (L9-18)
```yaml
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
```
