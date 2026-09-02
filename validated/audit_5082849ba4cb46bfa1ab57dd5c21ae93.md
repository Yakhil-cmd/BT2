### Title
Missing `webhook_secret` on an org causes `GitHubApp#verify_webhook_signature` to accept any unsigned webhook - ([File: lib/shipit/github_app.rb])

### Summary
`Shipit::GitHubApp#verify_webhook_signature` treats a `nil`/absent `webhook_secret` as automatic verification success, and `WebhooksController#verify_signature` trusts that result to decide whether to call `head(422)`. If any configured organization omits `webhook_secret`, an unauthenticated attacker can POST an arbitrary forged payload naming that org's repository and have `create` dispatch it to `PushHandler`/`StatusHandler`/`CheckSuiteHandler`, mutating that org's real stack state.

### Finding Description
The binding that must hold is: **request is authentic for org O** ⇔ **HMAC-SHA1(webhook_secret_O, raw_body) == signature header**. Instead, the code implements: if `webhook_secret_O` is absent, **request is authentic for org O** is defined as `true` unconditionally.

Concretely, `GitHubApp#initialize` sets `@webhook_secret = @config[:webhook_secret].presence` [1](#0-0) , so a config lacking (or blank) `webhook_secret` yields `@webhook_secret = nil`. `verify_webhook_signature` then short-circuits:

```
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
``` [2](#0-1) 

In `WebhooksController#verify_signature`, the app is resolved by the attacker-controlled `repository.owner.login` field of the JSON body via `Shipit.github(organization: repository_owner)` [3](#0-2) [4](#0-3) . `verified` becomes `true` for any signature (including none), so `head(422) unless verified` never fires, and `create` proceeds to `JSON.parse(request.raw_post)` and dispatches to `Shipit::Webhooks.for_event(event)` handlers [5](#0-4) .

`Shipit.github_app_config(organization)` looks up the org by the (attacker-supplied, but must match a real configured org) key in `secrets.github`, downcased [6](#0-5) ; there is no fallback or default enforcing a secret to be present — any org lacking `webhook_secret` in its config is exploitable this way. No other guard (`drop_unhandled_event`, `check_if_ping`, `ExplicitParameters`, authentication filters) checks payload authenticity; they only gate on event type/ping and are irrelevant to signature verification.

Attacker request: `POST /webhooks` with header `X-Github-Event: push` (or `status`, `check_suite`), no `X-Hub-Signature` header (or garbage), and a JSON body with `repository.owner.login` set to the victim org name and `repository.full_name` set to any stack tracked by Shipit for that org. This body is processed as if genuinely sent by GitHub.

### Impact Explanation
This is authentication bypass of the webhook provenance check for any organization whose config omits `webhook_secret`. An attacker can inject forged `push`, `status`, or `check_suite` events for that org, driving `PushHandler`/`StatusHandler`/`CheckSuiteHandler` to mutate real `Stack`/`Commit`/`CommitDeployStatus` state (e.g., faking CI status, pushing fake HEAD commits) without ever authenticating — this is a Critical, cross-tenant integrity violation matching "forged webhook accepted" / "unauthorized ... state mutation."

### Likelihood Explanation
Requires only that a Shipit operator configured multi-org `secrets.github` with at least one org missing `webhook_secret` — a plausible operator misconfiguration (no code path enforces its presence). Given that precondition, exploitation is a single unauthenticated HTTP POST with no secrets, tokens, or GitHub access required, and is fully repeatable against any stack under that org.

### Recommendation
In `Shipit::GitHubApp#verify_webhook_signature`, fail closed when `webhook_secret` is blank (return `false`/raise) instead of `return true unless webhook_secret`; alternatively enforce at config-load time that every organization entry defines a non-blank `webhook_secret`, raising on boot if any is missing.

### Proof of Concept
```ruby
# test/lib/github_app_test.rb (or a new test)
test "verify_webhook_signature fails closed when webhook_secret is missing" do
  app = Shipit::GitHubApp.new('acme', { app_id: 1, installation_id: 1 }) # no webhook_secret
  refute app.verify_webhook_signature(nil, '{"any":"payload"}'),
    "org without webhook_secret must NOT be treated as verified"
end

# test/controllers/webhooks_controller_test.rb
test "POST /webhooks is rejected for org missing webhook_secret" do
  # stub Shipit.github secrets so 'acme' org config has no webhook_secret
  post :create, body: { repository: { owner: { login: 'acme' }, full_name: 'acme/repo' } }.to_json,
       headers: { 'X-Github-Event' => 'push' } # no X-Hub-Signature
  assert_response 422
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
