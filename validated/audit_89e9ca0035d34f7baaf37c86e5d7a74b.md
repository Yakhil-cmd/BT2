### Title
Unauthenticated `push` webhook forgery for orgs without a configured `webhook_secret` triggers `PushHandler`/`sync_github` - (File: `lib/shipit/github_app.rb`)

### Summary
`GitHubApp#verify_webhook_signature` unconditionally returns `true` when the org's `webhook_secret` is blank/unconfigured, regardless of the presence, validity, or algorithm of `X-Hub-Signature`. Combined with `WebhooksController#verify_signature`, which derives the org and thus the `GitHubApp` instance entirely from the attacker-controlled payload (`repository.owner.login`/`organization.login`), an attacker can send a completely unsigned/forged `push` payload for any org configured without a `webhook_secret` and have it processed as legitimate, causing `PushHandler` to run `stack.sync_github` for any matching stack.

### Finding Description
The broken binding: the invariant should be `verified == (signature cryptographically matches HMAC-SHA1/256 of raw_post using the org's webhook_secret)`. Instead, in `lib/shipit/github_app.rb`:

```
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [1](#0-0) 

When `@webhook_secret` is `nil`/blank for the org resolved from the payload, `verify_webhook_signature` returns `true` for *any* input — including a missing header, garbage signature, or a body with no relation to a real GitHub delivery. This happens before the sha1-vs-sha256 algorithm check is even reached, so the "legacy sha1 signature header" gap is simply a subset of a broader "no secret configured -> no verification at all" gap.

The controller resolves which `GitHubApp` (and thus which webhook_secret policy) to use purely from the untrusted body:
```
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
``` [2](#0-1) 
```
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [3](#0-2) 

If that org's config in `Shipit.github_apps`/secrets has no `webhook_secret`, `verify_signature` never rejects the request. The `create` action then dispatches to handlers with the raw, forged payload:
```
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
``` [4](#0-3) 

`PushHandler` then acts on that forged payload:
```
def process
  stacks
    .not_archived
    .where(branch:)
    .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
end
``` [5](#0-4) 

Importantly, `stacks` (and thus which repository/stack is affected) is scoped by `Repository.from_github_repo_name(repository_name)`, where `repository_name` is `payload.dig('repository', 'full_name')` — also attacker-controlled:
```
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [6](#0-5) 

So the blast radius is confined to whatever `repository.full_name` the attacker names in the same forged JSON body — but that repository/stack only needs to belong to an org lacking a `webhook_secret`; the attacker does not need to know or hold any secret for it. `sync_github(expected_head_sha: ...)` on `Stack` triggers commit sync against the real GitHub state (via GitHub App/API credentials the server holds), which can advance `head`/append commits recognized by Shipit and feed continuous-deployment logic depending on stack configuration (e.g., continuous delivery enabled) — an unauthenticated party thereby drives internal state changes and downstream automation for a stack they do not control, without ever supplying a valid signature.

No other guard intervenes: `check_if_ping` only special-cases the `ping` event; `drop_unhandled_event` only filters unsupported event types, not authenticity; there is no secondary secret check, IP allowlist, or GitHub App signature enforcement independent of the per-org `webhook_secret` presence. The `ExplicitParameters` schema in `PushHandler` (`requires :ref`, `requires :after`) validates shape, not origin.

### Impact Explanation
For any org whose `Shipit.github_apps` configuration omits `webhook_secret` (a configuration state the code silently accepts as "trust everything" rather than "reject everything," which is the secure default for a supposed authentication boundary), an unauthenticated internet attacker can:
- Forge arbitrary `push` events for any repository under that org and cause `PushHandler` to invoke `stack.sync_github(expected_head_sha: ...)` for every matching non-archived stack/branch.
- This can desynchronize or advance Shipit's tracked commit history for a repository/stack the attacker does not own or control, and interact with continuous-deployment automation depending on stack config — matching the "unauthorized deploy/rollback" / "payload for one repository mutating another's stack" severity category (Critical) since the request is accepted with **no valid credential whatsoever**, not merely a downgraded algorithm.
- Repeatable indefinitely and for every repository under any no-secret org, i.e., blast radius scales with the number of misconfigured orgs.

### Likelihood Explanation
Preconditions: at least one org in `Shipit.github_apps`/secrets configuration has no `webhook_secret` set (this is a supported, non-error configuration state in `GitHubApp#initialize`, not a validation-blocked state) [7](#0-6) . Given that, attacker cost is a single unauthenticated `POST /webhooks` with a JSON body and headers `X-Github-Event: push`, no `X-Hub-Signature` required at all (or any garbage value) — trivial and fully repeatable, no GitHub account, session, or secret needed.

### Recommendation
Treat a missing `webhook_secret` as "reject all webhooks for this org" rather than "skip verification." In `GitHubApp#verify_webhook_signature`, replace `return true unless webhook_secret` with `return false unless webhook_secret`, and require `X-Hub-Signature-256` (`sha256`) using constant-time comparison. Additionally, log/alert or fail startup validation when an org is configured without a `webhook_secret` so the misconfiguration is caught at deploy time rather than silently permitting unauthenticated writes.

### Proof of Concept
```ruby
# test/controllers/shipit/webhooks_controller_test.rb (new test)
test "push webhook is accepted unconditionally for an org configured without webhook_secret" do
  org_config = { app_id: 1, installation_id: 1 } # no webhook_secret key
  Shipit.stubs(:github_apps).returns('no-secret-org' => org_config)
  # or directly stub Shipit.github(organization: 'no-secret-org') to return
  # a GitHubApp.new('no-secret-org', org_config)

  repo = shipit_repositories(:shipit)
  repo.update!(owner: 'no-secret-org') # ensure owner resolves to the no-secret org
  stack = repo.stacks.first
  refute_nil stack

  payload = {
    ref: "refs/heads/#{stack.branch}",
    after: 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
    repository: { full_name: repo.full_name, owner: { login: 'no-secret-org' } }
  }.to_json

  Shipit::Stack.any_instance.expects(:sync_github)
    .with(expected_head_sha: 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef')

  post '/webhooks', params: payload, headers: {
    'X-Github-Event' => 'push',
    'Content-Type' => 'application/json'
    # deliberately NO X-Hub-Signature header at all
  }

  assert_response :ok
end
```

Binding tested: before — `verified == true` is expected only when `signature` cryptographically matches `HMAC(webhook_secret, raw_post)`; after — the test shows `verified == true` even with **no signature header present at all**, and `sync_github` is invoked, proving the equality does not hold for orgs without `webhook_secret`.

### Citations

**File:** lib/shipit/github_app.rb (L44-51)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```
