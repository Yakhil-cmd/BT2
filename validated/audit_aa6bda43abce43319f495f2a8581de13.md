### Title
Unsigned webhook forgery accepted for any organization configured without a `webhook_secret` - (File: lib/shipit/github_app.rb)

### Summary
`GitHubApp#verify_webhook_signature` fails open: when `@config[:webhook_secret]` is blank for a configured GitHub organization, the method returns `true` regardless of the `X-Hub-Signature` header or payload content. Since `WebhooksController#verify_signature` routes verification through `Shipit.github(organization: repository_owner)` using the payload's own `repository.owner.login`, any unauthenticated caller can pick a configured-but-secretless organization and have arbitrary webhook payloads (push, pull_request, status, membership, check_suite) processed as genuine.

### Finding Description
The broken binding: the controller assumes `verified == (signature matches HMAC(webhook_secret, raw_body))`, but in reality `verified == true` whenever `webhook_secret` is blank, independent of `signature` or `raw_body`.

Path:
- `WebhooksController#verify_signature` at [1](#0-0)  computes `repository_owner` directly from the untrusted JSON body (`params.dig('repository', 'owner', 'login')`, see [2](#0-1) ) and passes it to `Shipit.github(organization: repository_owner)`.
- `Shipit.github` resolves the per-organization config via `github_app_config(organization)` at [3](#0-2)  and instantiates a `GitHubApp` with that org's config.
- `GitHubApp#initialize` sets `@webhook_secret = @config[:webhook_secret].presence` at [4](#0-3) .
- `verify_webhook_signature` at [5](#0-4)  starts with `return true unless webhook_secret` — if that org's `webhook_secret` is blank, the signature and body are never checked, and the method unconditionally returns `true`.
- Back in the controller, `verified` is `true`, so `head(422) unless verified` never fires, and `create` proceeds to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` at [6](#0-5) , dispatching the attacker-controlled payload to real handlers (e.g. `GithubSyncJob`, `RefreshCheckRunsJob`, team/user creation on `membership`).

Attacker request: any internet host, no auth, POSTs to `/webhooks` with `X-Github-Event` set to a supported event and a JSON body whose `repository.owner.login` (or `organization.login`) names an organization that is present in `Shipit.github_organizations` (i.e., configured via `github_app_config`) but whose `webhook_secret` is nil/blank. `X-Hub-Signature` can be omitted or garbage.

Existing guards do not prevent this: `drop_unhandled_event` only filters unsupported event types; `GithubOrganizationUnknown` handling only guards against organizations not present in config at all, not against configured-but-secretless organizations; there is no separate requirement elsewhere in the controller or `GitHubApp` that `webhook_secret` be present for a configured org.

### Impact Explanation
For any organization configured in `secrets.github` without a `webhook_secret`, an unauthenticated attacker can forge arbitrary webhook events processed by Shipit's real handlers — triggering `GithubSyncJob` (push), `RefreshCheckRunsJob` (check_suite), creating `Team`/`User` records (membership), or influencing commit/status state — for any repository claimed to belong to that organization. This is repeatable indefinitely and applies per-tenant to every organization configured this way; it is an authentication bypass matching the Critical severity category (forged webhook accepted).

### Likelihood Explanation
The precondition is a specific operator misconfiguration: an organization entry exists in `Shipit.github`'s multi-org config schema but lacks a `webhook_secret` value (blank/nil), which is exactly the state demonstrated by `OrgOne`/`OrgTwo` in `test/dummy/config/secrets_double_github_app.yml` and permitted by the commented example in `config/secrets.development.example.yml`. No secret knowledge is required by the attacker — the flaw is that the code silently treats "no secret configured" as "trust everything" rather than failing closed, so any deployment with this configuration state is immediately and trivially exploitable with a single unauthenticated POST.

### Recommendation
Change `GitHubApp#verify_webhook_signature` to fail closed when no `webhook_secret` is configured (return `false`, or raise/log a configuration error) instead of `return true unless webhook_secret`. Optionally add a startup/config validation that requires `webhook_secret` to be present for every organization entry in `Shipit.github`.

### Proof of Concept
In a minitest webhook controller test:
1. Stub `Shipit.github(organization: 'OrgOne')` (or configure test secrets to include an org with `webhook_secret: nil`) so `github_app_config('OrgOne')[:webhook_secret]` is blank.
2. Build a `push` payload JSON with `repository.owner.login == 'OrgOne'` and `repository.full_name` naming a real tracked stack.
3. Set `request.headers['X-Github-Event'] = 'push'` and either omit `X-Hub-Signature` or set it to `'sha1=deadbeef'`.
4. Assert:
   - Before fix: `assert_enqueued_with(job: GithubSyncJob) { post :create, body: payload, as: :json }` and `assert_response :ok` — i.e. `verified == true` even though the HMAC over `webhook_secret` (blank) and `raw_post` was never actually checked against the supplied/garbage signature.
   - Expected/fixed behavior: `assert_response :unprocessable_entity` and no job enqueued, i.e. `verified == false` when `webhook_secret` is blank, closing the divergence between "signature checked" and "signature ignored."

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** lib/shipit.rb (L170-200)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
```

**File:** lib/shipit/github_app.rb (L44-57)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]

      oauth = (@config[:oauth] || {}).with_indifferent_access
      @oauth_id = oauth[:id]
      @oauth_secret = oauth[:secret]
      @oauth_teams = Array.wrap(oauth[:teams])
    end
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
