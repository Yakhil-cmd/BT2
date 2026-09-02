### Title
Webhook signature check unconditionally passes for any configured GitHub org missing `webhook_secret` - (`File: lib/shipit/github_app.rb`)

### Summary
`GitHubApp#verify_webhook_signature` returns `true` before evaluating the algorithm/signature whenever `webhook_secret` is blank for the org resolved from the webhook payload's `repository.owner.login`/`organization.login`. Since `Shipit.github_app_config`/`Shipit.github` only raises `GithubOrganizationUnknown` if the organization key is entirely absent from `secrets.github`, an org that is configured but simply omits `webhook_secret` in its config still resolves successfully and hits this bypass, letting an attacker send a fully unsigned/arbitrarily-"signed" payload that reaches `Webhooks.for_event(event).each { |handler| handler.call(params) }`.

### Finding Description
The broken binding: `webhook_secret.present?` for the org resolved via `repository_owner` == the guard actually executed in `verify_webhook_signature`. When `webhook_secret` is blank, line `return true unless webhook_secret` [1](#0-0)  short-circuits before the `algorithm, signature = signature.split("=", 2)` / `return false unless algorithm == 'sha1'` checks are ever reached [2](#0-1) .

The controller resolves the org purely from attacker-controlled JSON body fields: `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [3](#0-2) , then calls `Shipit.github(organization: repository_owner)` and `github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)` in `before_action :verify_signature` [4](#0-3) . `Shipit.github` raises `GithubOrganizationUnknown` only when `github_app_config(organization)` returns `nil`, i.e., the org key is missing entirely from `secrets.github` [5](#0-4) . An org whose config hash exists but lacks a `webhook_secret` key still resolves to a `GitHubApp` instance with `@webhook_secret = @config[:webhook_secret].presence` = `nil` [6](#0-5) .

Exploit flow: attacker sends `POST /webhooks` with `X-Github-Event` set to a handled event, `X-Hub-Signature: sha256=garbage` (or omitted entirely), and a body whose `repository.owner.login` matches an organization that is configured in Shipit but has no `webhook_secret` set. `verify_signature` calls `verify_webhook_signature('sha256=garbage', raw_body)`, which returns `true` immediately at line 77 regardless of header content, and `create` proceeds to dispatch the unsigned payload to all registered webhook handlers for that org's repositories [7](#0-6) .

This is confirmed by the existing test suite itself: `GitHubApp.new(@organization, {})` is explicitly exercised as a valid, non-raising configuration ("`#initialize doesn't raise if given an empty config`") [8](#0-7) , demonstrating that an org with empty/no `webhook_secret` is a supported, reachable configuration state, not an edge case guarded against elsewhere.

No other guard intervenes: `drop_unhandled_event` only filters by event type, not authenticity [9](#0-8) , and `check_if_ping` only handles pings [10](#0-9) .

### Impact Explanation
Any organization configured in `secrets.github` without a `webhook_secret` value accepts arbitrary unsigned webhook payloads claiming that org as `repository.owner.login`. This lets an unauthenticated attacker feed forged `pull_request`, `push`, `status`, etc. events into `Shipit::Webhooks` handlers, potentially mutating stack/commit/task state for any repository under that org without ever authenticating with GitHub - matching the "authentication bypass (forged webhook accepted)" Critical category. The blast radius is scoped to whichever org(s) are missing `webhook_secret`; if the sole/default org is misconfigured this way, it affects the entire Shipit installation for that tenant.

### Likelihood Explanation
This requires a specific operator misconfiguration: an organization entry present in `secrets.github` but without `webhook_secret` set (or set to a blank string, since `.presence` nils it out). This is not the default recommended setup (docs instruct configuring `webhook_secret`), but the codebase explicitly supports and tests it as a non-error configuration state, and there is no validation anywhere (`Shipit.github_app_config`, `GitHubApp#initialize`) that rejects or warns about a missing `webhook_secret`. Attacker cost is minimal - one HTTP POST, no secrets needed, fully repeatable against any org in this state.

### Recommendation
Require `webhook_secret` to be present for any configured GitHub org and fail closed (reject the webhook, e.g., return `false`/422) instead of `return true unless webhook_secret` in `GitHubApp#verify_webhook_signature`. At minimum, log/alert and refuse unsigned webhooks rather than defaulting to acceptance; ideally validate at boot/config-load time that every org in `secrets.github` has a non-blank `webhook_secret`.

### Proof of Concept
```ruby
# test/unit/github_app_test.rb (new test)
test "#verify_webhook_signature returns false (not true) when webhook_secret is missing" do
  github_app = Shipit::GitHubApp.new("OrgWithoutSecret", {}) # no webhook_secret configured

  # Binding under test: webhook_secret.present? == false, so the algorithm/signature
  # branch is never reached; assert this does NOT silently authenticate the request.
  assert_not github_app.verify_webhook_signature("sha256=garbage", "arbitrary body")
end
```
Currently `verify_webhook_signature` returns `true` for this input (confirmed by reading `lib/shipit/github_app.rb` lines 76-77), so this assertion fails against the current implementation, demonstrating the bypass.

### Citations

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

**File:** lib/shipit/github_app.rb (L76-77)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret
```

**File:** lib/shipit/github_app.rb (L79-82)
```ruby
      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
```

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L19-22)
```ruby
    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
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

**File:** app/controllers/shipit/webhooks_controller.rb (L51-53)
```ruby
    def check_if_ping
      head(:ok) if event == 'ping'
    end
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

**File:** test/unit/github_apps_test.rb (L44-48)
```ruby
    test "#initialize doesn't raise if given an empty config" do
      assert_nothing_raised do
        GitHubApp.new(@organization, {})
      end
    end
```
