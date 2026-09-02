This confirms the vulnerability exists exactly as described. `GitHubApp#verify_webhook_signature` unconditionally returns `true` when `webhook_secret` is not configured for an organization [1](#0-0) , and `WebhooksController#verify_signature` resolves the app via `Shipit.github(organization: repository_owner)` where `repository_owner` is taken directly from the untrusted JSON payload [2](#0-1) . In a multi-tenant `github_apps` config, any org entry lacking a `webhook_secret` key causes signature verification to be bypassed entirely for that org's traffic, and `#create` then dispatches to handlers unauthenticated [3](#0-2) .

### Title
Unauthenticated webhook processing when an org's `webhook_secret` is unset - (File: lib/shipit/github_app.rb, app/controllers/shipit/webhooks_controller.rb)

### Summary
`GitHubApp#verify_webhook_signature` returns `true` unconditionally when `webhook_secret` is blank/absent for the resolved organization's config, and `WebhooksController#verify_signature` resolves that organization straight from attacker-controlled `repository.owner.login`/`organization.login` in the JSON payload. In a multi-org Shipit deployment where at least one configured org omits `webhook_secret`, any internet user can forge webhook events for that org's repositories with no valid signature.

### Finding Description
The broken binding: `verified == (HMAC-SHA1(webhook_secret, raw_post) == signature)` is claimed to hold for every processed event, but for an org whose config hash has no `webhook_secret`, the actual code path is `return true unless webhook_secret` at [4](#0-3) , making `verified` always `true` regardless of `signature` or `message`.

Trace: `WebhooksController#verify_signature` computes `repository_owner` from `params.dig('repository','owner','login') || params.dig('organization','login')` [5](#0-4) , both of which are attacker-supplied JSON fields with no prior authentication. It then calls `Shipit.github(organization: repository_owner)`, which looks up that org's config via `github_app_config` and instantiates a `GitHubApp` bound to whatever `webhook_secret` (or lack thereof) is configured for that org [6](#0-5) . If verification returns `true` (either legitimately, or vacuously via the missing-secret bypass), `#create` parses the raw body and dispatches to `Shipit::Webhooks.for_event(event)` handlers, which process push/status/pull_request/membership/check_suite events, enqueue jobs, write commits/statuses/teams for that org's tracked stacks [3](#0-2) . No other guard exists between the request and handler execution — `drop_unhandled_event` only filters by event type, not authenticity, and `check_if_ping` only short-circuits ping events.

Existing tests confirm signature verification is the sole gate and is expected to always be enforced per-org (e.g. `test "verifies webhook signature"` mocks `verify_webhook_signature` returning `false` to get a 422) [7](#0-6) , but no test covers the case of an org configured without `webhook_secret`, which silently defeats this gate by design of line 77.

### Impact Explanation
For any org configured without a `webhook_secret`, an unauthenticated attacker can forge arbitrary webhook payloads (push, status, check_suite, pull_request, membership) that Shipit will process as legitimate GitHub events for that org's repositories — e.g., triggering `GithubSyncJob`, fabricating commit statuses, or manipulating team memberships (`Team`/`Membership` records) — without ever needing the org's real webhook secret. This is a full authentication bypass scoped to any org lacking `webhook_secret`, repeatable indefinitely and across every repository owned by that org.

### Likelihood Explanation
Requires a specific deployment precondition: a multi-tenant `github_apps`/`secrets.github` configuration where at least one org entry omits `webhook_secret` (e.g., an org where webhooks were never intended to be enabled, or the operator forgot to set the secret). Given that precondition, exploitation costs nothing — a single unauthenticated `POST /webhooks` with a JSON body naming that org, with any or no `X-Hub-Signature` header.

### Recommendation
In `GitHubApp#verify_webhook_signature`, do not treat a missing `webhook_secret` as automatic success. Either require `webhook_secret` to be present for every configured org at boot/config-validation time, or make `verify_webhook_signature` return `false` (fail closed) when `webhook_secret` is blank, forcing webhooks for that org to be rejected rather than silently trusted.

### Proof of Concept
minitest plan (in `test/controllers/webhooks_controller_test.rb` style, extending existing setup):
1. Stub/configure an organization (e.g. `'shopify'`) such that `Shipit.github(organization: 'shopify').verify_webhook_signature` is exercised via the real `GitHubApp` with `webhook_secret: nil` — construct `GitHubApp.new('shopify', { webhook_secret: nil })` and stub `Shipit.github` to return it.
2. Build an unsigned push payload for a stack tracked under that org (reuse `payload(:push_master)` merged with `repository_params` pointing at `'shopify'`).
3. `assert_enqueued_with(job: GithubSyncJob, args: [...])` around `post :create, body: parsed_body.to_json, as: :json` with no `X-Hub-Signature` header (or a garbage one).
4. Assert `assert_response :ok` (200), not `:unprocessable_entity` (422) — demonstrating `verify_webhook_signature` returned `true` and the job was enqueued despite no valid signature, proving `verified == true` while `HMAC(secret, raw_post) == signature` is false/undefined.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

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

**File:** test/controllers/webhooks_controller_test.rb (L94-107)
```ruby
    test "verifies webhook signature" do
      commit = shipit_commits(:first)

      payload = { "sha" => commit.sha, "state" => "pending", "target_url" => "https://ci.example.com/1000/output" }.merge(repository_params).to_json
      signature = 'sha1=4848deb1c9642cd938e8caa578d201ca359a8249'

      @request.headers['X-Github-Event'] = 'push'
      @request.headers['X-Hub-Signature'] = signature

      Shipit.github(organization: 'shopify').expects(:verify_webhook_signature).with(signature, payload).returns(false)

      post :create, body: payload, as: :json
      assert_response :unprocessable_entity
    end
```
