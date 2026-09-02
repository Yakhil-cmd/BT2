This confirms the exploit path: `repository_owner` (used only for signature verification) is read from `repository.owner.login`, while the actual stack lookup in `Handler#repository_name` uses `repository.full_name` independently. An attacker can craft a payload where these two fields point at different organizations.

### Title
Unsigned webhook accepted and executed for a real stack when a secondary org has no `webhook_secret` configured - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp` to validate against using `repository.owner.login`, and `GitHubApp#verify_webhook_signature` returns `true` unconditionally when that app's `webhook_secret` is blank. Because the handler that actually mutates data (`Handler#repository_name`) looks up the target stack via the independent `repository.full_name` field, an attacker can pick an org name for `repository.owner.login` that maps to a secret-less `GitHubApp` while pointing `repository.full_name` at a real, secret-protected stack, bypassing signature verification entirely for that stack's webhook.

### Finding Description
The broken binding: for any org `O` with no configured `webhook_secret`, it must hold that `verified == false` for all payloads processed under `O`'s app — instead the code guarantees `verified == true` unconditionally: `return true unless webhook_secret` in `GitHubApp#verify_webhook_signature` [1](#0-0) .

`WebhooksController#verify_signature` resolves the app strictly from `repository_owner`, i.e. `params.dig('repository','owner','login')`, and passes/fails verification based on that app alone [2](#0-1) . Meanwhile `#create` invokes `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` with the full raw payload [3](#0-2) , and inside the handler, the actual repository/stack the mutation targets is derived from a *different* field: `payload.dig('repository', 'full_name')` via `Handler#repository_name` and `#stacks` [4](#0-3) . `PushHandler#process`, for example, updates `stacks.not_archived.where(branch:).find_each { |stack| stack.sync_github(...) }` for whatever stacks match that `full_name` [5](#0-4) .

Because `owner.login` (used to select the verifying `GitHubApp`) and `full_name` (used to select the target stack) are independently attacker-controlled fields in the same unauthenticated JSON body, an attacker can set `repository.owner.login = "org-unconfigured"` (an org configured under multi-org `github:` config per `docs/setup.md` and `config/secrets.development.shopify.yml` example, but lacking `webhook_secret`) while setting `repository.full_name = "configured-org/real-repo"` — a real, secret-protected stack. `Shipit.github(organization: 'org-unconfigured')` resolves via `Shipit.github_app_config` / `TOP_LEVEL_GH_KEYS` handling in `lib/shipit.rb` [6](#0-5) , yields a `GitHubApp` with `@webhook_secret` nil, and `verify_webhook_signature` returns `true` regardless of the (even garbage) `X-Hub-Signature` header. The handler then runs against `configured-org/real-repo` fully unsigned.

No other guard exists: `drop_unhandled_event` only filters by event type, not by org [7](#0-6) , and there is no cross-check that `repository.owner.login` matches the owner implied by `repository.full_name`.

### Impact Explanation
An unauthenticated attacker can trigger `Shipit::Webhooks` handlers (`push`, `pull_request`, `status`, `check_suite`, `membership`, etc.) against any stack belonging to a fully-secured organization, as long as any other org in the same Shipit installation's multi-org `github:` config lacks a `webhook_secret`. This is a payload for one repository ("org-unconfigured") mutating another organization's stack ("configured-org/real-repo") entirely without a valid signature — matching the Critical category "a payload for one repository mutating another's stack" and "authentication bypass (forged webhook ... accepted)". It is repeatable against any stack/branch in the target org and any handled event type, and the blast radius spans every tenant stack hosted by the Shipit instance, not just the misconfigured org's own repos.

### Likelihood Explanation
Requires the deployment to use the multi-org GitHub App config schema (`config/secrets.yml` `github: { org: {...} }` per `docs/setup.md` lines 182-209) with at least one org entry that omits `webhook_secret` — a configuration explicitly presented as valid/optional in the docs and example secrets files (`config/secrets.development.example.yml`, `config/secrets.development.shopify.yml`, `test/dummy/config/secrets_double_github_app.yml` all show `webhook_secret: # nil` as an accepted state). Given webhook secrets are documented as "(optional)" in `docs/setup.md`, this is a plausible real-world misconfiguration, not a contrived edge case. Attacker cost is a single unauthenticated HTTP POST to `/webhooks` with no secrets required.

### Recommendation
Do not let signature verification success depend on which org name the attacker supplies. Options: (1) require `webhook_secret` to be non-blank for every configured org and fail closed (`head(422)`/raise) if any org's `webhook_secret` is missing rather than treating it as "skip verification"; (2) after selecting the handler's target stack via `repository.full_name`, verify that stack's owning organization matches `repository_owner` before invoking handlers, so a secret-less org can never authorize actions on another org's repository; (3) change `GitHubApp#verify_webhook_signature` to return `false` (fail closed) when `webhook_secret` is blank instead of `true`, and require operators to always set a webhook secret per org.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (new test)
test "push webhook is accepted and processed unsigned for a real stack when the payload's owner org has no webhook_secret" do
  configured_stack = shipit_stacks(:shipit) # real stack under "configured-org/real-repo"
  Shipit.stubs(:github_app_config).with('org-unconfigured').returns({}) # no webhook_secret key
  # or: stub Shipit.github(organization: 'org-unconfigured') to return GitHubApp.new('org-unconfigured', {})

  payload = {
    'repository' => {
      'owner' => { 'login' => 'org-unconfigured' },
      'full_name' => configured_stack.repository.full_name
    },
    'ref' => "refs/heads/#{configured_stack.branch}",
    'after' => 'deadbeef'
  }.to_json

  PushHandler.any_instance.expects(:process) # or assert stack.sync_github called

  post :create, body: payload, params: {}, headers: {
    'X-Github-Event' => 'push',
    'X-Hub-Signature' => 'sha1=garbage'
  }

  assert_response :ok
  # Binding check: webhook_secret.blank? == true  =>  verified should be false, but is true
end
```
This demonstrates `verified == true` when it should be `verified == false`, and that the handler executes against `configured-org/real-repo`'s stack despite the request carrying an invalid signature.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L19-22)
```ruby
    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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
