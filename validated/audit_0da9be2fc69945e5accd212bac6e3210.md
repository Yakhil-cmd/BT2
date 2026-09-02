### Title
`GitHubApp#verify_webhook_signature` returns `true` unconditionally when an organization has no `webhook_secret`, allowing unauthenticated webhook forgery - (File: `lib/shipit/github_app.rb`)

### Summary
`GitHubApp#verify_webhook_signature` short-circuits with `return true unless webhook_secret`, so any organization configured in `Shipit.github` without a `webhook_secret` accepts webhooks with no valid HMAC at all. Since `WebhooksController#verify_signature` selects the `GitHubApp` instance purely from the attacker-controlled `repository.owner.login` field in the JSON body, an attacker can send a completely unsigned/garbage `X-Hub-Signature` for any org lacking a secret and reach handlers like `AssignedHandler#process`, which calls `pull_request.update(github_pull_request: params.pull_request)` on a real `Shipit::PullRequest`.

### Finding Description
The broken binding: `verify_webhook_signature(signature, message) == true` is claimed to imply `SecureCompare.secure_compare(signature_hmac, HMAC-SHA1(webhook_secret, message)) == true`. In fact: [1](#0-0) 

`return true unless webhook_secret` makes the equality vacuously true whenever `@webhook_secret` (set from `@config[:webhook_secret].presence` at `lib/shipit/github_app.rb:50`) is blank for that organization's config entry.

The controller resolves which `GitHubApp`/secret to check strictly from attacker-supplied JSON: `repository_owner` reads `params.dig('repository', 'owner', 'login')`, and `Shipit.github(organization: repository_owner)` is used to fetch the corresponding config via `github_app_config`: [2](#0-1) [3](#0-2) [4](#0-3) 

If the operator's `secrets.github` config has an org entry ("OrgC") that omits `webhook_secret`, `verify_signature` sets `verified = true` regardless of the `X-Hub-Signature` header content, and the request proceeds to `WebhooksController#create`, which dispatches to registered handlers such as `AssignedHandler`: [5](#0-4) 

`AssignedHandler#process` looks up an existing `Shipit::PullRequest` scoped by `number` and the repository derived from `params.repository.full_name`, then calls `.update(github_pull_request: params.pull_request)` without any authentication of the request's origin. No other guard (`drop_unhandled_event`, `ExplicitParameters` schema validation) checks the caller's identity — they only validate JSON shape and event type, not authenticity.

Attacker request: POST `/webhooks` with header `X-Github-Event: pull_request`, an arbitrary/garbage `X-Hub-Signature`, and a JSON body with `action: "assigned"`, `repository.owner.login: "OrgC"`, `repository.full_name` matching a real tracked repo, and `number` matching an existing PR. Since OrgC has no `webhook_secret`, `verify_webhook_signature` returns `true` and the mutation proceeds.

### Impact Explanation
An unauthenticated, unprivileged attacker can write arbitrary attacker-controlled `pull_request` JSON into a real `Shipit::PullRequest`'s `github_pull_request` field for any repository whose owning organization has no `webhook_secret` configured, and (depending on registered handlers for other events) trigger other webhook-driven side effects (e.g., stack archive/unarchive via `unlabeled_handler.rb`, review-stack provisioning via `opened_handler.rb`) without ever knowing a secret. This is a record write for a repository the attacker did not authenticate, matching the Critical category ("a payload for one repository mutating another's stack... or an unauthorized... action" via forged webhook / authentication bypass). It is fully repeatable against any org lacking a `webhook_secret` and any stack/PR under that org's tracked repositories.

### Likelihood Explanation
This requires a specific, non-default operator misconfiguration: at least one organization entry in `Shipit.github`/`secrets.github` must omit `webhook_secret` while being an active, tracked organization. `docs/setup.md` documents `webhook_secret` as part of the GitHub App setup, but the code and `GitHubApp#initialize` (`lib/shipit/github_app.rb:50`) do not enforce its presence — a blank/missing secret is silently accepted and, per `.presence`, degrades verification to "always true." Given multi-org Shipit deployments (`TOP_LEVEL_GH_KEYS`/`github_app_config` support multiple orgs), it's plausible for one org to be added without a secret (e.g., during initial setup or a config error) while others are properly configured — the attacker cost is then just crafting an HTTP POST with no cryptographic material needed.

### Recommendation
Change `verify_webhook_signature` to fail closed when no `webhook_secret` is configured (`return false unless webhook_secret`), and/or enforce at startup/config-validation time that every organization entry in `Shipit.github` must have a non-blank `webhook_secret`, raising a configuration error otherwise.

### Proof of Concept
Minitest plan (no live GitHub):
1. Unit test in `test/lib/shipit/github_app_test.rb`:
   ```ruby
   test "verify_webhook_signature returns true with no secret configured (vulnerable)" do
     app = Shipit::GitHubApp.new('OrgC', {})
     assert_equal true, app.verify_webhook_signature(nil, '{"any":"garbage"}')
     assert_equal true, app.verify_webhook_signature('sha1=deadbeef', '{"any":"garbage"}')
   end
   ```
   Assert both sides of the claimed binding: `verified == true` vs. `HMAC-checked == false` (no secret exists to check against) — they diverge, proving the bypass.
2. Integration test in `test/controllers/webhooks_controller_test.rb` (or a new test file) that stubs `Shipit.github(organization: 'OrgC')` to return a `GitHubApp.new('OrgC', {})` (no `webhook_secret`), then POSTs a `pull_request` `assigned` event with an existing `Shipit::PullRequest` fixture under an "OrgC" repository and a bogus `X-Hub-Signature` header, asserting `response :ok` and that `pull_request.reload.github_pull_request` was updated to the attacker-supplied payload — demonstrating `AssignedHandler#process` executed the `update` without any valid signature.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb (L41-45)
```ruby
          def process
            return unless respond_to_assignee_change?

            pull_request.update(github_pull_request: params.pull_request) if pull_request.present?
          end
```
