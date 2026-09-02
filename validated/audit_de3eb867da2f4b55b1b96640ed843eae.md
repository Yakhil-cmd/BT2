### Title
Webhook signature is verified against `repository.owner.login`/`organization.login` while the acted-upon repository comes from an unchecked `repository.full_name` field — organization-that-authenticated ≠ repository-that-is-written - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/secret to verify the HMAC signature against using `repository_owner`, a value taken from the untrusted JSON body (`params.dig('repository','owner','login')` or `params.dig('organization','login')`). The actual repository/stack that the webhook handlers act on is derived independently, from `payload.dig('repository','full_name')` inside `Shipit::Webhooks::Handlers::Handler#repository_name`. These two payload fields are never cross-checked against each other, so the "organization whose secret authenticated the request" and "the repository the handler writes to" are two separate, independently attacker-controlled inputs.

### Finding Description
Signature verification: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` resolves the app config per organization key, raising only if the organization key itself is unknown; it does not require a `webhook_secret` to be present for that org: [3](#0-2) 

The actual signature check silently passes for any org whose config omits `webhook_secret`: [4](#0-3) [5](#0-4) 

Meanwhile, every handler resolves the target repository/stacks from a completely different, unauthenticated field of the same payload: [6](#0-5) 

Because `repository_owner` (used to pick the verifying secret) and `repository.full_name` (used to pick the repository/stack acted upon) are independent JSON fields with no equality enforced between them, an attacker can set `repository.owner.login`/`organization.login` to any organization configured in Shipit that happens to have no `webhook_secret` set (permitted by the code, since it's `.presence`-guarded and optional), while setting `repository.full_name` to a fully-protected victim repository that does have stacks and enforced statuses. The forged request sails through `verify_signature` (bypassed because the "authenticating" org has no secret) and then `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` executes against the victim repository named in `repository.full_name`.

### Impact Explanation
This breaks the deployment-trust binding "organization that authenticated == repository that is written." Concrete write actions reachable via forged webhooks against an arbitrary victim repo/stack:
- `PushHandler#process` calls `stack.sync_github(expected_head_sha: params.after)` for any stack matching the victim repo/branch, letting the attacker push arbitrary head SHAs into Shipit's tracked history for that stack: [7](#0-6) 
- `StatusHandler#process` creates a CI `Status` for an arbitrary commit SHA (`commit.create_status_from_github!`), which can be used to mark victim commits as CI-passing (`required_statuses`/`release_status_context` gate deploys): [8](#0-7) 
- `PullRequest::OpenedHandler`/`ClosedHandler`/`ReopenedHandler` can create, archive, or unarchive review stacks for the victim repository.

Forging a passing CI status for a commit that has not actually passed CI can enable an unauthorized/unreviewed deploy on the victim stack, which falls under the Critical "unauthorized deploy" impact category, and the cross-repository write of commit/status/stack state is itself a cross-repository write.

### Likelihood Explanation
Exploitability depends on at least one organization being configured in Shipit's multi-org GitHub credentials with no `webhook_secret` set — a state the code explicitly permits (`@config[:webhook_secret].presence`) rather than rejects. Any Shipit deployment onboarding multiple organizations (e.g., an internal/staging org added without a webhook secret) creates this condition. The endpoint is fully unauthenticated/public (webhook route), requires no token, no GitHub write access, and no session — matching an unprivileged-attacker analog. The main uncertainty is confirming that at least one org config without `webhook_secret` is a realistic deployment configuration versus purely hypothetical; the codebase makes this state legal and does not warn against it.

### Recommendation
Bind the verification identity to the resource being acted on: derive `repository_owner` from the same `repository.full_name` used by handlers (or require them to match), and reject the request if they diverge. Additionally, require `webhook_secret` to be present for every configured organization (fail closed) rather than allowing `verify_webhook_signature` to return `true` when no secret is configured, and ensure `Shipit.github_app_config` cannot resolve to a "no secret" state silently.

### Proof of Concept
1. Configure Shipit in multi-org mode with two organizations, `unsecured-org` (no `webhook_secret` set) and `victim-org` (has a stack, `webhook_secret` set, and required CI statuses gating deploy).
2. POST to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "organization": { "login": "unsecured-org" },
  "repository": { "owner": { "login": "unsecured-org" }, "full_name": "victim-org/victim-repo" },
  "sha": "<victim commit sha awaiting CI>",
  "state": "success",
  "context": "required-ci-context"
}
```
No valid `X-Hub-Signature` is needed because `verify_webhook_signature` returns `true` for `unsecured-org` (`lib/shipit/github_app.rb:76-83`).
3. `WebhooksController#verify_signature` passes (`repository_owner` resolves to `unsecured-org`), then `StatusHandler#process` runs and looks up the commit by `params.sha` under `victim-org/victim-repo` via `Handler#repository_name` (`payload.dig('repository','full_name')`), creating a fabricated "success" status for the victim commit — potentially unblocking deploy of that commit on `victim-org`'s stack.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
