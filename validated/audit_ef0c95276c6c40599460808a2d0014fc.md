### Title
Webhook processing binds writes to `repository.full_name` while signature verification binds trust to `repository.owner.login`, allowing a mis-scoped/unsigned org to author events for any repository's stack - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
`WebhooksController#verify_signature` selects which `GitHubApp`/webhook secret to validate a delivery against using `repository_owner`, taken from `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`, but the actual state-mutating logic in `Shipit::Webhooks::Handlers::Handler#stacks` looks up the target `Stack` using a completely different, independently-controlled payload field: `payload.dig('repository', 'full_name')`. Nothing binds these two fields together, so the "organization whose credentials authenticated the request" and "the repository that is actually written to" are not the same equality that the deployment-trust model assumes.

### Finding Description
In a multi-organization Shipit deployment (`Shipit.github_organizations`, `Shipit.github_app_config`), each configured GitHub App organization has its own `webhook_secret` [1](#0-0) . Verification of an inbound webhook picks the app/secret solely from the payload's `repository.owner.login` (or `organization.login`) field: [2](#0-1) 

`GitHubApp#verify_webhook_signature` explicitly **skips verification entirely** when that selected organization has no `webhook_secret` configured: [3](#0-2) 

The example/deployment configs in this engine document organizations that intentionally omit a `webhook_secret` (`webhook_secret: # nil`) [4](#0-3) .

Once `verify_signature` passes (either because the selected org has no secret, or because signature verification otherwise succeeds), `WebhooksController#create` dispatches the *entire* raw payload to handlers without re-checking that `repository.full_name` belongs to the same organization that was used for authentication: [5](#0-4) 

The handler base class then resolves the target `Stack` purely from `repository.full_name`, with no cross-check against `repository.owner.login`/the authenticating organization: [6](#0-5) 

For example, `PushHandler` uses that repository-derived `stacks` scope to trigger `stack.sync_github(expected_head_sha: params.after)` against any stack under the resolved repository [7](#0-6) .

This is the direct analog of the reported bug class: the binding the engine implicitly relies on is `repository.owner.login (authenticated) == repository.full_name's owner (written)`, but no code enforces this equality. Just as swapping `VoteWeighting` broke the assumption that "the contract queried equals the contract that was configured for rewards," here the field used to pick the trust anchor (`repository.owner.login`) and the field used to determine what gets mutated (`repository.full_name`) are decoupled, and an app deployer/operator who configures a secret-less "backward compatibility" or secondary organization (a documented, supported configuration in this engine — see `github_default_organization`/`github_app_config` [8](#0-7) ) unintentionally creates an unauthenticated entry point that can carry a `repository.full_name` pointing at a stack belonging to a different, fully-secured organization.

### Impact Explanation
If any configured organization in `secrets.github` lacks a `webhook_secret` (a state the code explicitly supports via `return true unless webhook_secret`), an unauthenticated actor can send a crafted webhook with `repository.owner.login` set to that unsecured organization while `repository.full_name` points to a repository/stack owned by a different, secured organization. Because `Handler#stacks` never checks the owner/organization consistency, this results in unauthorized triggering of stack behavior (e.g., `sync_github`, membership/team creation, PR-driven merge-queue actions) for repositories outside the trust boundary that was actually authenticated — an unauthorized write/deploy-adjacent action originating from a boundary that was never cryptographically verified for that repository.

### Likelihood Explanation
This requires a specific, but supported and documented, deployment configuration: multiple GitHub organizations configured under `secrets.github`, with at least one organization missing a `webhook_secret` (explicitly shown as a valid config value in `config/secrets.development.shopify.yml`). Single-organization "backward compatible" deployments (`github_default_organization.nil?`) are unaffected because there is only one app/secret to select from — but even there, if `webhook_secret` is left blank (which the code tolerates), the same unauthenticated dispatch occurs for events targeting any repository name in the payload, entirely bypassing signature verification. Given `webhook_secret` is documented as "optional" in `docs/setup.md`, the misconfiguration is plausible in production.

### Recommendation
- Enforce that `repository.owner.login` (used to select the signing organization) matches the owner segment of `repository.full_name` (used to resolve the target stack) before dispatching to handlers.
- Do not silently bypass signature verification when `webhook_secret` is blank for a resolved organization; either require a secret for every configured organization or explicitly document/gate this as an insecure mode with a hard warning, since it currently allows unauthenticated event injection for the org's configured trust boundary.
- Pass the authenticated organization context into `Handler#stacks`/`repository_name` resolution so lookups are scoped to repositories consistent with the verifying organization, rather than trusting an unrelated field from the same unauthenticated JSON body.

### Proof of Concept
1. Deploy Shipit with two organizations configured under `secrets.github`: `secured-org` (has a `webhook_secret`) and `legacy-org` (no `webhook_secret`, per the documented/example config).
2. Send `POST /webhooks` with header `X-Github-Event: push` and a JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-controlled-sha>",
  "repository": {
    "owner": { "login": "legacy-org" },
    "full_name": "secured-org/production-repo"
  }
}
```
3. `WebhooksController#verify_signature` resolves `repository_owner => "legacy-org"`, calls `Shipit.github(organization: "legacy-org")`, and since that org's `webhook_secret` is blank, `verify_webhook_signature` returns `true` unconditionally — no signature is checked at all.
4. `Shipit::Webhooks.for_event('push')` dispatches to `PushHandler`, which resolves `stacks` via `Repository.from_github_repo_name("secured-org/production-repo")` — a repository never associated with the unauthenticated `legacy-org` credential — and calls `stack.sync_github(expected_head_sha: ...)` on it, all without ever validating a signature tied to `secured-org`.

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

**File:** config/secrets.development.shopify.yml (L6-14)
```yaml
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
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
