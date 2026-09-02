### Title
Cross-Organization Webhook Signature Bypass via Unbound `repository.owner.login` Selection — ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In multi-tenant GitHub App configurations, the field used to select which organization's secret verifies a webhook's HMAC signature (`repository.owner.login`) is not the same field used by event handlers to resolve the target repository/stack (`repository.full_name`). Because per-organization `webhook_secret` is optional, and any organization configured with no secret trivially "verifies" *any* signature, an attacker can forge a payload whose `owner.login` points at an unsecured/unknown-to-attacker-but-configured org while `repository.full_name` points at a different, secured org's tracked repository — bypassing signature verification for that secured org's data.

### Finding Description
`WebhooksController#verify_signature` selects the GitHub App configuration purely from the attacker-controlled JSON body: [1](#0-0) [2](#0-1) 

`repository_owner` is read from `params.dig('repository', 'owner', 'login')` (or `organization.login`), and `Shipit.github(organization: repository_owner)` looks up that org's config via `github_app_config`: [3](#0-2) 

`GitHubApp#verify_webhook_signature` short-circuits to `true` whenever that org has no `webhook_secret` configured: [4](#0-3) 

Meanwhile, every event `Handler` (e.g. `PushHandler`, pull-request handlers) resolves the actual target repository/stack from a **different** field in the same body, `repository.full_name`, via `Repository.from_github_repo_name`: [5](#0-4) [6](#0-5) [7](#0-6) 

The controller acts on the raw JSON body without cross-checking that `repository.owner.login` (used to pick the verifying secret) actually matches the owner segment of `repository.full_name` (used to pick the affected stack): [8](#0-7) 

This breaks the trust binding: `organization authenticated (repository.owner.login) == organization whose repository is written (repository.full_name)`. In the multi-org config schema (`config/secrets.development.shopify.yml` style, one entry per org under `github:`), an operator can legitimately configure some orgs without a `webhook_secret` (it's documented as optional: "If you've set a webhook secret during the App creation, you should copy it here" — implying it can be blank) while other orgs, tracking sensitive repos, do have one configured: [9](#0-8) 

### Impact Explanation
An unprivileged external attacker (no Shipit session, no `webhook_secret` for the target org) who knows the name of an organization configured in the same Shipit instance without a webhook secret can craft a fabricated GitHub webhook body with `repository.owner.login` set to that unsecured org and `repository.full_name` set to `"SecuredOrg/tracked-repo"`. The signature check passes unconditionally (`return true unless webhook_secret`), and the `PushHandler` will then process this as if it came from GitHub for `SecuredOrg/tracked-repo`, enqueuing `GithubSyncJob` with an attacker-chosen `expected_head_sha`/`after` value for that stack: [10](#0-9) 

Depending on the sync/deploy pipeline behavior downstream, this can drive an unauthorized sync of arbitrary commit SHAs into a protected stack's tracked state — a cross-organization write triggered without possessing that organization's webhook secret.

### Likelihood Explanation
Requires the deployment to use the multi-organization GitHub App config schema with at least one organization lacking a `webhook_secret` (an explicitly supported, documented configuration) and knowledge of another org's name/repo hosted on the same Shipit instance — both discoverable via the public webhook endpoint's error behavior (`GithubOrganizationUnknown` vs. signature failure responses differ, `422` in both cases, but only unconfigured orgs return no distinguishing signal without secret; determining which orgs lack secrets may require reconnaissance). This is a plausible but not universal deployment pattern, so likelihood is medium.

### Recommendation
Verify that `repository.owner.login`/`organization.login` (used to select the verification secret) matches the owner segment parsed from `repository.full_name` (used by handlers) before dispatching to handlers, and/or require every configured organization to have a non-blank `webhook_secret`, removing the `return true unless webhook_secret` bypass in `GitHubApp#verify_webhook_signature`.

### Proof of Concept
1. Configure Shipit with two orgs: `secured-org` (has `webhook_secret` set, tracks a real repository/stack) and `open-org` (no `webhook_secret` configured).
2. POST to `/github/webhooks` with header `X-Github-Event: push`, no valid `X-Hub-Signature` (or an arbitrary bogus one), and body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": { "owner": { "login": "open-org" }, "full_name": "secured-org/tracked-repo" }
}
```
3. `verify_signature` resolves `Shipit.github(organization: "open-org")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` regardless of the (missing/bogus) signature.
4. `PushHandler#process` resolves the target stack via `Repository.from_github_repo_name("secured-org/tracked-repo")` and enqueues `GithubSyncJob` for that stack with the attacker-supplied `expected_head_sha`, despite never presenting a valid signature for `secured-org`.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** docs/setup.md (L117-121)
```markdown
**`github.bot_login`** The login of the App [bot] user. Every GitHub App have an associated `[bot]` user which acts as the author of the App actions through the API, for example when an App merges a Pull Request. It should be the App "slug" with the suffix `[bot]`. For example if your app settings URL is `https://github.com/organizations/ACME/settings/apps/acme-shipit/installations`, the bot user should be `acme-shipit[bot]`. If you are unsure, you can leave it empty.

**`github.webhook_secret`** If you've set a webhook secret during the App creating, you should copy it here.

**`github.private_key`** In your GitHub App settings, on the `General` section, you can generate and download a private key. You will end up with a `.pem` file and you need to copy it's content here.
```
