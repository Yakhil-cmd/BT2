Confirmed: `test/dummy/config/secrets_double_github_app.yml` demonstrates multi-organization GitHub App configuration is a first-class, supported feature (`Shipit.github(organization: ...)` looks up per-org config via `github_app_config`). This confirms the exploit scenario is realistic for this engine.

### Title
Webhook signature is verified against the organization named in an attacker-controlled payload field, while the target repository/stack is resolved from a different, independently-forgeable field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In multi-organization deployments, `Shipit::WebhooksController#verify_signature` selects which GitHub App configuration (and thus which `webhook_secret`) to validate the request against using `repository_owner`, a value read directly out of the unauthenticated JSON body. The stack/repository actually mutated by the event handlers is resolved from a *different* JSON field, `repository.full_name`. Nothing ties these two fields together, so an attacker can pick an organization whose GitHub App has no `webhook_secret` configured (making signature verification a no-op) while pointing the actual repository at a target belonging to a completely different, properly-secured organization.

### Finding Description
`verify_signature` picks the GitHub App/secret to check against based on the claimed owner: [1](#0-0) [2](#0-1) 

That resolves an org-specific `GitHubApp` via `Shipit.github(organization:)`, which in multi-tenant mode looks up per-organization secrets: [3](#0-2) 

Crucially, if that organization's config has no `webhook_secret` set (documented as optional in `docs/setup.md`), signature checking is skipped entirely and the request is treated as verified: [4](#0-3) 

Once "verified," `WebhooksController#create` dispatches the *entire raw payload* to handlers: [5](#0-4) 

But the handlers resolve which `Repository`/`Stack` to act on using a *different* payload field, `repository.full_name`, not `repository.owner.login`: [6](#0-5) 

For example, `PushHandler` uses that repository resolution to trigger `stack.sync_github(expected_head_sha:)` against whatever stacks match: [7](#0-6) 

Since `repository.owner.login` (used only to pick which secret to check) and `repository.full_name` (used to pick which actual repository/stack is written to) are two independent strings inside the same attacker-supplied JSON body, there is no requirement that they agree. GitHub itself always sends consistent values, but this is an unauthenticated HTTP endpoint (`skip_before_action :verify_authenticity_token`), so nothing stops a forged request from setting them independently. Multi-organization GitHub App configuration is a supported, tested feature of this engine (`test/dummy/config/secrets_double_github_app.yml`, `test/unit/shipit_test.rb:11-22`), so it's realistic for one organization in the fleet to have no `webhook_secret` configured (per the docs, it is explicitly optional) while other organizations' repositories/stacks are the real deploy targets.

This is exactly the "organization that authenticated vs. repository that is written" binding break: the equality `verified_organization == acted_upon_repository_owner` is never enforced, only assumed.

### Impact Explanation
An unauthenticated network attacker who knows (or guesses) the name of any organization configured in the Shipit instance's `github` secrets that has no `webhook_secret` set can send a forged webhook (`push`, `status`, `check_suite`, `pull_request`, `membership`, etc.) with `repository.owner.login` set to that unsecured organization but `repository.full_name` pointing at any other organization's real repository/stack tracked by the instance. This lets the attacker:
- Force `GithubSyncJob`/`sync_github` to run against a target stack (`PushHandler`).
- Post forged CI/commit statuses affecting deployability gating (`StatusHandler`, `CheckSuiteHandler`).
- Manipulate pull-request/merge-queue state for a target repository (`PullRequest::*Handler`).
- Create/delete team memberships (`MembershipHandler`), influencing `Shipit.github_teams` authorization.

This crosses a repository boundary without any credential for the target organization, satisfying the "cross-repository writes" / "escalation into `Shipit.github_teams` authorization" High/Critical impact bar.

### Likelihood Explanation
Requires: (1) the Shipit instance to be configured for more than one GitHub organization (a supported, documented, tested configuration), and (2) at least one configured organization lacking a `webhook_secret` (explicitly documented as optional). Given that setup, exploitation requires only a single unauthenticated HTTP POST to the public `/webhooks` endpoint — no session, token, or GitHub write access is needed.

### Recommendation
Cryptographically bind signature verification to the exact repository/organization that handlers will act on: derive the verifying organization/secret from the same field(s) used for stack resolution (`repository.full_name`), or, after verification, re-check that `repository.owner.login` used to pick the secret equals the owner segment of `repository.full_name` before invoking handlers. Additionally, consider making `webhook_secret` mandatory for every configured organization so an unsecured org cannot exist alongside secured ones.

### Proof of Concept
1. Configure Shipit with two organizations, e.g. `secrets.github: { OrgA: { ..., webhook_secret: nil }, OrgB: { ..., webhook_secret: "s3cret" } }`, and a tracked stack for `OrgB/target-repo`.
2. As an anonymous attacker, POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/target-repo"
  }
}
```
No `X-Hub-Signature` header (or any arbitrary value) is required, since `repository_owner` resolves to `OrgA`, whose `webhook_secret` is `nil`, causing `verify_webhook_signature` at `lib/shipit/github_app.rb:76-83` to return `true` unconditionally.
3. `WebhooksController#create` dispatches the payload to `PushHandler`, which resolves `repository.full_name` = `"OrgB/target-repo"` and triggers `sync_github` against `OrgB`'s real, secured stack — despite the request never being validated against `OrgB`'s secret.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
