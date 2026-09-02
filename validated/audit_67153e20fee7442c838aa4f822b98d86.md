### Title
Webhook signature is verified against the organization named in the unauthenticated payload, not the repository the event actually writes to - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate the HMAC against using a field (`repository.owner.login` / `organization.login`) taken from the very payload whose signature is being checked, while the event handlers that subsequently act on the request use a *different* field (`repository.full_name`) to select the `Repository`/`Stack` that gets mutated. Because Shipit supports multiple independently-configured GitHub Apps/organizations (each with its own `webhook_secret`), nothing enforces that the organization whose secret validated the signature is the same organization that owns the repository the handlers operate on.

### Finding Description
`verify_signature` computes the authenticating organization purely from the request body: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` looks up a **per-organization** config/secret when Shipit is set up for multiple GitHub organizations (documented feature): [3](#0-2) 

Each organization can have its own `webhook_secret`, independently configured (e.g. by that organization's own GitHub App owner): [4](#0-3) 

After signature verification passes, `create` re-parses the raw body and dispatches to handlers, which locate the target `Repository`/`Stack` using `repository.full_name` — a completely separate field from the one used to select the signing organization: [5](#0-4) [6](#0-5) [7](#0-6) 

Nothing in `Repository.from_github_repo_name` or the handlers cross-checks that `full_name`'s owner segment matches the `repository_owner` value that was used to pick the webhook secret. Concretely: an attacker who legitimately administers (and thus knows the `webhook_secret` for) GitHub organization `A` configured in the same Shipit instance can craft a payload with `"repository": {"owner": {"login": "A"}, "full_name": "B/victim-repo"}`. `verify_signature` will fetch `Shipit.github(organization: "A")` and validate the HMAC with secret `A` — which succeeds, because the attacker signed the exact raw body with the secret they know. The handler (e.g. `PushHandler`, `StatusHandler`, pull-request handlers) then resolves the target using `repository.full_name` = `"B/victim-repo"`, an organization the attacker does not control and whose secret they never had.

This is the same class of bug as the referenced report: a value is used to authorize/select a trust boundary (there: the effective price scale; here: which organization's secret authenticates the request), while a *different* value drives the actual effect (there: the final price returned to `Controller.sol`; here: the repository/stack actually mutated). The binding `organization_that_authenticated == repository_that_is_written` is never enforced.

### Impact Explanation
This allows cross-organization forgery of GitHub webhook events in any Shipit deployment configured with `Shipit.github` for multiple organizations (a documented, supported configuration). An attacker who is a legitimate (but low-privilege from Shipit's perspective) admin/owner of one configured GitHub App/organization can:
- Force a `push` sync (`PushHandler` → `Stack#sync_github`) against another organization's stack.
- Inject fabricated commit statuses (`StatusHandler` → `Commit#create_status_from_github!`) for another organization's commits, which can gate CI/deploy/merge decisions.
- Trigger pull-request/review-stack side effects (open/close/label/merge-related handlers) against repositories in another organization.

This is a cross-repository/cross-organization write achieved by breaking the authentication binding between the signing organization and the acted-upon repository, matching the report's "Critical: cross-repository writes / unauthorized deploy/rollback/merge" category.

### Likelihood Explanation
Requires the attacker to control the webhook_secret of *some* organization configured in the same multi-tenant Shipit instance (documented as a supported configuration in `docs/setup.md`), which is plausible in any Shipit deployment shared across multiple orgs/teams where each org's App owner sets their own secret. No GitHub App private key, `api_clients_secret`, or Shipit session is required — only knowledge of one configured org's `webhook_secret`, which by design is set/known independently per organization.

### Recommendation
Bind the two fields together: after successfully verifying the signature for `organization = repository_owner`, require that `repository.full_name`'s owner segment (and/or `Repository#owner`) matches `repository_owner` before dispatching to handlers, rejecting (422) any mismatch. Alternatively, resolve the target `Repository`/`Stack` first and verify the signature using the secret associated with that resolved repository's organization, not a value read independently from the unauthenticated payload.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` and `OrgB`, each with its own `webhook_secret` (as in `test/dummy/config/secrets_double_github_app.yml`).
2. As the operator/owner of `OrgA`'s GitHub App (who knows `webhook_secret_A`), craft a `push` payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker chosen sha>",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/victim-repo"
  }
}
```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(webhook_secret_A, raw_body)>`.
4. POST to `/webhooks` with header `X-Github-Event: push`.
5. `verify_signature` calls `Shipit.github(organization: "OrgA")` and successfully validates the signature against `webhook_secret_A`.
6. `Shipit::Webhooks::Handlers::PushHandler` resolves `Repository.from_github_repo_name("OrgB/victim-repo")` and calls `stack.sync_github(expected_head_sha: ...)` on `OrgB`'s stack, even though the request was never signed by `OrgB`'s secret. [8](#0-7)

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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-7)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-27)
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

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
    end
  end
end
```
