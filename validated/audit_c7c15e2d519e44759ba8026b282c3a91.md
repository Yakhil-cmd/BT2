### Title
Cross-organization webhook secret confusion allows forging repository events for stacks in other GitHub organizations - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
When Shipit is configured with multiple GitHub Apps (one per organization, per `docs/setup.md` "Using Multiple Github Applications"), `WebhooksController#verify_signature` selects which organization's `webhook_secret` to validate the HMAC signature against by reading `repository.owner.login` (or `organization.login`) straight out of the *unauthenticated* JSON body. The handlers that actually mutate state, however, resolve the target repository/stack using a *different* field of the same body: `repository.full_name`. Nothing ties these two fields together, so a valid signature computed with Organization A's secret can be attached to a payload whose `repository.full_name` points at a repository belonging to Organization B.

### Finding Description
`WebhooksController#verify_signature` picks the verification key like this: [1](#0-0) [2](#0-1) 

`repository_owner` is read directly from the still-unverified `params` hash (`params.dig('repository', 'owner', 'login')`), and is used only to look up which `GitHubApp` (and thus which `webhook_secret`) should validate the signature via `Shipit.github(organization: repository_owner)` → `GitHubApp#verify_webhook_signature`: [3](#0-2) 

Each organization has its own independent secret when Shipit is configured for multiple GitHub orgs: [4](#0-3) 

Once the signature check passes, the request is dispatched to handlers via `Shipit::Webhooks.for_event(event)`, and every repository-scoped handler resolves its target stack/repository from a *completely different* field, `repository.full_name`, not `repository.owner.login`: [5](#0-4) [6](#0-5) 

The same pattern repeats in the pull-request handlers, which independently derive `repository` from `params.repository.full_name` (e.g. `OpenedHandler`, `ClosedHandler`, `LabelCapturingHandler`, `UnlabeledHandler`), never cross-checking it against `repository.owner.login`.

Broken binding (as an equality that should hold but doesn't):
`organization used to select the verifying secret (repository.owner.login)` == `organization/repository actually acted upon (repository.full_name)`.

**Attack scenario:** In a multi-organization Shipit deployment, an attacker who legitimately controls (or is an admin/owner of) GitHub Organization A knows Organization A's `webhook_secret` (they configured that GitHub App, or can read it from their own org's App settings — this is a normal, unprivileged capability with respect to Organization B). They then POST directly to Shipit's `/github/webhooks` endpoint (bypassing GitHub entirely — nothing requires the request to originate from GitHub's servers) with:
- `X-Github-Event: push` (or `pull_request`, etc.)
- `repository.owner.login` (or top-level `organization.login`) = `"org-a"` — so `verify_signature` fetches Org A's secret
- `X-Hub-Signature` = HMAC-SHA1 of the raw body computed with Org A's real secret (which the attacker legitimately possesses)
- `repository.full_name` = `"org-b/victim-repo"` — a repository/stack that belongs to an entirely different organization (Org B) that Shipit also serves, which the attacker has no rights to

`verify_signature` succeeds (the signature genuinely matches Org A's secret over the exact bytes sent), and `PushHandler` (or another handler) then looks up and mutates the stack belonging to `org-b/victim-repo` — a stack outside the attacker's actual organization.

### Impact Explanation
This breaks the "organization that authenticated versus the repository that is written" trust boundary explicitly called out as in-scope. Depending on the handler exercised, the attacker can:
- Force `PushHandler` to trigger `GithubSyncJob`/`stack.sync_github` against a victim stack in another org, at will and with a spoofed `after` SHA.
- Manipulate pull-request-driven review-stack lifecycle (archive/unarchive, provisioning) for repositories belonging to organizations they have no access to (`OpenedHandler`, `ClosedHandler`, `ReopenedHandler`, `UnlabeledHandler`), causing unauthorized creation/archival/deprovisioning of review stacks — an unauthorized state change/deploy-adjacent action on a repository the attacker does not control, satisfying "cross-repository writes" against a resource outside the attacker's authorization boundary.

This qualifies as a valid analog under the report's "organization that authenticated versus the repository that is written" binding-break criterion, at minimum reaching the High-severity bar (unauthorized cross-repository state mutation via a credential that should only authorize actions against the attacker's own organization).

### Likelihood Explanation
Requires a multi-organization Shipit deployment (explicitly documented and supported configuration) and requires the attacker to possess a legitimate `webhook_secret` for at least one of the configured organizations — a realistic scenario for any customer/tenant onboarded into a shared Shipit instance who is untrusted with respect to other tenants' repositories. No GitHub session, `ApiClient` token, or Shipit account is required; the request is sent directly to the webhook endpoint.

### Recommendation
After resolving the target repository/stack from the payload, verify that `repository.full_name`'s owner matches the `repository_owner` (or `organization.login`) value that was used to select the verifying secret, and reject the request if they differ. Alternatively, derive the webhook secret from the resolved `Repository`/`Stack` record's known owning organization rather than from attacker-controlled payload fields before performing any signature comparison.

### Proof of Concept
1. Configure Shipit with two GitHub organizations, `org-a` and `org-b`, each with its own `webhook_secret` (per `docs/setup.md`, "Using Multiple Github Applications").
2. As an attacker who knows `org-a`'s `webhook_secret` (e.g., an admin of Org A's own GitHub App installation), craft a `push` payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "org-a" },
    "full_name": "org-b/victim-repo"
  }
}
```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(org-a secret, raw_body)>`.
4. `POST` this body with `X-Github-Event: push` to the Shipit webhooks endpoint.
5. `WebhooksController#verify_signature` resolves the secret via `repository_owner` = `"org-a"`, validates successfully.
6. `PushHandler#process` resolves the stack via `Repository.from_github_repo_name("org-b/victim-repo")` and triggers `stack.sync_github(expected_head_sha: "<attacker-chosen sha>")` on a stack that belongs to `org-b`, which the attacker does not control.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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
