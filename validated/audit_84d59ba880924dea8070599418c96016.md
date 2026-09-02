### Title
Cross-organization commit-status forgery via `repository.owner.login` / `repository.full_name` divergence in webhook signature check - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects the HMAC secret used to validate an inbound webhook based on `repository.owner.login` (falling back to `organization.login`) extracted from the JSON payload, while every `Webhooks::Handlers::Handler` subclass resolves the target `Stack`/`Repository` to act on using the independent `repository.full_name` field. Because these are two separate JSON keys inside the same signed body, a party who legitimately controls (and thus knows the webhook secret of) *any* one GitHub organization configured on a shared multi-org Shipit instance can construct a payload where `repository.owner.login` matches their own org (so signature verification passes with their own secret) while `repository.full_name` names a repository belonging to a *different* tracked organization, causing the handler to act on that other stack.

### Finding Description
Signature check: [1](#0-0) [2](#0-1) 

selects the `GitHubApp` (and its `webhook_secret`) with `Shipit.github(organization: repository_owner)`, where `repository_owner` comes from `params.dig('repository', 'owner', 'login')`. In a multi-organization deployment, each org is configured with its own independent `webhook_secret`: [3](#0-2) 

Every event handler, however, resolves the acted-upon repository purely from `repository.full_name`, ignoring `repository.owner.login` entirely: [4](#0-3) 
which is looked up via a naive owner/name split with no cross-check against the field used for signature routing: [5](#0-4) 

Because the HMAC in `verify_webhook_signature` covers the raw request body as a whole, the check only proves the payload was signed with *some* configured org's secret — not that the `owner.login` value used to pick that secret is consistent with the `full_name` value the handler will act on: [6](#0-5) 

This breaks the intended binding: **organization authenticated (`repository.owner.login` → selected `webhook_secret`) must equal organization whose repository is written (`repository.full_name` → `Stack`/`Repository` acted upon)**. An attacker who legitimately administers Org A's GitHub App on the same shared Shipit instance (and thus can freely craft and sign arbitrary payloads with Org A's secret, e.g., by pointing their own org's webhook delivery settings at the shared endpoint, or replaying/crafting a delivery) can forge a `status` event with `repository.owner.login: "org-a"` and `repository.full_name: "org-b/victim-repo"`. Verification succeeds using Org A's secret, then `StatusHandler` looks up `Commit.where(sha: ...)` scoped only by SHA (no repository filtering at all) and calls `create_status_from_github!`: [7](#0-6) 

This lets the attacker inject a forged "success" commit status for a commit belonging to Org B's stack (`Commit` records are not repository-scoped in the query), which can influence deploy-gating logic (`deployable_status`) despite the attacker having no relationship to Org B's repository at all — an authorization boundary crossing an unprivileged/foreign-org actor should not be able to cross.

### Impact Explanation
This allows escalation into unauthorized manipulation of deploy-gating state (forged commit statuses) for a stack the attacker has no legitimate access to, by exploiting a shared multi-tenant Shipit deployment's webhook endpoint. This matches the "High" impact bucket: escalation into repository/organization authorization boundaries and unauthenticated influence over task/deploy-gating state for a stack the caller was never authorized against.

### Likelihood Explanation
Requires: (1) the Shipit instance be configured with the multi-org `github:` secrets schema (documented feature, `docs/setup.md`), and (2) the attacker legitimately control at least one of the configured GitHub organizations/apps (so they know that org's `webhook_secret`) and target another org's repo tracked on the same instance. This is a realistic scenario for shared/hosted Shipit deployments serving multiple orgs, and requires no repository write access or Shipit session — only knowledge of one configured org's webhook secret, which the org's own admins possess by design.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler#repository_name`), enforce that the organization used to select the verification secret is the same organization whose repository is being acted upon: after verifying, re-derive the owner from `repository.full_name` (or vice versa) and reject (422) if they don't match case-insensitively. Additionally, scope `StatusHandler`'s `Commit` lookup by the resolved `Repository`/`Stack` rather than by bare SHA to avoid cross-repository status bleed even if the identity check were bypassed.

### Proof of Concept
1. Configure Shipit with two orgs, `org-a` and `org-b`, each with a distinct `webhook_secret` (per `docs/setup.md`'s "Using Multiple Github Applications" section).
2. As an administrator of `org-a`'s GitHub App (attacker), compute a valid `X-Hub-Signature` over a crafted JSON body using `org-a`'s known webhook secret:
```json
{
  "repository": { "owner": { "login": "org-a" }, "full_name": "org-b/victim-repo" },
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/tests"
}
```
3. POST to `/webhooks` with header `X-Github-Event: status` and the computed signature.
4. `verify_signature` calls `Shipit.github(organization: "org-a")` and validates successfully with `org-a`'s secret.
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` — matching the victim commit belonging to `org-b`'s stack — and creates a forged successful status, independent of the fact the signature was never verified against `org-b`'s secret.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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
