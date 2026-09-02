### Title
Webhook status/commit-status injection is not bound to the signing organization/repository - forged CI status can unblock deploys in another tenant's stack - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`Shipit.github(organization:)` supports multi-tenant configs, each with its own `webhook_secret`, and `WebhooksController#verify_signature` authenticates a webhook only against the `webhook_secret` belonging to the organization named in the payload's `repository.owner.login` / `organization.login` field. [1](#0-0) [2](#0-1) 
Once the signature is accepted, `StatusHandler#process` looks up commits **globally by `sha` alone**, with no scoping to the repository/organization that produced the signature, and writes a GitHub status onto every matching commit. [3](#0-2) 

### Finding Description
The equality that should hold is: **organization that authenticated == repository whose commits are written**. That binding is broken here:

- The webhook signature is verified using the secret for `repository_owner`, which is read straight out of the still-unauthenticated JSON body (`params.dig('repository','owner','login') || params.dig('organization','login')`). [4](#0-3) 
- `Shipit::Webhooks::Handlers::Handler` (the base class most handlers use) does scope by `repository.full_name`, but `StatusHandler` does not inherit that scoping — it queries `Commit.where(sha: params.sha)` across the **entire database**, independent of which organization's secret validated the request. [5](#0-4) [6](#0-5) 

Because sha values are effectively global identifiers with no cryptographic tie to a specific repository or GitHub App installation, an attacker who legitimately owns/administers *any* organization onboarded to this multi-tenant Shipit instance (and therefore knows that organization's `webhook_secret`, which they are handed when installing their own GitHub App) can:

1. Compute a valid `X-Hub-Signature` over an arbitrary `status` payload using their own organization's `webhook_secret`.
2. Set `repository.owner.login` to their own org (so `verify_signature` authenticates successfully against their own secret).
3. Set `sha` to the commit SHA of a target commit belonging to a *different*, victim stack/repository tracked by the same Shipit instance, and set `state: "success"`.

`StatusHandler` will happily attach that forged, "verified" status to the victim commit, since it never checks that the commit's owning repository matches the authenticating organization.

### Impact Explanation
Shipit ships with pluggable deployment safety checks (`Shipit.deployment_checks`) and undeployed-commit / CI status gating (`app/models/shipit/undeployed_commit.rb`, `app/models/shipit/status.rb`) that decide whether a commit is "deployable" based on the aggregated GitHub commit statuses recorded via this exact webhook path. By injecting a fabricated "success" status for a commit in a stack the attacker has no legitimate access to, the attacker can make that commit appear to have passing CI/checks, satisfying deploy-safety gating and enabling an **unauthorized deploy** of a commit that never actually passed its real checks — this crosses the "unauthorized deploy" impact bucket explicitly called out as in-scope.

### Likelihood Explanation
The only prerequisite is administrative control of one legitimate, low-privilege GitHub organization/App installation already onboarded to the shared Shipit instance (a realistic scenario for any Shipit deployment serving multiple orgs/teams, which the engine explicitly supports via `github_organizations`/`github_app_config`). No access to the victim's secret, the app's GITHUB_TOKEN, or any Shipit session/API token is required — only the attacker's own, already-possessed webhook secret. This is a purely unprivileged-attacker path relative to the victim stack.

### Recommendation
Scope `StatusHandler#process` (and any other handler that doesn't already inherit `Handler#stacks`) to the commit's own repository, and additionally verify that the repository/organization named in the payload matches the repository/organization whose secret authenticated the request (e.g., re-check `commit.stack.repository.owner == repository_owner` before writing the status), rather than trusting a global `sha` lookup once any valid signature — from any tenant — has been observed.

### Proof of Concept
1. Attacker administers `org-attacker`, onboarded to the shared Shipit instance with `webhook_secret = S_attacker` (`lib/shipit.rb#github_app_config`).
2. Victim stack `org-victim/prod-repo` has an undeployed commit with `sha = deadbeef...`.
3. Attacker POSTs to `/webhooks` with header `X-Github-Event: status`, body:
```json
{
  "sha": "deadbeef...",
  "state": "success",
  "context": "ci/tests",
  "repository": { "owner": { "login": "org-attacker" } }
}
```
signed with `X-Hub-Signature: sha1=HMAC(S_attacker, body)`.
4. `WebhooksController#verify_signature` resolves `Shipit.github(organization: "org-attacker")` and successfully verifies the signature against `S_attacker` (`app/controllers/shipit/webhooks_controller.rb:24-30`, `lib/shipit/github_app.rb#verify_webhook_signature`).
5. `StatusHandler#process` runs `Commit.where(sha: "deadbeef...")`, finds the victim's commit (owned by `org-victim`), and calls `commit.create_status_from_github!(params)`, recording a fabricated "success" status on it (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`).
6. The victim stack's deploy-safety/undeployed-commit checks now see a passing status for that commit, potentially allowing it to be deployed even though the real CI for `org-victim/prod-repo` never ran or failed.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-24)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
