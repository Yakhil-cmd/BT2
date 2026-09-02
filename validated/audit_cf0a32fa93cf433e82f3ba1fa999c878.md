### Title
Webhook signature authenticates the payload's `repository.owner.login` organization while the `PushHandler`/`StatusHandler` act on the independent `repository.full_name` field, allowing cross-repository writes - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub organization's `webhook_secret` validates an inbound webhook's HMAC based on `repository.owner.login` (falling back to `organization.login`), but the handlers that actually mutate state (`PushHandler`, `StatusHandler`, etc.) resolve the target `Repository`/`Stack` from the independent `repository.full_name` field via `Handler#repository_name`. Multi-tenant Shipit installs configure one `webhook_secret` per organization (`Shipit.github_app_config`), so any organization onboarded onto the instance can craft a payload whose `repository.owner.login` names their own organization (so the HMAC check passes using their own known secret) while `repository.full_name` names a stack belonging to a *different* onboarded organization, causing writes (deploy sync, commit statuses) against a repository they do not own.

### Finding Description
`verify_signature` computes the authenticating identity from a field of the untrusted request body itself: [1](#0-0) [2](#0-1) 

The HMAC itself is verified over the whole `raw_post`, so an outside attacker without any org's `webhook_secret` cannot forge a payload — that part is sound. But Shipit supports **per-organization** webhook secrets in a single install (`Shipit.github_app_config(organization)`), each organization's admin necessarily knows/possesses their own org's `webhook_secret` because they configure the GitHub App/webhook for their own organization: [3](#0-2) 

`verify_signature` binds the HMAC check to `repository.owner.login`/`organization.login`, i.e. "which organization authenticated". The downstream handlers never re-derive the acted-upon repository from that same authenticated value; instead they use a second, independently-controlled field of the same JSON body: [4](#0-3) [5](#0-4) 

`Repository.from_github_repo_name` simply splits `owner/name` off `full_name` and looks up any repository/stack in the whole install by that literal string — it performs no cross-check against the organization whose secret validated the request: [6](#0-5) 

So the equality that should hold is:
`organization that authenticated the webhook (repository.owner.login used in verify_signature)` == `organization of the repository that is actually written to (repository.full_name used in Handler#repository_name / Repository.from_github_repo_name)`.

Before the attack: for a legitimate webhook, both fields describe the same repository, so the equality holds.
After the attack: OrgA (a legitimate, low-privilege tenant of the Shipit install who owns and knows their own `webhook_secret`) sends `POST /github/webhooks` with `X-Github-Event: push`, a valid `X-Hub-Signature` computed with OrgA's own secret, `repository.owner.login = "orga"` (so `Shipit.github(organization: "orga")` verifies it), but `repository.full_name = "orgb/some-stack"`. `verify_signature` passes because it used OrgA's own correctly-known secret. `PushHandler#stacks` then resolves `Repository.from_github_repo_name("orgb/some-stack")`, finds OrgB's `Stack`, and calls `stack.sync_github(expected_head_sha: params.after)`, which is a cross-tenant, cross-organization action OrgA had no authorization to trigger. The same confusion applies to `StatusHandler`, which matches purely on `sha` across all commits in the install with no organization scoping at all: [7](#0-6) 

This is the direct structural analogue of the reported bug class: a privileged-but-scoped actor (the `owner`/here, "the organization whose secret validated the request") is able to act outside the boundary it should be confined to (its own repositories) because the code never asserts that the entity that authenticated equals the entity that is written to — exactly as the original report's missing `assert_ne!(operator_account, self.owner, ...)`/ownership check.

### Impact Explanation
This breaks the `organization that authenticated` == `repository that is written` binding, enabling one onboarded organization to force out-of-band GitHub sync/deploy pipeline actions (`stack.sync_github`) and inject fabricated commit statuses (`StatusHandler`) against another organization's stacks on the same multi-tenant Shipit install — a cross-repository write, matching the "Critical" impact bucket (cross-repository writes / unauthorized deploy pipeline action) defined in scope.

### Likelihood Explanation
Requires only that the attacking organization be one of the tenants configured on a multi-org Shipit installation (a normal, unprivileged position relative to other tenants) — it does not require compromising anyone else's secret, GitHub App key, or a Shipit session/API token. This is a realistic precondition for any Shipit instance serving multiple GitHub organizations, though single-org deployments (the common/simple config path where `github_default_organization` is `nil`) are not affected since there is then only one webhook secret and `repository_owner` resolution is a no-op distinction.

### Recommendation
In `Handler#repository_name`/`Handler#initialize`, thread through the organization that was used to authenticate the webhook (as resolved in `WebhooksController#repository_owner`) and assert that it matches the owner segment of `repository.full_name` (and, for `StatusHandler`, scope the `Commit.where(sha:)` lookup to stacks belonging to that authenticated organization) before performing any lookup or mutation — mirroring the fix pattern from the reported bug, i.e. add an explicit equality/ownership assertion rather than trusting an unrelated field of the same payload.

### Proof of Concept
1. Configure a multi-org Shipit install with two tenants, `orga` and `orgb`, each with their own `github.orga.webhook_secret` / `github.orgb.webhook_secret`, per `lib/shipit.rb` `github_app_config`.
2. As an admin/owner of OrgA (who legitimately knows `orga`'s `webhook_secret` because they configured OrgA's GitHub App/webhook), build a JSON body:
   ```json
   {"ref":"refs/heads/master","after":"<attacker-chosen sha>","repository":{"owner":{"login":"orga"},"full_name":"orgb/target-stack"}}
   ```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(orga_webhook_secret, body)>` and send `POST /github/webhooks` with `X-Github-Event: push`.
4. `verify_signature` calls `Shipit.github(organization: "orga")` (from `repository.owner.login`), verifies successfully with OrgA's own secret.
5. `PushHandler` (via `Handler#repository_name`) resolves `repository.full_name = "orgb/target-stack"`, finds OrgB's `Stack`, and invokes `stack.sync_github(expected_head_sha: ...)` — an action on OrgB's stack triggered solely using OrgA's credentials, with no cross-check performed anywhere in `app/controllers/shipit/webhooks_controller.rb` or `app/models/shipit/webhooks/handlers/handler.rb`.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
