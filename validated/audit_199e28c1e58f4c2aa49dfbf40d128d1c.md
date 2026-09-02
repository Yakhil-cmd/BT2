### Title
Cross-organization commit-status and repository write via webhook signature verification decoupled from acted-upon repository - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/status_handler.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App secret to validate a webhook against using the `repository.owner.login` (or `organization.login`) field of the untrusted JSON body, but the handlers that actually act on data (`StatusHandler`, and `Handler#repository_name`/`#stacks` used by `PushHandler`, `PullRequest::ClosedHandler`, etc.) use a *different* field (`sha` with no repository scoping at all, or `repository.full_name`) to decide what to write to. Nothing ties the organization whose secret validated the signature to the repository/commit actually mutated, breaking the binding: `organization that authenticated == repository/commit that is written`.

### Finding Description
`verify_signature` picks the `GitHubApp` (and therefore the `webhook_secret` used for HMAC verification) purely from the payload itself: [1](#0-0) [2](#0-1) 

This is standard in Shipit's documented multi-tenant configuration, where distinct organizations each have their own `app_id`/`webhook_secret` under `secrets.github`: [3](#0-2) 

Once the signature is accepted (because it validates against *some* organization's own legitimate secret), `Shipit::Webhooks.for_event(event)` dispatches handlers with the raw, attacker-controlled payload: [4](#0-3) 

The handlers do not re-check that the data they act on belongs to the organization that produced the valid signature:
- `Handler#repository_name`/`#stacks` resolve the target purely from `payload.dig('repository', 'full_name')`, a field independent of `repository.owner.login`/`organization.login` used for signature routing: [5](#0-4) 
- `StatusHandler` is even less scoped: it looks up commits **engine-wide** by `sha` with no repository/organization filter at all, then writes a status onto whatever commit matches: [6](#0-5) 

Root cause equality that should hold but doesn't:
`organization_used_to_select_webhook_secret (repository.owner.login) == organization_owning_the_repository/commit_actually_mutated (repository.full_name / sha's owner)`

Before the attack: for genuine GitHub traffic these two are always the same repository/organization, because GitHub always signs and sends a self-consistent payload for one repository.

After the attack: any tenant of a multi-org Shipit deployment (holder of their *own*, legitimately-issued `webhook_secret`) can sign an arbitrary JSON body with their own secret while setting `repository.owner.login`/`organization.login` to their own org (so `verify_signature` picks their own, correctly-validating secret) and setting `repository.full_name` or `sha` to reference a stack/commit belonging to a completely unrelated organization also hosted on the same instance. `verify_signature` passes, and the handler then mutates the unrelated organization's data.

### Impact Explanation
This breaks the deployment-trust binding between "the organization whose credential authenticated the request" and "the repository actually written to," resulting in cross-repository/cross-organization writes:
- `StatusHandler` lets a tenant forge a passing/failing CI status on any commit in the system, including commits belonging to organizations they have no GitHub-side authority over, potentially manipulating deploy-gating logic for those other stacks (`Commit#create_status_from_github!`).
- `Handler#stacks`/`#repository_name` let a tenant trigger `GithubSyncJob`s, PR-close side effects (`review_stack.archive!`), and related stack mutations on stacks owned by other organizations, simply by putting a different `repository.full_name` in a self-signed payload.

This matches the "cross-repository writes" / unauthorized-deploy-adjacent impact tier, since forged commit statuses can influence whether commits are considered deployable.

### Likelihood Explanation
Requires the attacker to be an onboarded tenant of a multi-organization Shipit deployment (i.e., control their own legitimately-provisioned `webhook_secret`/GitHub App for one organization) but have no authorization over other organizations tracked by the same instance — a realistic scenario for any shared/multi-tenant Shipit installation as explicitly documented ("Using Multiple GitHub Applications"). No GitHub write access, session, or `ApiClient` token to the *target* org is needed; only the ability to craft and POST an HTTP request signed with the attacker's own org secret.

### Recommendation
After signature verification selects an organization, every handler must re-derive and verify that the object being mutated (`Commit`, `Repository`, `Stack`) genuinely belongs to that same verified organization/repository before taking any action — in particular `StatusHandler` must scope its `Commit` lookup by the repository resolved from the verified organization, and `Handler#repository_name`/`#stacks` must cross-check `repository.full_name`'s owner against `repository_owner` used for signature verification, rejecting mismatches.

### Proof of Concept
1. Deploy Shipit configured for two organizations, `OrgA` and `OrgB`, each with distinct `webhook_secret`s, tracking stacks for `OrgA/repo1` and `OrgB/repo2` respectively (per docs/setup.md multi-org config).
2. As a legitimate holder of `OrgA`'s `webhook_secret` (an OrgA admin), craft a `status` event payload:
```json
{"sha": "<sha of a commit belonging to OrgB/repo2>", "state": "success", "context": "ci", "repository": {"owner": {"login": "OrgA"}}}
```
3. Compute `X-Hub-Signature: sha1=<hmac_sha1(OrgA_webhook_secret, body)>` and POST to `/webhooks` with `X-Github-Event: status`.
4. `verify_signature` resolves `repository_owner` → `"OrgA"`, fetches OrgA's `GitHubApp`, and the signature validates against OrgA's own secret.
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` and creates a status on the OrgB commit — mutating OrgB's data using only OrgA's credentials.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
