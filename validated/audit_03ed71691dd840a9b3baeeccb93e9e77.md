## Analysis Summary

Confirmed: `Shipit.github(organization:)` (`lib/shipit.rb:170-181`) supports a documented multi-organization configuration (`config/secrets.development.example.yml`, `docs/setup.md`) where each GitHub organization has its own `webhook_secret`, selected via `github_app_config(organization)`. The webhook signature check in `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) selects the app/secret using `repository_owner`, which reads `params.dig('repository','owner','login')`. All the actual webhook business logic (`Handler#repository_name`, `app/models/shipit/webhooks/handlers/handler.rb:36-38`, used by `PushHandler`, `StatusHandler`, `CheckSuiteHandler`, pull-request handlers) instead resolves the target `Repository`/`Stack` from `payload.dig('repository','full_name')` — a distinct, independently-attacker-controlled JSON field within the same request body. Nothing cross-checks that `repository.full_name`'s owner segment matches `repository.owner.login`.

### Title
Webhook Signature Verifies `repository.owner.login` While Handlers Act on the Unbound `repository.full_name` Field, Enabling Cross-Organization Event Forgery - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
In multi-organization Shipit deployments, an attacker who legitimately possesses (or otherwise obtains through their own org's GitHub App admin access) the `webhook_secret` of Organization A can forge a webhook payload whose `repository.owner.login` says "OrgA" (so the HMAC check passes against OrgA's secret) but whose `repository.full_name` names a completely different repository belonging to Organization B. Because the field used to select/verify the signing secret is never bound to the field used to select the target `Stack`, the forged request is accepted and executed against Organization B's stack.

### Finding Description
`verify_signature` picks the `GitHubApp` (and thus the HMAC secret) to validate against using: [1](#0-0) 

using `repository_owner`: [2](#0-1) 

Once the signature check passes, `create` hands the *entire* parsed body to the registered handlers unmodified: [3](#0-2) 

Every default handler resolves the affected `Stack`/`Repository` via a *different* JSON path, `repository.full_name`, not `repository.owner.login`: [4](#0-3) 

`PushHandler` then uses that repository to enqueue a `GithubSyncJob`, which pulls new commits into the target stack and can trigger continuous-deployment logic: [5](#0-4) 

`Shipit.github(organization:)` confirms the app explicitly supports a per-organization secret configuration, where `secrets.github` is a hash keyed by organization name each carrying its own `webhook_secret`: [6](#0-5) 

This is corroborated by the documented multi-org config layout: [7](#0-6) 

The trust binding that should hold is: `repository.owner.login (secret used to sign) == owner(repository.full_name) (repository acted upon)`. The code never enforces this equality. An attacker who is a legitimate GitHub App admin/webhook operator for Organization A (and thus knows OrgA's `webhook_secret` — a credential entirely outside Shipit's own authentication domain and outside OrgB's trust boundary) can:
1. Build a `push` (or `status`/`check_suite`/`pull_request`) JSON body with `repository.owner.login = "OrgA"` and `repository.full_name = "OrgB/target-repo"`.
2. Sign the raw body with OrgA's `webhook_secret` and set `X-Hub-Signature` accordingly.
3. POST it to the shared `/webhooks` endpoint (there is no per-org URL segment).

`verify_signature` computes the HMAC with OrgA's `webhook_secret` over the exact bytes sent — which succeeds, because the attacker controls the whole payload and signs it themselves. The handler then locates and mutates state on OrgB's `Stack` using `repository.full_name`, entirely outside OrgA's authority.

### Impact Explanation
This breaks the "organization authenticated vs. repository written" binding described by this bug class. Concretely, an attacker with credentials scoped only to Organization A's GitHub App can:
- Force `GithubSyncJob` to run against an unrelated Organization B's stack, causing Shipit to ingest attacker-chosen `expected_head_sha` / commit metadata into that stack's commit history.
- If the target stack has `continuous_deployment` enabled and the referenced commit passes/records CI (via forged `status`/`check_suite` events using the same technique), this can result in an **unauthorized deploy** being triggered for a repository the attacker has no legitimate relationship with — a cross-organization/cross-repository write and potential unauthorized deploy, matching the Critical impact bar ("cross-repository writes, or an unauthorized deploy").
- `membership` and `pull_request` handlers can similarly be induced to create/modify `Team`/`User`/pull-request state tied to an org the caller's secret doesn't belong to.

### Likelihood Explanation
Exploitability is contingent on the deployment using the documented multi-organization `github:` configuration (per docs/setup.md and `config/secrets.development.example.yml`), which is an explicitly supported and documented topology, not an undocumented misconfiguration. Within that topology, any party holding a single organization's `webhook_secret` (e.g., any admin of one of the several GitHub App installations the Shipit instance serves) can mount this attack against every other organization served by the same Shipit instance, with no additional privilege. This is a moderate-likelihood, high-blast-radius issue for multi-tenant Shipit installations.

### Recommendation
After signature verification, the webhook controller/handlers should require that the organization/owner used to select the verifying secret matches the owner embedded in `repository.full_name` (and `organization.login` for org-scoped events) before dispatching to handlers — e.g., reject the request if `repository.full_name.split('/').first.casecmp?(repository_owner)` is false, or better, look up the target `Repository`/`Stack` scoped to the already-authenticated organization rather than trusting `full_name` independently.

### Proof of Concept
1. Configure Shipit with two organizations, `orga` and `orgb`, each with its own `webhook_secret` (per the documented multi-org schema in `config/secrets.development.example.yml`).
2. As an attacker who administers `orga`'s GitHub App (and thus knows `orga`'s `webhook_secret`), craft:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": { "owner": { "login": "orga" }, "full_name": "orgb/target-repo" }
}
```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(orga_webhook_secret, raw_body)>`.
4. `POST /webhooks` with header `X-Github-Event: push`, the above signature, and the body.
5. `verify_signature` resolves `Shipit.github(organization: "orga")` and validates successfully against `orga`'s secret.
6. `PushHandler#process` resolves stacks via `payload.dig('repository','full_name')` → `orgb/target-repo`, and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")`, enqueuing `GithubSyncJob` against Organization B's stack — despite the attacker never having presented any credential associated with Organization B.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-17)
```ruby
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

**File:** config/secrets.development.example.yml (L18-38)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
```
