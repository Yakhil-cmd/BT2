### Title
Cross-organization webhook forgery: signature is verified against the payload's `repository.owner.login`, but stack resolution uses `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate a webhook against using the organization derived from `repository.owner.login` (or `organization.login`) in the JSON body, but the handlers that actually act on the payload (`Handler#repository_name`, consumed by `PushHandler`, `StatusHandler`, `CheckSuiteHandler`, etc.) resolve the target `Stack`/`Commit` using `repository.full_name` from the same attacker-controlled body. Nothing binds these two fields together, so on a multi-organization Shipit deployment, an org that is legitimately registered under `Shipit.secrets.github` can forge webhook events that are "signed" for itself but target any other organization's repository/stack.

### Finding Description
`WebhooksController#verify_signature` computes `repository_owner` purely from the JSON body: [1](#0-0) 

It then fetches the `GitHubApp` (and therefore the `webhook_secret` used for HMAC verification) for that organization: [2](#0-1) 

`Shipit.github(organization:)` looks up per-organization config (each with its own `webhook_secret`) keyed by the lowercased organization name: [3](#0-2) 

This multi-organization scheme is explicitly documented/supported: [4](#0-3) 

Once the signature is verified, the raw parsed body is dispatched unmodified to handlers: [5](#0-4) 

Every handler resolves the target repository/stack from a *different* field of the same body — `repository.full_name` — with no cross-check against the `owner.login` used to select the verifying secret: [6](#0-5) 

Concretely:
- `PushHandler` finds stacks by branch on `stacks` (derived from `repository_name`) and calls `stack.sync_github`: [7](#0-6) 
- `StatusHandler` finds real `Commit` rows by `sha` and injects an attacker-controlled CI status (`state`, `context`, `description`, `target_url`) via `create_status_from_github!`: [8](#0-7) 

Because `Commit.where(sha: params.sha)` is a global lookup unscoped to the verified organization, an attacker who legitimately owns "org A" (registered as its own entry under `Shipit.secrets.github` in a multi-tenant Shipit instance) knows/controls `org A`'s `webhook_secret`. They can sign an arbitrary JSON body with that secret while setting `repository.owner.login: "org-a"` (so `verify_signature` picks org A's secret and passes) and `repository.full_name: "victim-org/victim-repo"` plus any `sha`/`state`/`context` (so the handler acts on a real commit belonging to org B's stack). This breaks the equality that should hold: `organization authenticated by the signature == organization owning the repository the handler mutates`.

### Impact Explanation
Via `StatusHandler`, the attacker can fabricate a passing (`state: "success"`) CI status for a specific commit `sha` on a victim's stack under a required/blocking status `context`. If that stack has `continuous_deployment` enabled and the forged status satisfies `required_statuses`, `ContinuousDeliveryJob` will pick it up (`stack.continuous_deployment?` check) and trigger an automatic, unauthorized deploy of that commit via `stack.trigger_continuous_delivery`: [9](#0-8) 

This is a cross-organization write (forging status data belonging to another org's commit) that can culminate in an unauthorized deploy, satisfying the Critical/High impact bar for this analysis (unauthorized deploy / cross-repository writes).

### Likelihood Explanation
This requires the Shipit instance to be configured for multiple GitHub organizations (a documented, supported configuration in `config/secrets.development.example.yml`) and for the attacker to control (or know) the `webhook_secret` of one of those organizations while targeting another organization hosted on the same instance. This is a realistic scenario for shared/self-service Shipit deployments serving several orgs, but not applicable to single-org deployments (where `github_default_organization` is `nil` and only one secret exists, making `repository_owner` irrelevant to secret selection — though even then, `full_name` is still not validated against `owner.login`, it doesn't cross a trust boundary in the single-org case).

### Recommendation
- In `WebhooksController#verify_signature`/`Handler`, after establishing which organization's secret validated the signature, enforce that `payload.dig('repository', 'owner', 'login')` matches the owner embedded in `payload.dig('repository', 'full_name')`, and reject the event if they diverge.
- Additionally, scope `Handler#stacks`/`Commit` lookups to repositories belonging to the verified organization rather than trusting `full_name` alone, closing the gap between "the org whose secret authenticated the request" and "the repository the handler is permitted to mutate."

### Proof of Concept
1. Configure Shipit with two organizations, `org-a` and `org-b`, each with its own `webhook_secret` (per the documented multi-org schema in `config/secrets.development.example.yml`).
2. As an attacker who controls `org-a` (and thus knows `org-a`'s `webhook_secret`), craft a `status` event body:
```json
{
  "sha": "<victim commit sha belonging to org-b/victim-repo>",
  "state": "success",
  "context": "<required-status-context-for-victim-stack>",
  "repository": { "owner": { "login": "org-a" }, "full_name": "org-b/victim-repo" }
}
```
3. Compute `X-Hub-Signature` using `org-a`'s `webhook_secret` over the raw body.
4. `POST /webhooks` with `X-Github-Event: status` and the signature header.
5. `verify_signature` resolves `repository_owner => "org-a"`, verifies successfully against `org-a`'s secret.
6. `StatusHandler#process` runs `Commit.where(sha: params.sha)` (global, unscoped by org) and calls `create_status_from_github!`, creating a forged "success" status on the victim's commit belonging to `org-b`, potentially triggering `ContinuousDeliveryJob` to deploy it if that stack has continuous deployment enabled and required statuses satisfied.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/jobs/shipit/continuous_delivery_job.rb (L10-21)
```ruby
    def perform(stack)
      return unless stack.continuous_deployment?

      # If there is a schedule defined for this stack, make sure we are within a
      # deployment window before proceeding.
      return if stack.continuous_delivery_schedule && !stack.continuous_delivery_schedule.can_deploy?

      # checks if there are any tasks running, including concurrent tasks
      return if stack.occupied?

      stack.trigger_continuous_delivery
    end
```
