### Title
Webhook signature verification is scoped to `repository.owner.login`, but handlers act on unrelated `full_name`/`sha` fields with no cross-check, allowing an attacker who controls one configured GitHub organization's webhook secret to forge events against another organization's stacks/commits - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to verify the HMAC signature with, based on `repository.owner.login` (or `organization.login`) pulled from the *as-yet-unverified* payload. [1](#0-0) [2](#0-1)  Once the signature check passes (proving only that the request was signed with *that organization's* secret), the event handlers act on completely different fields of the same payload - `repository.full_name` in `Handler#stacks`/`PushHandler`/pull-request handlers, or, worse, only `sha` in `StatusHandler`, with no repository binding at all. [3](#0-2) [4](#0-3) [5](#0-4)  Shipit explicitly supports multiple GitHub organizations sharing one instance, each with its own `webhook_secret`, selected via `Shipit.github(organization:)`. [6](#0-5) [7](#0-6)  There is no code path that verifies the organization that produced a valid signature actually matches the repository/commit the handler subsequently mutates.

### Finding Description
The trust binding that should hold is:

`organization whose secret produced a valid signature == organization/repository the handler subsequently writes to`

In `verify_signature`, the organization used to pick the verification secret comes from the payload itself:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [2](#0-1) 

This is fed into `Shipit.github(organization: repository_owner)`, which - in the documented multi-org configuration - looks up a distinct `webhook_secret` per organization key. [6](#0-5)  A signature that verifies only proves the request body was HMAC-signed with *that particular organization's* secret; nothing else in the request is otherwise authenticated as coming from GitHub for a specific repository.

Downstream, the actual side effects are keyed off a *different, uncorrelated* field:
- `Handler#stacks` / `PushHandler` resolve the target `Repository`/`Stack` via `payload.dig('repository', 'full_name')` [3](#0-2) , then trigger `stack.sync_github(expected_head_sha: params.after)` for every matching stack. [4](#0-3) 
- `StatusHandler#process` doesn't even use `repository.full_name` - it looks up commits **globally by sha alone**: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`. [5](#0-4) 

Because the code never checks that `repository.owner.login` (the field bound to the verified signature) is consistent with `repository.full_name` or with the repository owning the `sha`-matched commit, an entity that legitimately controls the webhook secret for *organization A* in a shared, multi-org Shipit deployment can forge a signed payload claiming `repository.owner.login: "A"` (so it authenticates with A's own secret) while setting `repository.full_name` (or simply `sha`) to point at a stack/commit that belongs to organization B on the same instance. The signature check passes because it only validates the byte-for-byte body against A's secret; it says nothing about which repository the handler is permitted to touch.

### Impact Explanation
- Via `StatusHandler`, an attacker who controls one organization's webhook secret can inject arbitrary commit statuses for any commit `sha` tracked anywhere in the Shipit instance, regardless of which organization or repository it belongs to. [5](#0-4)  Shipit's deploy pipeline uses commit statuses to gate whether a commit is deployable; forging a "success" status on a victim's commit can be used to make an otherwise-blocked/unreviewed commit appear deployable, leading to an **unauthorized deploy** through Shipit's own credentials.
- Via `PushHandler`, the attacker can force `stack.sync_github(expected_head_sha:)` to run against a victim organization's stack, using an attacker-chosen `after` SHA, again keyed only by the org that signed the request rather than by the org that owns the target repository. [4](#0-3) 

This crosses the "unauthenticated action on another organization's repository state" line and can result in an unauthorized deploy, matching the Critical impact bucket in scope.

### Likelihood Explanation
Exploitation requires the attacker to legitimately control (or compromise) the webhook secret of *any one* organization configured on a shared Shipit instance - a lower bar than compromising the target organization directly, and squarely a multi-tenant deployment the engine explicitly supports and documents (`config/secrets.development.example.yml` shows the multi-org schema). [7](#0-6)  No repository write access, `ApiClient` token, or GitHub App private key for the *victim* organization is required, only the ability to send an HTTP POST with a valid signature for the attacker's own configured org.

### Recommendation
Cross-validate the organization bound to the verified signature against the organization implied by the fields handlers act on:
- In `WebhooksController#verify_signature`/`Webhooks.for_event`, pass the verified `repository_owner` (or organization) into each handler and have `Handler#stacks`/`StatusHandler`/pull-request handlers scope their lookups by that same organization, rejecting payloads whose `repository.full_name` owner or matched commit's repository owner doesn't match the organization that produced the valid signature.
- Specifically fix `StatusHandler` to scope `Commit.where(sha: ...)` by the repository/organization derived from the verified signature instead of matching `sha` globally.

### Proof of Concept
1. Configure Shipit with two organizations sharing one instance, e.g. `github: { orgA: { webhook_secret: "secretA", ... }, orgB: { webhook_secret: "secretB", ... } }` per the documented multi-org schema. [7](#0-6) 
2. As an entity with legitimate access to `orgA`'s GitHub App / webhook secret (`secretA`), craft a `status` event payload:
   ```json
   { "sha": "<sha of a commit belonging to orgB's tracked repository>",
     "state": "success",
     "repository": { "owner": { "login": "orgA" } } }
   ```
3. Sign the raw body with `secretA` and send it as `X-Hub-Signature` to `/webhooks` with `X-Github-Event: status`.
4. `WebhooksController#verify_signature` resolves `repository_owner => "orgA"`, fetches `orgA`'s `GitHubApp`, and successfully verifies the signature against `secretA`. [1](#0-0) 
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, matching the `orgB` commit by `sha` alone (no organization scoping) and applies the forged status via `create_status_from_github!`. [5](#0-4)  The forged status can satisfy `orgB`'s deploy-gating checks, enabling an unauthorized deploy of that stack.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-36)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
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
