### Title
Webhook signature verification is scoped to `repository.owner.login` while the actual repository/stack acted upon is resolved from the independent `repository.full_name` field, allowing cross-organization webhook forgery in multi-org deployments - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
Shipit supports a multi-organization configuration where each GitHub organization has its own `webhook_secret` [1](#0-0) , selected at runtime via `Shipit.github(organization:)` / `github_app_config` [2](#0-1) . `WebhooksController#verify_signature` picks which org's secret to verify the HMAC signature against using `repository_owner`, itself read from the attacker-controlled JSON body (`params.dig('repository','owner','login')`), then verifies the signature over the same raw body [3](#0-2) . However, once verified, the event handlers resolve the *actual* repository/stack to act on from a **different field in the same body**: `payload.dig('repository', 'full_name')` [4](#0-3) . Nothing enforces that `repository.owner.login` (used to select/verify against the correct org secret) actually matches the owner encoded in `repository.full_name` (used to select which repository/stack the event is applied to). An attacker who legitimately knows one organization's webhook secret (e.g. because they configured/administer their own org's GitHub App integration in this Shipit multi-org instance) can therefore forge a signed webhook payload whose `owner.login` is their own org (to pass signature verification) but whose `full_name` names a completely different, unrelated repository/stack hosted in the same Shipit instance, and have that handler act on the victim repository's stacks.

### Finding Description
The binding that should hold is:
`organization authenticated by verify_signature (repository.owner.login → selected webhook_secret)` == `organization/repository actually written to by the handler (repository.full_name)`

Before the fix, these are two independent reads of the same attacker-supplied JSON body:

1. `WebhooksController#repository_owner` reads `params.dig('repository', 'owner', 'login')` to pick which `GitHubApp`/`webhook_secret` is used to verify `X-Hub-Signature` [3](#0-2) .
2. `Shipit::Webhooks::Handlers::Handler#repository_name` reads `payload.dig('repository', 'full_name')` to resolve `Repository.from_github_repo_name(...)` and hence the `stacks` acted upon by concrete handlers such as `PushHandler` and `StatusHandler` [4](#0-3) [5](#0-4) [6](#0-5) .

Since the entire JSON body is attacker-controlled content signed with a secret the attacker may legitimately possess (their own org's `webhook_secret` in a multi-org deployment, per the documented "multiple GitHub applications for different GitHub organizations" schema) [1](#0-0) , the attacker can independently set `repository.owner.login = "my-org"` (satisfies signature check) and `repository.full_name = "victim-org/victim-repo"` (drives what the handler actually mutates). The HMAC only guarantees the bytes weren't tampered with in transit; it does not bind `owner.login` to `full_name`, and no other code path cross-checks them.

Notably `StatusHandler#process` writes attacker-controlled CI state directly into the datastore without ever calling back to GitHub: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [6](#0-5) , and `PushHandler#process` triggers `stack.sync_github(expected_head_sha: params.after)` for stacks resolved via the forged `full_name` [5](#0-4) .

### Impact Explanation
This breaks the "organization that authenticated versus the repository that is written" trust binding. Concretely, an attacker who legitimately controls one org's webhook secret in a multi-tenant Shipit deployment can forge webhook events (push, status, check_suite, membership, etc.) that are attributed to and acted upon a victim organization/repository they do not administer. The most severe consequence is via `status` events: an attacker can inject a fabricated `success` CI status for an existing commit SHA of the victim stack, without that check ever actually running on GitHub. If the victim stack requires that CI context before deploy (`ci.require`) and has continuous deployment enabled, this can lead to an **unauthorized deploy** of a commit that never passed CI — matching the Critical impact bar ("unauthorized deploy, rollback or merge").

### Likelihood Explanation
Exploitation requires the attacker to know a valid `webhook_secret` for at least one organization configured in the Shipit instance — a realistic condition only in multi-org deployments where different teams each provide/own their org's webhook secret, which is an explicitly supported and documented configuration schema in this engine. Under that documented setup, the attack requires no compromise of the victim org, no GitHub credentials for the victim, and no Shipit user session — only crafting and POSTing a JSON body directly to `/webhooks` with a valid signature for the attacker's own org. This is a plausible, not merely theoretical, path given the schema is first-class in the codebase.

### Recommendation
Bind repository resolution to the same authenticated identity used for signature verification: after `verify_signature` succeeds for organization `O` (derived from `repository.owner.login`), require that the repository resolved from `repository.full_name` also belongs to organization `O` before invoking any handler (e.g., compare `repository.full_name.split('/').first` against the org used to select the `webhook_secret`, and reject/`head(422)` on mismatch). Alternatively, always resolve the repository/organization strictly from `repository.owner.login` (or `organization.login` for org-level events) end-to-end, rather than mixing it with `full_name` picked up later by handlers.

### Proof of Concept
Given a Shipit instance configured for two organizations, `attacker-org` (attacker knows/owns its `webhook_secret`) and `victim-org` (unrelated, hosts a Shipit-tracked repository/stack with continuous deployment enabled and a required CI context):

1. Attacker crafts a JSON body for a `status` event:
```json
{
  "sha": "<existing sha of victim-org/victim-repo tracked commit>",
  "state": "success",
  "context": "required-check",
  "repository": {
    "full_name": "victim-org/victim-repo",
    "owner": { "login": "attacker-org" }
  }
}
```
2. Attacker computes `X-Hub-Signature: sha1=<hmac(attacker-org's webhook_secret, body)>` and sends it to `POST /webhooks` with `X-Github-Event: status`.
3. `WebhooksController#verify_signature` looks up `Shipit.github(organization: "attacker-org")` (from `repository.owner.login`) and successfully verifies the signature (attacker knows this secret) [7](#0-6) .
4. `StatusHandler#process` resolves stacks/commits via `repository.full_name = "victim-org/victim-repo"` [4](#0-3)  and writes a forged `success` status for that commit in `victim-org`'s repository [6](#0-5) , potentially unblocking an automated deploy that should have been gated on real CI results.

### Citations

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

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

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
