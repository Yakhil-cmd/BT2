### Title
Organization-selection field used for webhook signature verification is not the same field used to identify the acted-upon repository, allowing signature bypass via secret-less org - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and thus which `webhook_secret`) to verify against using `repository_owner`, taken from the *unauthenticated* JSON body (`params.dig('repository', 'owner', 'login')`). The actual event-processing handlers, however, resolve the target `Repository`/`Stack` using a *different* field from the same untrusted body: `payload.dig('repository', 'full_name')`. Because these two fields are not cryptographically bound together, an attacker can craft a payload that authenticates as one (secret-less/misconfigured) organization while acting on a repository belonging to a different, properly-secured organization.

### Finding Description
`verify_signature` picks the GitHub App/secret to check against based on attacker-supplied data: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` completely skips verification when the resolved org's `webhook_secret` is blank: [3](#0-2) 

This is a legitimate, documented configuration: `webhook_secret` is explicitly optional in both single-org and multi-org configs, and Shipit natively supports multiple GitHub App configs keyed by organization name via `Shipit.github(organization:)` / `github_app_config`: [4](#0-3) [5](#0-4) 

Once signature verification passes (or is skipped), the raw JSON body is dispatched to event handlers. All handlers resolve which `Repository`/`Stack` to mutate via `Handler#repository_name`, which reads `payload.dig('repository', 'full_name')` — a completely separate field from the one used for the auth-org lookup: [6](#0-5) 

Because `repository.owner.login` (used to pick the verifying secret) and `repository.full_name` (used to pick the target stack) are independent JSON fields in the same attacker-controlled body, an attacker can submit:
```json
{
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  },
  "ref": "refs/heads/master",
  "after": "<attacker chosen sha>"
}
```
If `attacker-org` is configured in `secrets.github` with no `webhook_secret` (documented as optional/`nil`), `verify_webhook_signature` returns `true` unconditionally — no signature is checked at all — while the event still fully drives `PushHandler#process`, which looks up stacks by `victim-org/victim-repo` and triggers `stack.sync_github(expected_head_sha: params.after)`: [7](#0-6) 

This breaks the intended binding: *the organization whose credentials authenticated the request* should equal *the repository the request is permitted to act on*. Here, the authenticating organization (`attacker-org`, secret-less) and the acted-upon repository (`victim-org/victim-repo`, secret-protected) are decoupled, so the attacker never needs to know `victim-org`'s webhook secret.

### Impact Explanation
An unauthenticated network attacker who merely knows (a) that Shipit is configured for multiple organizations and (b) that at least one configured organization has no `webhook_secret` set, can forge fully unsigned webhook deliveries that are processed as if they came from GitHub for *any* repository tracked by Shipit. Depending on event type this can:
- Force `GithubSyncJob`/`sync_github` to run against attacker-chosen `expected_head_sha`, influencing what is considered deployable and potentially enabling an unauthorized deploy of attacker-controlled state.
- Forge `status`/`check_suite` events to fabricate green CI/commit statuses that gate deploy/merge safety checks.
- Forge `membership` events to add/remove `Team`/`Membership` records, which feed directly into `Shipit.github_teams` authorization used by `Authentication#force_github_authentication` (`current_user.authorized?`), potentially escalating access.

This matches the "escalation into `Shipit.github_teams` authorization" and "unauthorized deploy" impact classes.

### Likelihood Explanation
Requires a specific but plausible and documented deployment shape: multi-organization Shipit configuration where at least one organization intentionally or accidentally omits `webhook_secret` (explicitly shown as optional in `config/secrets.development.example.yml`). No credentials, session, or GitHub App key are needed — only network access to `/webhooks` and knowledge of one org name with no secret configured. This is a realistic misconfiguration risk in any Shipit instance serving several GitHub orgs, rather than a purely theoretical scenario.

### Recommendation
Bind the field used to select the verifying secret to the same field used to identify the acted-upon repository — e.g., always resolve the authenticating organization from `repository.full_name`'s owner segment (or equivalently validate that `repository.owner.login` matches the owner segment of `repository.full_name`) before dispatching to handlers. Additionally, consider making `webhook_secret` mandatory (or failing closed) whenever more than one GitHub organization is configured, since a single secret-less org currently disables verification for events attributable to that org while still allowing handlers to act on any repository named in the payload.

### Proof of Concept
1. Configure Shipit with two orgs in `secrets.github`: `victim-org` (with `webhook_secret` set) and `attacker-org` (with `webhook_secret` left `nil`), each with a stack tracked for `victim-org/victim-repo`.
2. POST to `/webhooks` with header `X-Github-Event: push` and no valid `X-Hub-Signature`, body:
```json
{
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" },
  "ref": "refs/heads/master",
  "after": "deadbeef"
}
```
3. `verify_signature` resolves `Shipit.github(organization: "attacker-org")`; since `attacker-org.webhook_secret` is blank, `verify_webhook_signature` returns `true` without checking anything (`lib/shipit/github_app.rb:76-77`).
4. `create` proceeds; `PushHandler` resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `sync_github(expected_head_sha: "deadbeef")` on its stacks — fully unauthenticated relative to `victim-org`.

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

**File:** config/secrets.development.example.yml (L8-38)
```yaml
github:
  app_id:
  installation_id:
  webhook_secret: # nil
  private_key:
  oauth:
    id:
    secret:
    teams: # Optional

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
