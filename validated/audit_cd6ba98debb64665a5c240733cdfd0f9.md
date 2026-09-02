### Title
Cross-Organization Signature Bypass via Attacker-Controlled `repository.owner.login` in Webhook Verification - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App / webhook secret to validate the HMAC signature against using a field taken from the **unauthenticated, attacker-supplied JSON body itself** (`repository.owner.login`, falling back to `organization.login`), rather than from any value tied to the actual repository the payload will act upon. Because `GitHubApp#verify_webhook_signature` unconditionally returns `true` when no `webhook_secret` is configured for the resolved organization, an attacker can pick an organization with no configured secret to satisfy verification, while independently setting `repository.full_name` — the field actually used by `Handlers::Handler#repository_name` to resolve the `Stack`/`Repository` to write to — to a *different*, secret-protected organization's repository.

### Finding Description
Verification and the field acted upon are bound to different parts of the same untrusted payload:

- Verification org: `app/controllers/shipit/webhooks_controller.rb:24-30,59-62` computes `repository_owner = params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(header, raw_post)`. [1](#0-0) [2](#0-1) 

- Secret-less bypass: `lib/shipit/github_app.rb:76-83` — `verify_webhook_signature` returns `true` immediately when `webhook_secret` is blank for the resolved org, regardless of the actual `X-Hub-Signature` sent. [3](#0-2) 

- Multi-org config explicitly allows a `webhook_secret` to be left unset per organization, as documented/sampled in `config/secrets.development.shopify.yml:1-23` (`webhook_secret: # nil`), and organizations are resolved independently via `Shipit.github_app_config`/`Shipit.github` in `lib/shipit.rb:170-200`. [4](#0-3) [5](#0-4) 

- Target repository: after verification passes, `WebhooksController#create` (`app/controllers/shipit/webhooks_controller.rb:10-15`) dispatches the *same raw JSON body* to `Shipit::Webhooks.for_event(event)` handlers. `Handlers::Handler#repository_name` (`app/models/shipit/webhooks/handlers/handler.rb:36-38`) resolves the target repository from `payload.dig('repository', 'full_name')` — a field completely independent of `repository.owner.login` used for verification — and `#stacks` (`handler.rb:32-34`) looks up `Repository.from_github_repo_name(repository_name)` to obtain the `Stack`(s) to act on. [6](#0-5) [7](#0-6) 

- `PushHandler#process` (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`) then calls `stack.sync_github(expected_head_sha: params.after)` for every non-archived stack of that repository matching the attacker-supplied branch, enqueuing `GithubSyncJob` (`app/jobs/shipit/github_sync_job.rb:18-49`) which fetches commits and appends them to the stack's commit history — data that feeds deploy/rollback eligibility, CI status matching, and (if continuous delivery is enabled) triggers deploy jobs. [8](#0-7) 

**Broken binding (equality that must hold but doesn't):**
`organization whose secret authenticated the request` **==** `organization/repository the request actually causes writes to`.

An attacker with no Shipit credentials, no `webhook_secret`, and no repository access can post to the public `/webhooks` endpoint with:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": { "full_name": "victim-org/target-repo", "owner": { "login": "org-without-secret" } },
  "organization": { "login": "org-without-secret" }
}
```
`repository_owner` resolves to `org-without-secret`, whose `webhook_secret` is unset, so `verify_webhook_signature` returns `true` unconditionally — the attacker doesn't even need to send a valid `X-Hub-Signature` header. The `create` action then processes the full payload with `Handlers::PushHandler`, which resolves the actual target via `repository.full_name = "victim-org/target-repo"`, entirely bypassing the fact that `victim-org` does have a webhook secret configured.

### Impact Explanation
This crosses an organization/repository trust boundary without any secret for the targeted org/repository — an unauthenticated, unprivileged actor can forge push (and similarly, `status`, `check_suite`, `membership`, `pull_request` — any handler keyed off the same payload) events against any stack tracked by Shipit, as long as at least one configured GitHub organization in the deployment has no `webhook_secret` set. This can inject attacker-controlled commit SHAs into a victim stack's commit graph via `GithubSyncJob`/`stack.commits.create_from_github!`, and per `Shipit.update_latest_deployed_ref`/continuous-delivery configuration this data feeds decisions about what gets auto-deployed. This matches the "organization that authenticated versus the repository that is written" boundary explicitly called out as in-scope.

### Likelihood Explanation
Requires the shipit instance to be configured with multiple GitHub organizations where at least one has no `webhook_secret` set (a configuration explicitly supported and shown as a sample in this engine's own docs/config, `config/secrets.development.shopify.yml`). Given that setup, exploitation requires no authentication, no tokens, and no prior access — a single unauthenticated HTTP POST.

### Recommendation
Do not derive the organization used for signature verification from the same untrusted payload that determines the acted-upon repository. Instead, verify the signature against the webhook secret of the organization that actually owns `repository.full_name`/the resolved `Stack`'s registered repository, and reject payloads with mismatched owner/full_name organizations. Additionally, do not allow `verify_webhook_signature` to silently return `true` when a per-organization secret is unset in production configurations — require an explicit "no verification" opt-in, or fail closed by default.

### Proof of Concept
1. Configure Shipit with two GitHub orgs: `victim-org` (has `webhook_secret: real-secret`, has a tracked `Repository`/`Stack` for `victim-org/target-repo`) and `org-without-secret` (no `webhook_secret` configured).
2. POST to `/webhooks` with header `X-Github-Event: push` and any/garbage `X-Hub-Signature`, and body:
```json
{
  "ref": "refs/heads/main",
  "after": "0000000000000000000000000000000000dead",
  "repository": { "full_name": "victim-org/target-repo", "owner": { "login": "org-without-secret" } }
}
```
3. `WebhooksController#verify_signature` resolves `repository_owner = "org-without-secret"`, whose `GitHubApp#verify_webhook_signature` returns `true` since `webhook_secret` is blank (`lib/shipit/github_app.rb:76-77`).
4. `create` dispatches to `PushHandler`, which resolves `repository_name = "victim-org/target-repo"` (`handler.rb:37`) and enqueues `GithubSyncJob` for `victim-org/target-repo`'s stacks, despite the request never being validated against `victim-org`'s actual secret.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
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
