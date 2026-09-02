### Title
Webhook signature is bound to `repository.owner.login`, but event handlers key off the unauthenticated `repository.full_name` field, letting a valid webhook signer for one org forge events against any other configured org's stacks - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to check the HMAC signature against using `repository_owner`, taken from `params.dig('repository','owner','login')` (falling back to `params.dig('organization','login')`). Once the signature is accepted, the same raw JSON payload is dispatched to handlers, which instead resolve the target `Stack`/`Repository` using a *different* payload field: `params.dig('repository','full_name')`. These two fields are never cross-checked against each other, so the field that is authenticated (owner login) is not the field that is acted upon (repository full name).

### Finding Description
`verify_signature` computes the signing organization purely from attacker-controlled JSON and uses it only to pick the `GithubApp`/secret to verify against: [1](#0-0) [2](#0-1) 

After the signature check passes, the full, unmodified `params` hash is handed to the event handlers: [3](#0-2) 

The base `Handler` class (used by `PushHandler`, `StatusHandler`, PR handlers, etc.) resolves the target repository purely from `repository.full_name`, a completely independent JSON field from `repository.owner.login`: [4](#0-3) 

`PushHandler` then triggers a real GitHub sync/fetch against that resolved stack: [5](#0-4) 

`StatusHandler` writes an arbitrary commit status onto any commit matching `sha` across the whole install, without any repository-ownership check: [6](#0-5) 

The multi-organization mode is a documented, supported configuration where each org gets its own `webhook_secret` and GitHub App credentials: [7](#0-6) [8](#0-7) 

**The broken binding, as an equality**: the engine implicitly assumes
`organization used to select/verify the signing secret == organization that owns the repository acted upon by handlers`
but this is never enforced — verification uses `repository.owner.login`/`organization.login`, while every handler uses `repository.full_name`. An attacker who legitimately controls (or has compromised) the webhook secret for **any one** organization configured in a multi-org Shipit deployment can set `repository.owner.login` to their own org (so verification passes with their own secret) while setting `repository.full_name` to `"other-org/other-repo"` (a repo/stack belonging to a different organization on the same install). The signature is valid, so `verify_signature` accepts the request, and the handler blindly acts on the forged `full_name`.

### Impact Explanation
This crosses an authentication boundary the rules explicitly call out ("an organization that authenticated versus the repository that is written"):
- Via `PushHandler`, the attacker can force `GithubSyncJob` to run against a victim stack in another org, triggering `stack.sync_github`, which fetches/attaches new commits from the real upstream repo — effectively forcing unauthorized re-sync/processing on a stack the attacker does not own.
- Via `StatusHandler`, the attacker can inject an arbitrary CI/commit status (`state`, `context`, `target_url`, `description`) onto **any commit sha already known to Shipit for any stack**, since `Commit.where(sha: params.sha)` is not scoped by organization/repository at all. Shipit deploy safety in review/CI gating relies on commit statuses; forging a "success" status for a commit belonging to another organization's stack can be used to make an otherwise-unreviewed or failing commit appear deployable, since the write only requires *some* valid webhook signature on the whole instance, not one bound to that specific repository/org.
- This qualifies as escalation of the trust boundary between organizations hosted on the same Shipit instance ("unauthenticated read/write of stack state" / potential "unauthorized deploy" pathway via a forged deployable commit status), which meets the High-impact bar defined in scope.

### Likelihood Explanation
Requires the attacker to already possess a valid webhook secret for *some* organization configured on the Shipit instance (e.g., they administer that GitHub App/organization, or that secret has otherwise leaked) — this is a real-world condition for multi-tenant/multi-org Shipit deployments, which is a first-class supported configuration mode (`config/secrets.development.shopify.yml`, `Shipit.github_organizations`). No repository write access, `ApiClient` token, or session cookie is required — only a webhook POST with a correctly-computed HMAC using the secret they legitimately hold for their own org.

### Recommendation
When resolving the target repository/stack in `Handler#stacks`/`#repository_name`, cross-validate that `repository.full_name`'s owner segment matches the `repository_owner` (or `organization.login`) that was used to select and verify the signature in `WebhooksController#verify_signature`. Reject (422) any payload where these two identities disagree, rather than trusting `repository.full_name` unconditionally once any valid signature is found.

### Proof of Concept
1. Deploy Shipit configured for two organizations, `org-attacker` and `org-victim`, each with its own `webhook_secret` (per `config/secrets.development.shopify.yml` schema).
2. Attacker holds `org-attacker`'s legitimate webhook secret (e.g., they manage that GitHub App/org, a documented supported scenario).
3. Attacker crafts a `status` (or `push`) webhook payload:
   ```json
   {
     "sha": "<victim commit sha>",
     "state": "success",
     "context": "ci/required-check",
     "repository": { "owner": { "login": "org-attacker" }, "full_name": "org-victim/victim-repo" }
   }
   ```
4. Attacker signs the raw body with `org-attacker`'s `webhook_secret` and sets `X-Hub-Signature` accordingly; `X-Github-Event: status`.
5. `WebhooksController#verify_signature` computes `repository_owner = "org-attacker"`, fetches `Shipit.github(organization: "org-attacker")`, and the signature verifies successfully (attacker used the correct secret for that org).
6. `Shipit::Webhooks.for_event('status')` dispatches to `StatusHandler`, which looks up `Commit.where(sha: params.sha)` — matching the victim commit belonging to `org-victim/victim-repo` — and calls `commit.create_status_from_github!(params)`, writing a forged "success" status onto a commit the attacker does not control, despite the signature only having been verified against `org-attacker`'s secret.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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
