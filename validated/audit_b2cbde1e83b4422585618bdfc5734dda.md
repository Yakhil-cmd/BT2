### Title
Webhook signature verification is keyed by an unauthenticated payload field, allowing cross-organization forgery of commit statuses and sync events - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate the HMAC signature against using `repository_owner`, a value read directly out of the *unauthenticated* JSON body (`params.dig('repository', 'owner', 'login')` or `organization.login`). Downstream event handlers, however, resolve the target `Stack`/`Commit`/`Repository` using a *different* field of the same untrusted body (`repository.full_name`, or bare `sha`). Nothing binds these two fields together, so a payload can be signed with the secret of Org A (the value used for verification) while acting on a repository belonging to Org B (the value used to locate records to write).

### Finding Description
The engine supports multiple configured GitHub Apps/organizations, each with its own `webhook_secret` [1](#0-0) . Signature verification picks the app config purely from the request body: [2](#0-1) 

`repository_owner` is derived like this: [3](#0-2) 

`Shipit.github(organization:)` looks up the app config by downcasing this attacker-controlled string and raises only if the organization name is *unknown* to the instance — it does not verify that this organization actually owns the repository referenced elsewhere in the payload [4](#0-3) .

Once the HMAC check passes (using Org A's secret), `Shipit::Webhooks.for_event(event)` dispatches the full raw `params` hash to handlers [5](#0-4) . Handlers derive the actual record(s) to act on from **other** fields of the same body, independent of `repository_owner`:

- Generic handler base resolves the repository/stacks scope from `repository.full_name`, not `repository.owner.login`: [6](#0-5) 
- `StatusHandler` looks commits up **only by `sha`** (no repository/owner check at all) and writes a status record directly from attacker-supplied fields: [7](#0-6) 
- `PushHandler` resolves stacks via `repository_name` from the base `Handler#stacks` (i.e., `repository.full_name`) and triggers a GitHub sync job using the payload's `after` SHA: [8](#0-7) 

Because the field used to select the verifying secret (`repository.owner.login`) is decoupled from the field(s) used to select the acted-upon repository/commit (`repository.full_name`, bare `sha`), an attacker who possesses (or can obtain, e.g. through a legitimately-owned Org A configured on the same Shipit instance) a valid `webhook_secret` for Org A can craft a payload where `repository.owner.login = "OrgA"` (making the signature valid) but `repository.full_name = "OrgB/victim-repo"` or an arbitrary `sha` belonging to a completely different, unaffiliated stack. The signature check passes because it only validates against Org A's secret, and the handler then writes data (commit statuses, triggers `GithubSyncJob`, etc.) against Org B's stack.

This breaks exactly the binding described in the rules as: *"an organization that authenticated versus the repository that is written."*

### Impact Explanation
The most severe consequence is via `StatusHandler`, which creates/updates a `Commit::Status` for **any** `sha` matching **any** stack tracked by the Shipit instance, without any repository/owner correlation at all [7](#0-6) . Status/commit-status data feeds directly into required-CI-status checks that gate deploys and merges (`deploy_spec` `ci.require`/`merge.require`) [9](#0-8) . An attacker who only controls the webhook secret of one organization on a multi-org Shipit instance can forge a "success" status for a commit belonging to an entirely different organization's stack, potentially satisfying CI requirements and enabling an unauthorized deploy — this reaches the "unauthorized deploy" Critical-impact category. It also allows cross-repository writes (forged statuses, spurious sync jobs) for stacks the attacker has no legitimate relationship with, matching the "cross-repository writes" Critical-impact category.

### Likelihood Explanation
Likelihood is highest in installations that configure multiple GitHub organizations behind one Shipit instance (a documented, supported configuration, see `test/dummy/config/secrets_double_github_app.yml`), where a customer/tenant administering Org A's GitHub App only needs to know Org A's own `webhook_secret` (which they legitimately possess, since they configured that app) to forge events against Org B's repositories tracked by the same instance. No repository write access, GitHub token, or Shipit session is required — only knowledge of one configured organization's webhook secret, which the rules explicitly allow as a valid unprivileged starting point relative to a *different* victim organization/repository.

### Recommendation
Bind the verified organization to the repository actually being acted upon: after establishing which org's secret validated the signature, require that `repository.full_name`'s owner segment (or `organization.login`) matches `repository_owner` before dispatching to handlers, and have handlers use the already-verified owner (not a re-derived value from the untrusted body) when resolving the `Stack`/`Repository`/`Commit` to mutate.

### Proof of Concept
1. Configure Shipit with two orgs, `OrgA` and `OrgB`, each with its own `webhook_secret` (as supported by `config/secrets_double_github_app.yml`), and create a stack for a repository under `OrgB`.
2. As an operator who only knows `OrgA`'s `webhook_secret` (e.g., the legitimate admin of `OrgA`'s GitHub App), craft a JSON body for the `status` event:
```json
{
  "sha": "<sha of a commit belonging to OrgB's tracked stack>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "OrgA" } }
}
```
3. Sign the raw body with `OrgA`'s `webhook_secret` using HMAC-SHA1 and send it to `POST /github/webhooks` with `X-Hub-Signature` set accordingly and `X-Github-Event: status`.
4. `verify_signature` calls `Shipit.github(organization: "OrgA")` and successfully verifies the signature against `OrgA`'s secret [10](#0-9) .
5. `StatusHandler#process` matches the commit purely by `sha` (ignoring the `owner`/org used for verification) and creates a "success" status on the `OrgB` commit [7](#0-6) , potentially satisfying `OrgB`'s required CI checks and enabling an unauthorized deploy of `OrgB`'s stack.

### Citations

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/deploy_spec.rb (L194-196)
```ruby
    def required_statuses
      (Array.wrap(config('ci', 'require')) + blocking_statuses).uniq
    end
```
