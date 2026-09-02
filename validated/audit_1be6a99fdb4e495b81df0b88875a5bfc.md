### Title
Cross-organization webhook forgery via `repository.owner.login`-selected secret vs `repository.full_name`-addressed stack - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
When Shipit is configured with per-organization GitHub Apps (the multi-org `secrets.yml` schema), `WebhooksController#verify_signature` selects which `webhook_secret` to HMAC-verify a webhook against based on `repository.owner.login` (or `organization.login`) taken from the **unverified** JSON body, while the event handlers that subsequently act on that same body address the target `Stack`/`Repository` using the *separate* `repository.full_name` field. Nothing ties the verified organization identity to the "owner" segment encoded in `full_name`, so a party who legitimately controls the webhook secret for *one* configured organization can forge a payload whose `owner.login` matches their own org (so it authenticates against their own secret) while `full_name` names a completely different, victim organization's repository.

### Finding Description
`Shipit.github(organization:)` looks up a distinct `GitHubApp`/`webhook_secret` per configured organization [1](#0-0) . The webhook signature check derives that organization purely from the raw, unauthenticated payload: [2](#0-1) 

`repository_owner` is read straight from `params.dig('repository','owner','login')` [3](#0-2)  and is used only to pick which secret to verify the HMAC against. Once `verify_webhook_signature` passes, `params` is handed unmodified to every registered handler [4](#0-3) .

Handlers, however, resolve the target repository/stack from a *different* field in the same body — `repository.full_name` — via `Repository.from_github_repo_name`: [5](#0-4) [6](#0-5) [7](#0-6) 

Because the HMAC covers the *entire* raw request body, an attacker cannot alter a payload signed by someone else. But they don't need to: if they are the legitimate administrator/holder of the webhook secret for **any one** configured organization (`org-A`) in a Shipit instance that hosts multiple organizations (the documented multi-org config: `docs/setup.md` lines around the multi-org `secrets.yml` schema, and `config/secrets.development.example.yml` lines 18-30 showing the multiple-organization schema), they can construct and self-sign an arbitrary JSON body where:
- `repository.owner.login` = `"org-A"` (so `verify_signature` looks up and validates against `org-A`'s own webhook secret, which the attacker legitimately possesses),
- `repository.full_name` = `"org-B/victim-repo"` (any other tracked repository in the same Shipit instance).

`verify_signature` only checks that the payload was signed by *some* known org's secret — it never asserts that the org used for verification matches the owner encoded in `full_name`. The handler (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, membership handlers, etc.) then acts on `org-B/victim-repo` using attacker-supplied fields (e.g., `after` SHA for a push event), causing `Stack#sync_github` to run for the victim's stack with an attacker-chosen expected head SHA, or forging `status`/`check_suite` events for the victim's commits.

This breaks exactly the described binding: **an organization that authenticated (org-A, via its own webhook secret) versus the repository that is written (org-B's repository/stack, addressed via `full_name`)**.

### Impact Explanation
This allows an entity that only has legitimate access to one tenant's/organization's own webhook secret (not the target org's secret, not any Shipit `ApiClient` token, not the GitHub App private key) to forge GitHub events attributed to a different organization's repositories tracked by the same Shipit instance. Concretely this can:
- Force `GithubSyncJob`/`sync_github` to run for a victim stack with an attacker-chosen `expected_head_sha` (`PushHandler#process`), influencing what Shipit believes is deployable/at HEAD for that stack.
- Inject forged commit `status` / `check_suite` records for a victim's commits, which the merge queue and CI-gating logic (`MergeRequest#any_status_checks_failed?`, `StatusChecker`) consult to decide whether a merge/deploy is allowed — i.e. an attacker-controlled organization can manipulate CI-status trust used to gate an **unauthorized deploy or merge** on another organization's stack.

This matches the "High"/"Critical" impact bar: escalation into cross-organization control over deploy/merge gating without holding the victim organization's credentials.

### Likelihood Explanation
Requires only that the Shipit deployment is configured with the multi-org `github:` schema (explicitly documented as a supported configuration) and that the attacker administers (or has compromised) any one of the configured organizations' GitHub App/webhook secret — not the victim's. No Shipit session, `ApiClient` token, `api_clients_secret`, or GitHub App private key is needed. This is a realistic scenario for shared/multi-tenant Shipit installations serving several GitHub organizations.

### Recommendation
In `WebhooksController#verify_signature`/handlers, cross-check that the organization used to select and validate the webhook secret (`repository.owner.login`/`organization.login`) matches the owner segment of `repository.full_name` (and any other repository identifiers used by handlers) before dispatching to handlers; reject the webhook otherwise.

### Proof of Concept
1. Deploy Shipit configured with two organizations, `org-A` and `org-B`, each with its own `webhook_secret` (per the documented multi-org schema).
2. As the legitimate owner of `org-A`'s GitHub App, craft a `push` event JSON body:
   ```json
   {
     "ref": "refs/heads/main",
     "after": "<attacker-chosen sha>",
     "repository": { "owner": { "login": "org-A" }, "full_name": "org-B/victim-repo" }
   }
   ```
3. Compute `X-Hub-Signature` using `org-A`'s own `webhook_secret` (`OpenSSL::HMAC.hexdigest('sha1', org_a_secret, body)`), which the attacker legitimately controls.
4. POST to `/github/webhooks` with header `X-Github-Event: push`. `verify_signature` resolves `repository_owner` = `"org-A"`, fetches `org-A`'s app/secret, and the signature validates successfully.
5. `PushHandler#process` resolves `stacks` via `repository.full_name` = `"org-B/victim-repo"` and invokes `stack.sync_github(expected_head_sha: "<attacker-chosen sha>")` on the victim's stack — a stack the attacker has no legitimate access to.

### Citations

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
