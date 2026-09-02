### Title
Webhook signature verification keys off `repository.owner.login`, while event handlers act on `repository.full_name` — cross-organization forged webhooks in multi-org installs - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In a multi-organization Shipit installation, `WebhooksController#verify_signature` selects which `GitHubApp` (and therefore which `webhook_secret`) to validate a webhook against using `repository.owner.login` (or `organization.login`) pulled straight out of the untrusted, attacker-suppliable JSON body. The event handlers that actually act on the payload (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, etc.) instead resolve the target using `repository.full_name` via `Handler#repository_name`/`Repository.from_github_repo_name`. Because these two fields are read independently from the same untrusted body and are never cross-checked for consistency, an attacker who legitimately controls a webhook secret for one organization configured in Shipit can forge a signature that Shipit will accept for a payload whose `repository.full_name` points at a *different* organization's repository tracked by the same Shipit instance. This is directly analogous to the Moonwell finding's pattern of one privileged identity's authorization being used to affect a different, unauthorized target — here, "the organization that authenticated" (`repository.owner.login`, used for `verify_webhook_signature`) is decoupled from "the repository that is written" (`repository.full_name`, used to find `Stack`/`Commit` records).

### Finding Description
`WebhooksController#verify_signature` computes `repository_owner` from the payload and uses it purely to pick the `GitHubApp`/secret for HMAC verification: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` resolves per-organization `webhook_secret`/`GitHubApp` config from `secrets.github`, supporting multiple, independently configured GitHub App installations (multiple organizations) in one Shipit instance: [3](#0-2) 

Once signature verification passes, `WebhooksController#create` dispatches the *entire raw payload* — including the same JSON body — to the registered handlers: [4](#0-3) 

The base `Handler` resolves the actual `Stack`/repository target from `repository.full_name`, a separate field from `repository.owner.login`: [5](#0-4) 

`PushHandler` uses that repository/stack resolution to trigger `stack.sync_github`, and `StatusHandler` writes a `Status` for any `Commit` matching `params.sha` regardless of which org actually owns that commit's stack: [6](#0-5) [7](#0-6) 

Nothing in this chain asserts that `repository.owner.login` (the field used to select which secret validates the signature) matches `repository.full_name`'s owner segment (the field that determines which `Stack`/`Commit` records get mutated). Shipit explicitly documents and supports installing multiple independent GitHub App configurations, each with its own `webhook_secret`, in a single instance: [8](#0-7) 

### Impact Explanation
An attacker who is a legitimate GitHub App administrator for one organization tracked by a shared Shipit instance (and therefore knows/controls that organization's `webhook_secret`) can forge a signed webhook whose `X-Hub-Signature` validates against their own org's secret while `repository.full_name` in the body names a repository belonging to a *different* organization tracked by the same Shipit instance. This lets them:
- Inject a forged `status` webhook (`StatusHandler`) to mark any commit — including ones belonging to another org's stack — as CI-passing (`create_status_from_github!`), which can satisfy `ci.require` checks and unblock/trigger an unauthorized deploy.
- Inject a forged `push` webhook (`PushHandler`) to force `stack.sync_github` against another org's stack.

This crosses a repository/organization trust boundary using credentials the attacker legitimately possesses only for a different, unrelated repository — matching the "cross-repository writes" / "unauthorized deploy" criteria for Critical impact.

### Likelihood Explanation
This only manifests when a single Shipit installation is configured with multiple GitHub organizations (a documented, supported configuration in `docs/setup.md`), and requires the attacker to be a legitimate administrator/owner of at least one of those organizations' GitHub App installations (so they possess that org's `webhook_secret`). This is a real, if narrower, deployment scenario rather than a purely theoretical one, since Shipit is explicitly designed to support multi-org installs sharing one instance and one set of tracked repositories/stacks.

### Recommendation
When verifying webhook signatures and dispatching to handlers, cross-validate that the organization/owner used to select the signing secret matches the owner embedded in `repository.full_name` (and any other identity fields, e.g., `organization.login` for membership events) before processing. Reject the webhook if these fields disagree, and consider deriving the target `Stack`/`Repository` strictly from the same owner value that was used for signature verification rather than re-deriving it independently later in the handler chain.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` and `OrgB`, each with distinct GitHub Apps/`webhook_secret`s, tracking `OrgA/repo1` and `OrgB/repo2` respectively (per `docs/setup.md` multi-org setup).
2. As a legitimate admin of `OrgA`'s GitHub App, compute a valid HMAC signature over a crafted JSON body using `OrgA`'s `webhook_secret`, where:
   - `event: status`
   - `repository.owner.login: "OrgA"` (used by `WebhooksController#repository_owner` to select `OrgA`'s secret for verification)
   - `sha`, `state: success`, matching a commit that actually belongs to `OrgB/repo2`'s stack (attacker can learn shas from public commit history/CI or the Shipit UI if visible)
3. POST this payload with the computed signature to `/webhooks`.
4. `verify_signature` validates successfully against `OrgA`'s secret; `Webhooks.for_event('status')` then runs `StatusHandler`, which looks up `Commit.where(sha: params.sha)` — independent of `repository.owner.login` — and creates a passing `Status` on `OrgB`'s commit, potentially satisfying `ci.require` and enabling an unauthorized deploy on `OrgB/repo2`'s stack.

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

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
```
