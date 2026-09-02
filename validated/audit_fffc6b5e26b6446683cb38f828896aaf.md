Confirmed: `Shipit.github_organizations` supports multi-tenant configs where each organization key in `secrets.github` has its own `webhook_secret`, and `github_app_config(organization)` looks up config by organization name only [1](#0-0) . `WebhooksController#verify_signature` selects the `GitHubApp` (and thus the HMAC secret) purely by `repository_owner`, derived as `params.dig('repository','owner','login') || params.dig('organization','login')` [2](#0-1) [3](#0-2) . But once the signature passes, `create` hands the *entire raw JSON payload* to every registered handler [4](#0-3) , and the base `Handler` class resolves the target repository independently via `payload.dig('repository', 'full_name')` [5](#0-4) , which is also what `PushHandler` uses to enqueue a sync against matching stacks [6](#0-5) .

### Title
Cross-organization webhook forgery via mismatched signature-selection key and repository-resolution key - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
In a multi-tenant deployment (`Shipit.github_organizations` configured with multiple GitHub orgs, each with its own `webhook_secret`), `WebhooksController#verify_signature` picks which organization's HMAC secret to validate the request against using `repository.owner.login` (or `organization.login`) from the attacker-controlled JSON body. Once verified, the very same body is dispatched unmodified to event handlers, which independently derive the repository to act on from `repository.full_name` in that same body. Nothing enforces that the owner login used for signature selection matches the owner encoded in `full_name`.

### Finding Description
`verify_signature` fetches `github_app = Shipit.github(organization: repository_owner)` and validates `X-Hub-Signature` against that org's `webhook_secret` [2](#0-1) . `repository_owner` is read from the payload body itself: `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [3](#0-2) . Each organization has an independent `webhook_secret` in `secrets.github`, looked up by `github_app_config(organization)` [7](#0-6) .

The equality that should hold is: *organization whose secret authenticated the request* == *organization of the repository the handlers actually act on*. Because both values are read from attacker-supplied JSON fields (`repository.owner.login` vs `repository.full_name`), an attacker who knows/controls the `webhook_secret` for their own onboarded organization (`org-attacker`) can craft a payload where `repository.owner.login` = `org-attacker` (used only for HMAC selection) while `repository.full_name` = `org-victim/target-repo` (used for actual repository/stack resolution in `Handler#repository_name` and `PushHandler#process`) [5](#0-4) [6](#0-5) . The signature check succeeds against `org-attacker`'s secret, and `create` still runs all handlers against the full, unmodified body [4](#0-3) .

### Impact Explanation
This breaks the binding between "organization that authenticated" and "repository that is written." A `push` event forged this way enqueues `stack.sync_github(expected_head_sha:)` on any stack whose repository matches `org-victim/target-repo`, forcing an out-of-band GitHub sync against `expected_head_sha` supplied by the attacker [6](#0-5) . `pull_request` handlers similarly resolve `Repository.from_github_repo_name(params.repository.full_name)` to archive/unarchive review stacks in a repository the attacker does not own [8](#0-7) . This can trigger unauthorized deploy-pipeline state changes (sync/archive/unarchive) on a repository the requester has no legitimate relationship with, satisfying the "unauthorized deploy/rollback" class of impact once chained with downstream automatic-deploy configuration.

### Likelihood Explanation
Requires (a) a multi-tenant Shipit instance with more than one organization configured under `secrets.github`, and (b) the attacker controlling/knowing the `webhook_secret` of at least one onboarded organization (e.g., they administer their own org's GitHub App/webhook settings, which is normal for a org-admin onboarding their own repos, not requiring any Shipit session or `ApiClient` token). No other privilege is required to hit `POST /webhooks`.

### Recommendation
Verify that the organization used to select the HMAC secret is the same organization actually encoded in `repository.full_name` (and any other repository fields the dispatched handlers will read) before running handlers — e.g., derive `repository_owner` from `repository.full_name.split('/').first` consistently, or re-check owner/org equality between the two payload paths after signature validation, and reject the request if they diverge.

### Proof of Concept
1. Onboard/administer `org-attacker` in the target Shipit instance's `secrets.github`, giving you its `webhook_secret`.
2. Craft a `push` webhook body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker chosen sha>",
  "repository": { "owner": { "login": "org-attacker" }, "full_name": "org-victim/target-repo" }
}
```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(webhook_secret_of_org-attacker, raw_body)>`.
4. `POST /webhooks` with `X-Github-Event: push` and the above signature — `verify_signature` resolves and validates against `org-attacker`'s secret and passes [2](#0-1) .
5. `PushHandler#process` resolves stacks via `full_name` = `org-victim/target-repo` and enqueues `sync_github(expected_head_sha: "<attacker chosen sha>")` on it [6](#0-5) , despite the request never having been authenticated for `org-victim`.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
