### Title
Webhook signature check keys off `repository.owner.login` while every handler acts on the unrelated `repository.full_name` field, letting a webhook signed for one configured GitHub organization drive actions on any other organization's stacks - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which organization's `webhook_secret` to validate the `X-Hub-Signature` against by reading `params.dig('repository', 'owner', 'login')` (falling back to `organization.login`), i.e. it authenticates the request against *one* organization's secret. But every webhook handler (`Shipit::Webhooks::Handlers::Handler#repository_name`, and each `PullRequest::*Handler#repository`) resolves the target repository/stack from a *different* field of the same JSON body, `repository.full_name`, via `Repository.from_github_repo_name`. Nothing ties these two fields together after the signature check passes. [1](#0-0) [2](#0-1) 

### Finding Description
Shipit supports a multi-organization configuration where each GitHub org has its own `app_id`, `installation_id`, `webhook_secret`, and `oauth` block (`docs/setup.md` "Using Multiple Github Applications"), each surfaced through `Shipit.github(organization:)` / `Shipit.github_app_config` in `lib/shipit.rb`. [3](#0-2) 

For every inbound webhook, `WebhooksController#verify_signature` computes `repository_owner` from the payload and asks `Shipit.github(organization: repository_owner)` for that organization's `GitHubApp`, then verifies the raw body's HMAC against *that org's* `webhook_secret`: [4](#0-3) 

Crucially, `GitHubApp#verify_webhook_signature` treats an unset `webhook_secret` as "always verified": [5](#0-4) 

The example multi-org config explicitly shows `webhook_secret: # nil` as a normal, supported per-organization value: [6](#0-5) [7](#0-6) 

So in any deployment where at least one configured organization has no `webhook_secret` set (a documented, valid configuration), `verify_signature` becomes a no-op for requests that merely claim `repository.owner.login` = that unsecured org — no valid GitHub signature is required at all.

After this bypass, `WebhooksController#create` dispatches the parsed JSON straight to the registered handlers: [8](#0-7) 

Every handler, however, determines *which* repository/stack to mutate using `repository.full_name`, a field completely independent from `repository.owner.login`: [2](#0-1) [9](#0-8) [10](#0-9) 

`Repository.from_github_repo_name` simply splits this attacker-controlled string on `/` and looks up any repository row by owner/name, with no relation to the organization used for signature verification: [11](#0-10) 

This is exactly the "organization authenticated vs. repository written" binding break: the equality that should hold is `organization_used_to_verify_signature == owner(repository_acted_upon)`, but the engine never enforces it. An unprivileged attacker who merely knows (or guesses) that some configured org in a multi-org Shipit instance has no `webhook_secret` can send a POST to `/github_hooks` with:
- `X-Github-Event: push` (or `pull_request`, `status`, `check_suite`, `membership`)
- `repository.owner.login` = the org with no secret (so `verify_signature` passes unconditionally)
- `repository.full_name` = `"victim-org/some-existing-repo"` (any repository actually configured in Shipit, belonging to a *different*, secured organization)

`verify_signature` resolves `Shipit.github(organization: "org-with-no-secret")`, calls `verify_webhook_signature` on it, which returns `true` because `webhook_secret` is blank — regardless of the (missing or garbage) `X-Hub-Signature` header. The request is then routed to `Shipit::Webhooks::Handlers::PushHandler` (or others), which resolves `stacks` from `payload.dig('repository','full_name')` = `"victim-org/some-existing-repo"`, completely ignoring which org's key validated the request.

### Impact Explanation
Depending on handler and event type this enables an unauthenticated deploy/rollback trigger, PR/review-stack archival, forced commit-status writes, or membership/team mutation against a repository/stack belonging to an organization the attacker was never authenticated for — i.e. an unauthorized deploy/action across organizational trust boundaries, satisfying the "cross-repository writes / unauthorized deploy" impact bar. For example `PushHandler#process` calls `stack.sync_github(expected_head_sha: params.after)` for every not-archived stack matching the forged `full_name`+branch, and `PullRequest::ClosedHandler`/`LabeledHandler` archive or unarchive review stacks — all without ever validating a signature tied to the target org. [12](#0-11) 

### Likelihood Explanation
This requires a multi-organization Shipit deployment where at least one configured org has an empty `webhook_secret` — an explicitly documented and supported configuration shape (shown as the default in `config/secrets.development.example.yml` and `docs/setup.md`). Any operator following the documented multi-org setup and forgetting to set a webhook secret on one org (or leaving it blank for a low-value/test org) creates a bypass usable against every other org's repositories, not just the unsecured one. No credentials, GitHub App keys, or session are required — only knowledge of the vulnerable org's login name and the target repository's `owner/name`, both of which are typically public.

### Recommendation
`verify_signature` and the handlers must agree on which organization is authenticated. At minimum:
1. Bind signature verification to the organization actually referenced by `repository.full_name` (or verify both `repository.owner.login` and `repository.full_name`'s owner match before dispatch), not just `repository.owner.login`/`organization.login`.
2. Do not silently treat an absent `webhook_secret` as "always verified" for organizations mapped from attacker-controlled payload data; require an explicit opt-in (e.g., only skip verification for the single-org "no multi-org config" legacy mode, never per-org in a multi-org config).
3. After signature verification, re-derive the acted-upon repository strictly from the same organization key that produced a valid signature, rejecting any event whose `repository.full_name` owner differs from the verified organization.

### Proof of Concept
Given a `config/secrets.yml` such as:
```yaml
production:
  github:
    attacker-org:
      app_id: 1
      installation_id: 1
      private_key: ...
      webhook_secret: # not set
    victim-org:
      app_id: 2
      installation_id: 2
      private_key: ...
      webhook_secret: real-secret
```
and a Shipit stack already configured for `victim-org/prod-app`, an attacker sends:
```
POST /github_hooks
X-Github-Event: push
(no valid X-Hub-Signature required)

{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha-that-exists-in-victim-org/prod-app>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/prod-app"
  }
}
```
`verify_signature` resolves `Shipit.github(organization: "attacker-org")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally. `PushHandler#process` then looks up `Repository.from_github_repo_name("victim-org/prod-app")` and triggers `stack.sync_github(expected_head_sha: ...)` on the real `victim-org` stack, without ever presenting a signature valid for `victim-org`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L65-68)
```ruby
          def repository
            @repository ||= Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
                            Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
