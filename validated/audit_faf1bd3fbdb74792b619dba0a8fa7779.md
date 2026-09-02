## Analysis

This confirms the exploit is only viable for multi-org installations, where `github_default_organization` is non-nil [1](#0-0) , and `Shipit.github(organization:)` looks up a distinct config, including a distinct `webhook_secret`, per organization key [2](#0-1) . The docs explicitly support multiple orgs each with an optional (`nil`) `webhook_secret` [3](#0-2) .

### Title
Webhook signature verification keys off `repository.owner.login`/`organization.login` while event handlers act on `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In multi-GitHub-App deployments, `WebhooksController#verify_signature` selects which organization's `webhook_secret` to check the `X-Hub-Signature` against using `repository_owner`, taken from `params.dig('repository', 'owner', 'login')` (or `organization.login`) [4](#0-3) . Once verification passes, `create` dispatches the *entire* JSON body, unmodified, to the event handlers [5](#0-4) , which instead resolve the actual `Repository`/`Stack` to act on using `payload.dig('repository', 'full_name')` [6](#0-5) . Nothing binds these two fields together.

### Finding Description
The binding that should hold is: `organization credential used to authenticate == organization/repository actually written to`. Instead:
- Authentication path: `Shipit.github(organization: repository_owner)` where `repository_owner` comes from `repository.owner.login`/`organization.login` [7](#0-6) , and `verify_webhook_signature` trivially returns `true` when that organization's config has no `webhook_secret` configured [8](#0-7) .
- Execution path: handlers such as `PushHandler`/`StatusHandler`/PR handlers resolve the target repository via `Repository.from_github_repo_name(payload.dig('repository', 'full_name'))`, a completely separate field of the same JSON body [6](#0-5) , and this repository's `owner` is independently used to select `stacks`/sync jobs [9](#0-8) .

Because `repository.owner.login` and `repository.full_name` are never cross-checked, an attacker who controls (or has been granted) an organization configured in Shipit's `github:` secrets with no `webhook_secret` set — an explicitly documented, supported configuration (`webhook_secret: # nil`) [3](#0-2)  — can send a raw POST to `/webhooks` with `repository.owner.login`/`organization.login` set to their own (secret-less) org so `verify_signature` passes unconditionally, while setting `repository.full_name` to any other organization/repository tracked by the same Shipit instance. The handler will then act on the victim's `full_name`-resolved `Stack`, e.g. queueing `GithubSyncJob` for a push, injecting a fabricated commit `Status` via `StatusHandler`, or driving pull-request/review-stack lifecycle transitions (`archive!`, `unarchive!`) via the `PullRequest::*` handlers, for a repository the attacker's org has no relationship to at all.

### Impact Explanation
This crosses the "organization that authenticated versus the repository that is written" boundary called out explicitly in scope. It allows unprivileged forgery of GitHub webhook events (push syncs, commit statuses, PR/review-stack state, team membership changes) against arbitrary repositories/stacks managed by the same Shipit instance, without possessing the victim organization's `webhook_secret`, GitHub App credentials, or any Shipit session/API token — qualifying as an unauthorized deploy-trigger/state-manipulation path (cross-repository writes).

### Likelihood Explanation
Requires a multi-organization Shipit configuration where at least one configured GitHub organization does not set `webhook_secret` (an explicitly documented, supported option) [3](#0-2) . Given that setup, exploitation requires only crafting and posting an unauthenticated HTTP request to the public `/webhooks` endpoint with mismatched `repository.owner.login`/`repository.full_name` fields — no cryptographic material or privileged access needed for the secret-less organization.

### Recommendation
In `WebhooksController#verify_signature`, derive the signing/verification organization from the same field used by handlers to resolve the target repository (`repository.full_name`'s owner segment), or explicitly reject payloads where `repository.owner.login` does not match the owner encoded in `repository.full_name`. Additionally, consider disallowing (or warning strongly against) organizations configured without a `webhook_secret` when multiple organizations are configured, since a single secret-less org currently allows signature bypass for that org's identity, which can then be leveraged against any other tracked repository.

### Proof of Concept
1. Configure Shipit with two organizations: `orgA` (attacker-influenced, `webhook_secret: nil`) and `orgB` (victim, `webhook_secret: <secret>`), per the documented multi-org schema [3](#0-2) .
2. POST to `/webhooks` with header `X-Github-Event: push`, no valid `X-Hub-Signature` needed, and body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/victim-repo" }
}
```
3. `verify_signature` resolves `repository_owner` to `orgA`, `Shipit.github(organization: "orgA").verify_webhook_signature` returns `true` because `orgA` has no `webhook_secret` [8](#0-7) .
4. `PushHandler` then resolves `stacks` from `payload.dig('repository','full_name')` == `"orgB/victim-repo"` [6](#0-5)  and enqueues `stack.sync_github(expected_head_sha: params.after)` for `orgB`'s stack [10](#0-9)  — a forged, unauthenticated cross-organization action.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
