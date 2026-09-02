Confirmed root cause chain. The webhook signature verification path is:

`WebhooksController#verify_signature` picks the GitHub App/secret using `repository_owner`, which reads `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` — a field taken directly from the unauthenticated request body [1](#0-0) . That selects the `GitHubApp` instance via `Shipit.github(organization: repository_owner)`, whose `webhook_secret` is then used in `verify_webhook_signature` [2](#0-1) . Critically, if that organization's `webhook_secret` is unset/nil, `verify_webhook_signature` returns `true` unconditionally [3](#0-2) .

Meanwhile, every webhook `Handler` resolves the actual `Stack`/`Repository` it writes to via `payload.dig('repository', 'full_name')`, an entirely separate field from the one used for org/secret selection [4](#0-3) . Handlers like `PushHandler` then trigger `stack.sync_github` for whatever stack matches that `full_name` [5](#0-4) .

Since Shipit explicitly supports multi-organization configs where each org has its own independent `webhook_secret` [6](#0-5) , and the docs show this is a normal, documented setup [7](#0-6) , this is a real in-scope configuration, not a misuse of the engine.

### Title
Webhook org used for signature-secret selection is not bound to the repository the payload writes to, allowing cross-org webhook forgery when any configured org has no `webhook_secret` - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/secret to validate a webhook's HMAC signature against using `repository.owner.login` (or `organization.login`) taken straight from the unauthenticated JSON body. Webhook handlers, however, resolve the `Stack`/`Repository` they act on using `repository.full_name` — a different field from the same attacker-controlled payload. Nothing binds these two fields to the same value. If any organization configured in `Shipit.github` (multi-org setup) has no `webhook_secret` configured, `verify_webhook_signature` returns `true` unconditionally for that org, so an attacker can submit an unsigned/arbitrary-signature webhook claiming `repository.owner.login` = that secretless org while setting `repository.full_name` to a completely different, secret-protected organization's repository, and have Shipit process it as authentic.

### Finding Description
- `verify_signature` computes `repository_owner` from `params.dig('repository','owner','login') || params.dig('organization','login')` [8](#0-7) .
- It uses that value to select the verifying `GitHubApp`: `Shipit.github(organization: repository_owner)` [9](#0-8) .
- `GitHubApp#verify_webhook_signature` short-circuits to `true` when `webhook_secret` is blank: `return true unless webhook_secret` [2](#0-1) .
- `Shipit.github` supports per-organization configs, each with its own independent `webhook_secret`, which is a documented, supported deployment shape [6](#0-5) [7](#0-6) .
- Once past `verify_signature`, `WebhooksController#create` dispatches the *entire raw payload* to handlers: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [10](#0-9) .
- Every `Handler` (e.g. `PushHandler`) resolves the target `Stack` via `payload.dig('repository', 'full_name')`, not via `repository.owner.login` [4](#0-3) [5](#0-4) .

The binding that breaks is: **organization authenticated (used to pick the webhook secret) == repository actually written (used by handlers to locate the Stack)**. An attacker fully controls both `repository.owner.login`/`organization.login` and `repository.full_name` in the same POST body, so these two values can be made to diverge.

### Impact Explanation
Given a realistic multi-org Shipit deployment (explicitly documented and supported) where at least one configured organization has no `webhook_secret` set (the example configs in this repo, e.g. `test/dummy/config/secrets_double_github_app.yml`, ship with `webhook_secret: # nil` for both orgs), an unauthenticated attacker can:
1. Set `organization.login` (or `repository.owner.login`) to the secretless org so `verify_signature` passes unconditionally.
2. Set `repository.full_name` to a *different*, secret-protected organization's tracked repository.
3. Trigger handlers (`push`, `status`, `check_suite`, `membership`, `pull_request`, etc.) against that other org's `Stack`, e.g. forcing `GithubSyncJob` to run with an attacker-chosen `expected_head_sha`, or injecting fake commit statuses/deployable statuses that the merge queue and continuous-deployment logic trust to gate/trigger an unauthorized deploy.

This crosses the "unauthorized deploy/rollback" and "cross-repository writes" impact bar defined in scope, since it lets an attacker inject trusted-looking GitHub state (commit statuses, sync events, membership changes) into a stack belonging to an organization whose webhook secret they never possessed.

### Likelihood Explanation
Requires: (a) a multi-org Shipit deployment (explicitly documented/supported feature), and (b) at least one configured organization lacking a `webhook_secret`. Both conditions are plausible in real deployments — `webhook_secret` is documented as optional per-org, and the shipped example/dummy multi-org configs in this codebase default it to nil. No credentials, session, or GitHub App private key are needed; the attacker only needs to know (or guess) the name of a secretless configured organization and the `full_name` of a target repository/stack, both discoverable from Shipit's public UI/URLs.

### Recommendation
Bind signature verification to the same repository identity the handlers act on: derive the verifying organization strictly from `repository.full_name`'s owner segment (not from `organization.login`, which the handlers never consult), reject webhooks where `repository.owner.login` and `repository.full_name`'s owner disagree, and stop treating a missing `webhook_secret` as an implicit "always trust" for any organization — require secret configuration for orgs that expect to be webhook-verified, or fail closed instead of returning `true`.

### Proof of Concept
1. Configure Shipit with two orgs: `victim-org` (webhook_secret set, has a tracked stack `victim-org/app`) and `attacker-org` (no `webhook_secret` configured) — a valid supported multi-org setup per `docs/setup.md`.
2. POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "organization": { "login": "attacker-org" },
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/app" },
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>"
}
```
No `X-Hub-Signature` header (or any garbage value) is required.
3. `verify_signature` calls `Shipit.github(organization: "attacker-org")`, whose `webhook_secret` is nil, so `verify_webhook_signature` returns `true` and the request passes [2](#0-1) .
4. `PushHandler` resolves `stacks` via `payload.dig('repository','full_name')` = `"victim-org/app"`, matching the real `victim-org` stack, and calls `stack.sync_github(expected_head_sha: "<attacker-chosen sha>")` [11](#0-10) , forging a sync event for `victim-org`'s stack despite having authenticated with `attacker-org`'s (absent) secret.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-27)
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

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
    end
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
