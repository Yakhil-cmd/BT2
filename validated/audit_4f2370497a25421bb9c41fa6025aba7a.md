### Title
Webhook signature verification is scoped to an attacker-chosen organization while the event payload's `repository.full_name` (used to locate the target `Stack`) is a different, unverified field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App/webhook secret to verify the HMAC signature against by reading `repository.owner.login` (or `organization.login`) straight out of the *unauthenticated* request body, then calls `GitHubApp#verify_webhook_signature`. That method explicitly **bypasses verification and returns `true` when no `webhook_secret` is configured for the resolved organization**: [1](#0-0) 

The organization used to pick the verification secret is not the same value used later to locate and act on a `Stack`/`Repository` — handlers act on `repository.full_name` (or similar fields) inside the same JSON body, which the attacker controls independently of `repository.owner.login`: [2](#0-1) [3](#0-2) [4](#0-3) 

### Finding Description
Shipit supports hosting multiple GitHub organizations/apps in one instance, each with its own `webhook_secret` (some intentionally left blank, as shown in the documented/example configs): [5](#0-4) [6](#0-5) 

`Shipit.github(organization:)` resolves per-organization config, and `GitHubApp#verify_webhook_signature` treats an unset `webhook_secret` as "nothing to verify," returning `true` unconditionally: [7](#0-6) [1](#0-0) 

The controller picks *which* organization's secret to check purely from the attacker-supplied JSON body:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [4](#0-3) 

This breaks the trust binding: "the organization whose secret was used to authenticate the request" ≠ "the repository/stack that the event handlers will actually act on." Since the JSON body is fully attacker-controlled prior to verification, nothing forces `repository.owner.login` (used only to pick the verification key) to correspond to `repository.full_name` (used by `Shipit::Webhooks` handlers to find the target `Repository`/`Stack`). If any organization configured on the instance has no `webhook_secret` set — a state the project's own example configs treat as valid — an attacker can submit a forged, unsigned webhook whose `repository.owner.login` names that unsecured organization while its `repository.full_name`/commit/PR/status fields target a *different*, secured organization's stack. `verify_signature` passes (returns `true`), and `create` then dispatches the forged payload to the real handlers for whatever event type was declared, acting on the spoofed repository/commit/PR/status data: [8](#0-7) 

### Impact Explanation
This allows an unauthenticated, unprivileged attacker to inject forged GitHub webhook events (`push`, `status`, `pull_request`, `check_suite`, `membership`, etc.) against stacks/repositories belonging to a *different*, properly-secured organization, as long as at least one org on the instance has no webhook secret configured. Depending on the event handler reached, this can trigger unauthorized `GithubSyncJob` commit ingestion, forged commit statuses/check runs that gate merges and deploys, forged `pull_request` events that manipulate `MergeRequest`/`review_stack` state, or team/membership manipulation — all without any credential, matching the High-impact category of "escalation into authorization state" or "unauthenticated write of stack/deploy-relevant state."

### Likelihood Explanation
Likelihood depends entirely on deployment configuration: it requires at least one organization in the multi-org `github:` config to have a blank/unset `webhook_secret`. This is a documented, supported configuration pattern (see the example and Shopify-flavored sample secrets files), not a hardened requirement enforced anywhere in code, so it is plausible in real deployments running multiple orgs where some are considered "low risk" and left unsecured. No authentication, token, or write access is needed to exploit it — a bare HTTP POST to `/webhooks` suffices.

### Recommendation
- Require `webhook_secret` to be present for every configured organization at boot/config-validation time, rejecting empty configuration instead of silently allowing bypass in `verify_webhook_signature`.
- Do not let the attacker-supplied payload select which secret is used for verification; instead, verify against the secret of the organization that actually owns the `Stack`/`Repository` being modified (resolved server-side from `full_name`), and cross-check that this matches `repository.owner.login`/`organization.login` before dispatching to handlers.
- Fail closed: if `verify_webhook_signature` cannot find a real secret for the resolved organization, return `false`/422 rather than `true`.

### Proof of Concept
1. Configure Shipit with two organizations: `secured-org` (with `webhook_secret` set) and `open-org` (with `webhook_secret` left blank/nil, e.g. as in `config/secrets.development.example.yml`).
2. Send an unsigned POST to `/webhooks` with header `X-Github-Event: status` and a JSON body:
```json
{
  "organization": { "login": "open-org" },
  "repository": { "owner": { "login": "open-org" }, "full_name": "secured-org/secured-repo" },
  "sha": "<commit sha under secured-org/secured-repo>",
  "state": "success",
  "context": "ci/required-check"
}
```
3. `verify_signature` resolves `Shipit.github(organization: "open-org")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` without checking any HMAC.
4. `create` dispatches the payload to the `status` handler, which records a forged successful status against `secured-org/secured-repo`'s commit — potentially satisfying merge/deploy required-status checks — without ever presenting a valid signature for `secured-org`. [9](#0-8) [10](#0-9)

### Citations

**File:** lib/shipit/github_app.rb (L44-83)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]

      oauth = (@config[:oauth] || {}).with_indifferent_access
      @oauth_id = oauth[:id]
      @oauth_secret = oauth[:secret]
      @oauth_teams = Array.wrap(oauth[:teams])
    end

    def login
      raise NotImplementedError, 'Handle App login / user'
    end

    def api
      client = (Thread.current[:github_client] ||= new_client(access_token: token))
      client.access_token = token if client.access_token != token
      client
    end

    def api_status
      conn = Faraday.new(url: 'https://www.githubstatus.com')
      response = conn.get('/api/v2/components.json')
      parsed = JSON.parse(response.body, symbolize_names: true)
      parsed[:components].find { |c| c[:id] == API_STATUS_ID }
    end

    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L1-64)
```ruby
# frozen_string_literal: true

module Shipit
  class WebhooksController < ActionController::Base
    skip_before_action :verify_authenticity_token, raise: false
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature

    respond_to :json

    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end

    private

    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
    end

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
  end
end
```

**File:** config/secrets.development.example.yml (L8-16)
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
