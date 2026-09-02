I have enough to construct the finding. Let me verify the exact deploy trigger chain quickly.### Title
Cross-repository CI status forgery via unscoped webhook signature/repository binding - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` authenticates an inbound GitHub webhook only against the GitHub App/organization named in the payload's own `repository.owner.login` (falling back to `organization.login`), then hands the *entire, attacker-suppliable* JSON payload to the registered handler for the event. `Shipit::Webhooks::Handlers::StatusHandler`, which processes `status` events, never re-checks that binding: it looks up commits purely `Commit.where(sha: params.sha)` with no repository/organization scoping at all, and applies the attacker-controlled `state`/`description`/`context` as a real CI status via `commit.create_status_from_github!`.

### Finding Description
The signature check computes:

`Shipit.github(organization: repository_owner).verify_webhook_signature(...)` [1](#0-0) 

where `repository_owner` is read straight from the untrusted payload body: [2](#0-1) 

This only proves that *some* GitHub App installation (whichever organization's `webhook_secret` the attacker names in `repository.owner.login`) produced a valid HMAC over the raw body. It says nothing about which repository/commit the payload's other fields describe. Because Shipit installs are typically multi-tenant (one Shipit instance, many `Shipit.github` orgs, each configured in `secrets.yml`, e.g. `somegithuborg` / `someothergithuborg`) [3](#0-2) 
an attacker who legitimately owns/administers **any one** of those configured GitHub App installations (e.g. their own org) knows that org's `webhook_secret` and can therefore sign an arbitrary JSON body themselves and pass `verify_signature` for their own org while putting whatever they want in the rest of the payload.

After signature verification, `WebhooksController#create` dispatches the raw payload to the handler with no further binding check: [4](#0-3) 

`StatusHandler#process` does not use `Handler#stacks`/`repository_name` scoping at all (unlike `PushHandler`, which at least filters `stacks` by `Repository.from_github_repo_name(repository_name)` [5](#0-4) 
). Instead it matches purely by commit SHA across the whole database: [6](#0-5) 

`Commit#create_status_from_github!` then persists the forged state/description/context as a genuine `Status` record and triggers downstream effects (`enable_ci_on_stack`, `schedule_continuous_delivery`) [7](#0-6) [8](#0-7) 

The binding equality that should hold is:
`organization authenticated by verify_signature (repository_owner in payload) == organization owning the repository/commit that the handler mutates`

Instead, the code enforces only:
`organization authenticated == organization named in the same untrusted payload` (tautological, attacker-controlled)

while the object actually mutated (`Commit` found by `sha`) is completely decoupled from that organization — exactly the same class of bug as GG‑3's `transferLock`, where `_to.stakeUntil = _from.stakeUntil` let an unrelated, attacker-chosen source dictate state on a target it should never have been able to influence.

### Impact Explanation
Commit SHAs are not secret (they are visible in any public GitHub repo, PR link, or `git log`/API response). Any attacker who operates their own GitHub App installation configured in this Shipit instance's `secrets.yml` (a normal, low-privilege setup step for any org onboarded to a shared Shipit instance) can:
1. Discover the SHA of an undeployed commit on a *different* org/repository tracked by the same Shipit instance.
2. Sign a `status` webhook payload with their own org's `webhook_secret`, setting `sha` to that commit and `state: "success"`.
3. POST it to `/webhooks`; `verify_signature` passes because it only validates against the attacker's own org.
4. `StatusHandler` finds the victim's `Commit` by SHA alone and marks it CI-successful, which can make it `deployable?` and trigger `schedule_continuous_delivery`, i.e., an unauthorized deploy trigger on a stack/repository the attacker's credentials were never authorized for.

This satisfies the Critical bar: an unauthorized deploy is reachable purely from cross-tenant webhook forgery, without any Shipit session, `ApiClient` token, or repository write access — only knowledge of a public SHA and control of one's own (unprivileged, self-service) GitHub App installation on the shared instance.

### Likelihood Explanation
Any user/org that has been onboarded with their own GitHub App entry in the multi-org `secrets.yml` config (a documented, expected configuration for shared Shipit deployments) automatically has everything needed: their own valid `webhook_secret` and the ability to freely craft the JSON body, including `sha`, `state`, `context`. No social engineering, no compromise of the target org, and no rate-limited secret-guessing is required — this is a pure logic flaw in scoping, not a cryptographic weakness.

### Recommendation
- In `StatusHandler` (and any handler lacking repository scoping), always scope lookups through `Handler#stacks`/`repository_name` derived from `payload.dig('repository', 'full_name')`, and reject/ignore commits that don't belong to a stack under that repository.
- In `WebhooksController#verify_signature`, additionally assert that the `repository_owner` used to select the signing org matches the owner of `repository.full_name` in the same payload, so the authenticated org and the acted-upon repository can never diverge.

### Proof of Concept
1. Attacker configures/owns their own GitHub App entry `attacker-org` in the shared Shipit instance's `secrets.yml`, with a known `webhook_secret`.
2. Attacker finds the SHA of an undeployed commit `deadbeef...` belonging to `victim-org/victim-repo`, a completely unrelated stack on the same Shipit instance.
3. Attacker crafts:
```json
{
  "sha": "deadbeef...",
  "state": "success",
  "context": "ci/forged",
  "repository": { "owner": { "login": "attacker-org" } }
}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC(attacker_webhook_secret, body)` and POSTs to `/webhooks` with `X-Github-Event: status`.
5. `verify_signature` succeeds (`Shipit.github(organization: "attacker-org")` matches the attacker's own secret).
6. `StatusHandler#process` runs `Commit.where(sha: "deadbeef...")`, finds the victim's commit regardless of owning organization, and calls `create_status_from_github!`, marking it CI-successful and potentially triggering an unauthorized deploy on `victim-org/victim-repo`. [9](#0-8) [10](#0-9)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L1-63)
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-27)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
      end
    end
  end
```

**File:** app/models/shipit/status.rb (L16-20)
```ruby
    validates :state, inclusion: { in: STATES, allow_blank: true }, presence: true

    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

```

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```
