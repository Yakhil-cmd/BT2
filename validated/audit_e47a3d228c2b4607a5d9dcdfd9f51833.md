Confirmed: Shipit supports multi-organization GitHub App configuration, where `Shipit.github_app_config(organization)` looks up a distinct `webhook_secret` per organization key in `secrets.github` [1](#0-0) . This makes the analog concrete and exploitable in a multi-org deployment.

### Title
Webhook signature verification is bound to `repository.owner.login`, but stack/repository mutation is keyed on the unverified `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to verify the `X-Hub-Signature` against using `repository_owner`, computed as `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [2](#0-1) [3](#0-2) . However, every event handler that actually mutates state locates the target `Repository`/`Stack` using a *different* field: `payload.dig('repository', 'full_name')` [4](#0-3) , e.g. `PushHandler#process` calls `Repository.from_github_repo_name(repository_name)` to trigger `stack.sync_github` [5](#0-4) . In a multi-organization Shipit installation, `Shipit.github(organization:)` resolves a per-organization `webhook_secret` via `github_app_config(organization)` [1](#0-0) .

### Finding Description
The binding that should hold is:

`organization whose webhook_secret authenticated the signature == organization/repository whose Stack is written`

The code breaks this equality: the signature is verified only against `repository.owner.login` (or `organization.login`) to pick a secret, while the repository actually acted upon is `repository.full_name`, an entirely separate JSON field in the same payload, and it is never checked that `full_name`'s owner segment matches the verified `owner.login`. An attacker who controls a GitHub organization/repo onboarded to this Shipit instance (i.e., can trigger a legitimately signed webhook delivery from *their own* org, using their own org's valid `webhook_secret`) can craft/replay a payload where:
- `repository.owner.login` = `attacker-org` (used only to select which secret to verify with — passes, since attacker owns that org's secret)
- `repository.full_name` = `victim-org/victim-repo` (used by `PushHandler`, `StatusHandler`, `CheckSuiteHandler`, and the `pull_request/*` handlers to look up the actual `Stack`/`Repository` and trigger `sync_github`, create commit statuses, or archive/unarchive review stacks)

Because `verify_signature` only checks the HMAC validity for the org derived from `owner.login`, and does not re-derive/cross-check that value against `full_name`, the signature check authenticates one identity while the write path acts on a different, attacker-chosen repository/stack.

### Impact Explanation
This crosses the "organization that authenticated versus the repository that is written" boundary explicitly called out as in-scope. Concretely, `PushHandler#process` calls `stack.sync_github(expected_head_sha: params.after)` [5](#0-4)  for the victim's stack, and `StatusHandler`/`CheckSuiteHandler` similarly can flip CI status / check-run state for a stack the attacker does not own, which can affect deploy safety gating. Pull request handlers can archive/unarchive a victim's review stacks. Since Shipit's deploy pipeline treats commit status and check-run state as gating signals for whether a deploy is safe, an attacker forging these for a victim repository can influence an unauthorized deploy decision on that stack, satisfying the "unauthorized deploy" High/Critical impact bar.

### Likelihood Explanation
This requires the deployment to run Shipit's multi-org GitHub App configuration (distinct `webhook_secret` per organization key under `secrets.github`) and the attacker to control at least one onboarded organization capable of delivering a webhook with a valid signature for that org, while pointing `repository.full_name` at a different onboarded org/repo. This is a real, unprivileged-attacker-reachable path within a supported configuration mode of the engine (no assumption of session, API token, or GitHub App private key), matching the required threat model.

### Recommendation
`verify_signature` should derive the organization to verify against, and every handler's repository resolution, from the *same* payload field, and should additionally assert that `repository.full_name`'s owner segment matches the organization whose secret validated the signature before any handler is dispatched.

### Proof of Concept
1. Attacker controls GitHub organization `attacker-org`, which is configured in this Shipit instance's `secrets.github[:attacker-org]` with its own `webhook_secret`.
2. Attacker triggers (or crafts, using their known secret) a `push` webhook delivery with:
   - `X-Github-Event: push`
   - Body: `{"ref": "refs/heads/master", "after": "<attacker-controlled sha>", "repository": {"owner": {"login": "attacker-org"}, "full_name": "victim-org/victim-repo"}}`
   - `X-Hub-Signature` computed with `attacker-org`'s `webhook_secret`.
3. `WebhooksController#verify_signature` computes `repository_owner` = `"attacker-org"`, calls `Shipit.github(organization: "attacker-org")`, and the signature verifies successfully [2](#0-1) .
4. `PushHandler.call(params)` is invoked; `repository_name` resolves to `"victim-org/victim-repo"` [6](#0-5) , and `stack.sync_github(expected_head_sha: ...)` is triggered for the victim's stack — a write the attacker was never authorized to perform. [7](#0-6) [8](#0-7) [9](#0-8) [1](#0-0)

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L1-42)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class Handler
        class << self
          attr_reader :param_parser

          def params(&block)
            @param_parser = ExplicitParameters::Parameters.define(&block)
          end
        end

        def self.call(params)
          new(params).process
        end

        attr_reader :params, :payload

        def initialize(payload)
          @payload = payload
          @params = self.class.param_parser.parse!(payload)
        end

        def process
          raise NotImplementedError
        end

        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
      end
    end
  end
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
