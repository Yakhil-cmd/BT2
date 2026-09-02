Based on my investigation, I found a genuine analog: the webhook signature verification in `WebhooksController` authenticates the request against a GitHub organization derived from one payload field, while the actual event-processing logic (repository lookup) trusts a different payload field that is not cross-checked against the authenticated organization.

### Title
Webhook signature verification authenticates the organization but not the repository, allowing an owner of a valid Shipit webhook secret to sync/push events for another organization's repository - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks the GitHub App/webhook secret to check the HMAC signature using `repository_owner`, computed from `params.dig('repository','owner','login')` (or `organization.login`). Once the signature validates against *that* organization's secret, the entire raw payload—including `repository.full_name`—is handed unchecked to `Shipit::Webhooks.for_event(event)` handlers, which resolve the target `Stack`/`Repository` via `payload.dig('repository','full_name')` in `Shipit::Webhooks::Handlers::Handler#repository_name`.

### Finding Description
`verify_signature` in `app/controllers/shipit/webhooks_controller.rb` resolves the signing organization from the payload itself: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` looks up per-organization `webhook_secret` config from `secrets.github` and instantiates a `GitHubApp` scoped to that organization key (this only matters in the multi-org config schema documented in `docs/setup.md`, where `secrets.github` has one sub-hash per org): [3](#0-2) 

After `verify_signature` passes, `create` dispatches the *entire* raw payload, unmodified, to handlers: [4](#0-3) 

Handlers (e.g. the `push` handler feeding `GithubSyncJob`, and the base `Handler` class used by pull_request handlers) locate the target repository/stack using a *different* payload field than the one used for authentication: [5](#0-4) 

The equality that should hold but is never enforced is:
`organization used to select webhook_secret (params.dig('repository','owner','login'))` == `organization implied by params.dig('repository','full_name')` (the repo the handler actually mutates/syncs).

Nothing in `verify_signature` or in `Handler#repository_name` cross-checks that the `full_name`'s owner segment matches `repository_owner`. If a Shipit deployment is configured with the multi-org schema (multiple entries under `secrets.github`, each with its own `webhook_secret`), a party who legitimately controls one organization's webhook secret (e.g., because they operate a GitHub App/webhook integration for `OrgA`) can craft a signed payload where `repository.owner.login == "OrgA"` (so the HMAC check passes using OrgA's secret) but `repository.full_name == "OrgB/some-repo"`. The signature check only binds the secret choice to `owner.login`; it never binds it to `full_name`.

### Impact Explanation
If exploitable, this breaks the binding between "the organization whose secret authenticated this webhook" and "the repository whose Stack gets mutated." For the `push` event this reaches `GithubSyncJob`, which fetches commits via `stack.github_commits` and appends them to the stack's commit history, and other handlers (`pull_request`, `membership`, `status`) mutate `Stack`/`Team`/`Membership`/`Commit::Status` records for whatever repository/stack is resolved from `full_name`. This is a cross-repository write driven by a signature that was never scoped to that repository, which matches the Critical "cross-repository writes" criterion.

### Likelihood Explanation
Low/uncertain. This requires: (1) the deployment to use the multi-organization `secrets.github` schema (documented in `docs/setup.md`) rather than the single-org schema, and (2) the attacker to already possess a valid webhook secret for *at least one* configured organization on that Shipit instance while wanting to affect a *different* configured organization's stacks. I could not fully verify from the available code whether `Repository.from_github_repo_name` or the `Stack` lookup implicitly re-validates the owner against the configured organizations elsewhere in the request pipeline (e.g., is there stack existence gating that would reject a `full_name` belonging to an org whose repos aren't already registered as Stacks?). Because Stacks/Repositories are presumably pre-registered by Shipit admins for known org/repo pairs, this may only allow forging events for repos that already exist as Stacks under a *different* org than the one whose secret was used — still a boundary violation, but the practical blast radius depends on how repositories are provisioned, which is outside what I could confirm in-scope.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler#repository_name`), require that the organization derived from `repository.full_name` (i.e., the owner segment) matches `repository_owner` used to select the webhook secret, and reject the request (422) otherwise. Alternatively, always resolve the GitHub App/secret from the *same* field (`full_name`'s owner) that handlers use to resolve the target repository, so there is only one source of truth for "which organization does this payload belong to."

### Proof of Concept
1. Deploy Shipit with the multi-org config schema: `secrets.github: { OrgA: {webhook_secret: SECRET_A, ...}, OrgB: {webhook_secret: SECRET_B, ...} }`, with Stacks registered for repos under both `OrgA/*` and `OrgB/*`.
2. As an attacker who knows `SECRET_A` (e.g., a legitimate webhook integrator for `OrgA`), craft a `push` payload:
   ```json
   {
     "repository": { "owner": {"login": "OrgA"}, "full_name": "OrgB/target-repo" },
     "after": "<attacker-controlled sha>"
   }
   ```
3. Sign the raw body with `HMAC-SHA1(SECRET_A, body)` and set `X-Hub-Signature`, `X-Github-Event: push`.
4. POST to `/github/webhooks` (or the mounted webhook path). `verify_signature` computes `repository_owner = "OrgA"`, fetches `Shipit.github(organization: "OrgA")`, and the signature validates using `SECRET_A`.
5. `create` then dispatches the full payload to the `push` handler, which uses `full_name = "OrgB/target-repo"` to resolve the Stack and enqueue `GithubSyncJob`, syncing commits into `OrgB`'s stack — a write to a repository never covered by the verifying secret. [6](#0-5) [3](#0-2) [7](#0-6)

### Citations

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L1-41)
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
```
