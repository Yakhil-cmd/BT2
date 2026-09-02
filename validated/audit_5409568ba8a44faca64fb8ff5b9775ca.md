Found the analog. It breaks the binding: **organization whose webhook signature was verified == repository the payload is trusted to act on**.

### Title
Webhook signature is verified against the organization derived from the unverified payload, but the handler acts on a repository field that is never bound to that verified organization - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to use for HMAC verification by reading `repository_owner` straight out of the **unverified** JSON body, then, once *any* signature check for *that* selected org's secret passes, the raw `params` (including `repository.full_name`) are handed unmodified to the event handlers, which look up the target `Stack`/`Repository` purely by that same unverified `full_name` field.

### Finding Description
In a multi-organization Shipit installation, `Shipit.github(organization:)` maps an organization name to a `GitHubApp` instance holding a distinct `webhook_secret` [1](#0-0) .

The controller picks which secret to verify against using a value taken from the raw, unauthenticated payload before any signature check has occurred: [2](#0-1) [3](#0-2) 

Once `verify_signature` passes (i.e. `head(422) unless verified`, which — like the liquidation check — is only evaluated once, at delivery time, and never re-validated against what is actually acted upon), the full `params` hash, including `repository.full_name`, is forwarded verbatim to handlers: [4](#0-3) 

The generic `Handler` base class and `PushHandler` then resolve the target `Repository`/`Stack` solely from that same unverified `repository.full_name` field, with no re-check that it belongs to the organization whose secret validated the signature: [5](#0-4) [6](#0-5) 

This is the same class of bug as the CDPVault report: a single check ("is this payload's claimed org's HMAC valid") is performed against one field (`repository.owner.login`), while a *different* field in the same unverified payload (`repository.full_name`) is what is actually acted upon — the two are never bound to each other, so the "verified" side and the "acted upon" side can diverge (equality broken: `verified_org(repository.owner.login) ≠ repository_acted_on(repository.full_name)`).

### Impact Explanation
If an operator configures Shipit for multiple GitHub organizations (the documented `github: {org1: {...}, org2: {...}}` schema in `config/secrets.development.shopify.yml`), each org has its own `webhook_secret`. An attacker who has (or compromises) a valid webhook secret for **any one** of the configured organizations (e.g. by being a maintainer of an unrelated, less-trusted org onboarded onto the same Shipit instance) can craft a payload where `repository.owner.login` matches their own org (so their own secret verifies), but `repository.full_name` names a **stack/repository belonging to a different, more privileged organization** on the same instance. Because the handler trusts `repository.full_name` independent of which org's secret validated the request, this can trigger `GithubSyncJob`, status updates, or check-run refreshes against a stack outside the attacker's authorization scope — a cross-repository / cross-tenant write triggered by an unauthorized organization's credentials, i.e. an unauthorized deploy-relevant action.

### Likelihood Explanation
Requires the target Shipit instance to be configured with the multi-organization `github:` schema (explicitly documented and supported, see `config/secrets.development.shopify.yml`), and requires the attacker to control a legitimately configured (but lower-privileged) organization's webhook secret. This is a real operational configuration path, not a hypothetical mis-deployment, so it is plausible in multi-tenant Shipit deployments, though it does not apply to single-organization setups (`github_default_organization` nil case) where only one secret exists.

### Recommendation
After `verify_signature` succeeds, bind the verified organization to the rest of the request: re-derive `repository_owner`/`organization` from the payload used inside handlers and assert it equals (or the resolved `Repository`'s `owner` equals) the organization whose secret validated the signature, rejecting (422) on mismatch, rather than trusting `repository.full_name` in isolation in `Handler#repository_name`.

### Proof of Concept
Conceptual (multi-org config required):
1. Configure Shipit with two orgs, `attacker-org` (secret `S1`) and `victim-org` (secret `S2`), per the `github: {org: {...}}` schema.
2. Attacker crafts a `push` webhook body: `{"repository": {"owner": {"login": "attacker-org"}, "full_name": "victim-org/victim-repo"}, "ref": "refs/heads/main", "after": "<sha>"}`.
3. Attacker signs the raw body with `S1` (their own valid secret) and sends `X-Hub-Signature`.
4. `verify_signature` calls `Shipit.github(organization: "attacker-org")` (from `repository_owner`), verifies against `S1` → passes.
5. `PushHandler#stacks` resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and triggers `sync_github` for a stack the attacker's org secret was never meant to authorize. [7](#0-6) [8](#0-7)

### Citations

**File:** lib/shipit.rb (L170-181)
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
```

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L19-62)
```ruby
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
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L1-39)
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
