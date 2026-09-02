Based on the confirmed multi-organization webhook design in `lib/shipit.rb` and `app/controllers/shipit/webhooks_controller.rb`, there is a genuine analog: the signature-verification organization is selected from an attacker-controlled, unverified field, but the object actually mutated by the handler is looked up from a *different* field that is not required to belong to that organization.

### Title
Webhook signature is verified against an organization chosen from unverified payload data, decoupling "organization authenticated" from "repository written" - ([File: app/controllers/shipit/webhooks_controller.rb])

### Finding Description
`WebhooksController#verify_signature` picks which GitHub App/organization config (and therefore which `webhook_secret`) to validate the delivery against by reading `repository_owner` straight out of the **unparsed, unauthenticated** JSON body: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` then resolves that organization to a `GitHubApp` instance with its own independent `webhook_secret`: [3](#0-2) 

`GitHubApp#verify_webhook_signature` explicitly treats a blank/`nil` `webhook_secret` as "always verified": [4](#0-3) 

Meanwhile, once the signature check passes, the actual event handlers (`PushHandler`, `PullRequest::*Handler`, etc.) resolve the repository/stack to mutate using a **separate** field, `repository.full_name`, via `Handler#repository_name`/`Repository.from_github_repo_name`: [5](#0-4) [6](#0-5) 

Because `config/secrets.*.yml` supports multiple, independently-configured organizations (each with its own possibly-unset `webhook_secret`), the field used to select "which secret protects this delivery" (`repository.owner.login` / `organization.login`) is never required to be consistent with the field used to select "which repository this delivery affects" (`repository.full_name`). Nothing in the controller binds the two together, and nothing re-validates that `repository.full_name`'s owner matches the organization whose secret validated the payload: [7](#0-6) 

This breaks the intended trust equality: `organization authenticated by signature == organization owning the repository that gets written`.

### Impact Explanation
In a multi-org Shipit deployment (the engine's own documented multi-tenant config format, not a misconfiguration), if any one configured organization has a blank/unset `webhook_secret` (a legitimate, supported state per `GitHubApp#verify_webhook_signature`'s `return true unless webhook_secret`), an attacker who can reach the `/webhooks` endpoint can craft a payload where:
- `repository.owner.login` / `organization.login` = the organization with no `webhook_secret` (or one whose secret the attacker knows through unrelated means), so `verify_webhook_signature` returns `true` unconditionally, and
- `repository.full_name` = a repository belonging to a **different**, sensitive organization actually protected by a secret.

The event is then processed as if it were authentically delivered for the sensitive org's repository — e.g. `PushHandler` triggers `stack.sync_github(expected_head_sha: ...)` for that stack, or `PullRequest::ClosedHandler`/`LabeledHandler` archive/unarchive review stacks, purely from attacker-supplied JSON with no valid signature over the acted-upon repository. This crosses the organization/repository authentication boundary without any GitHub-issued signature covering the actually-affected repository, i.e., an unauthorized action taken against a stack/repository the attacker does not control — a cross-repository write triggered through a spoofed webhook.

### Likelihood Explanation
Requires the deployment to configure more than one GitHub organization (a supported, documented configuration, see `config/secrets.development.shopify.yml`, `Shipit.github_organizations`) where at least one organization's `webhook_secret` is unset — plausible for a staging/dev org or an org onboarded before rotating secrets. No GitHub App private key, `ApiClient` token, or Shipit session is needed; only network access to the `/webhooks` endpoint, which is intentionally unauthenticated (webhook signature is the only defense). This is a design gap in the controller rather than a rare edge case, but it is conditioned on the multi-org/blank-secret configuration state, so likelihood is Medium rather than High.

### Recommendation
- After resolving `repository_owner` for signature selection, also derive the organization from `repository.full_name` and require them to match before dispatching to handlers, or
- Refuse to treat a blank `webhook_secret` as "always verified" once more than one organization is configured (`Shipit.github_organizations.size > 1`), or require an explicit non-blank secret for every configured organization, and
- Have each handler independently assert that the `repository`/`organization` used for routing belongs to the same organization whose secret validated the delivery.

### Proof of Concept
1. Deploy Shipit configured with two organizations, e.g. `trusted-org` (has `webhook_secret: <real-secret>`) and `test-org` (has `webhook_secret:` left blank), matching the documented format in `config/secrets.development.shopify.yml`.
2. Attacker POSTs to `/webhooks` with header `X-Github-Event: push` and body:
   ```json
   {
     "ref": "refs/heads/main",
     "after": "<attacker-chosen sha>",
     "repository": { "full_name": "trusted-org/production-app", "owner": { "login": "test-org" } }
   }
   ```
   No valid `X-Hub-Signature` is required because `repository_owner` resolves to `test-org`.
3. `verify_signature` calls `Shipit.github(organization: "test-org")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally.
4. `Shipit::Webhooks.for_event('push')` dispatches to `PushHandler`, which resolves the stack via `Repository.from_github_repo_name("trusted-org/production-app")` (from `repository.full_name`) and calls `stack.sync_github(expected_head_sha: params.after)` — an action against `trusted-org`'s stack triggered by a payload never signed by `trusted-org`'s secret. [8](#0-7) [4](#0-3) [9](#0-8)

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
