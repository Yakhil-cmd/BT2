### Title
Webhook signature verification is keyed on an attacker-controlled organization field that is decoupled from the repository actually processed - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App/webhook secret to validate an inbound webhook against using `repository_owner`, a value read directly from the untrusted JSON payload (`repository.owner.login` or `organization.login`). Because this same payload also carries the `repository.full_name`/branch information that the event handlers actually act on, the "organization that authenticated" the request and the "repository that is written" by the resulting handler are not cryptographically bound together, mirroring the reported access-control class (a check performed against one identity/role while a different, unverified identity is what gets acted upon).

### Finding Description
`verify_signature` does:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

Shipit supports configuring multiple GitHub organizations, each with its own independent `webhook_secret`: [2](#0-1) 

The org used to pick the verifying secret (`repository_owner`) is derived purely from JSON fields inside the very payload whose signature is being checked, not from any authenticated/routing context tied to the target repository. Once the signature check passes, `create` dispatches the parsed body to the registered handler for the event, e.g. `PushHandler`, which matches stacks by the `ref`/branch fields in the same payload and calls `stack.sync_github`: [3](#0-2) [4](#0-3) 

Because the HMAC only proves "this body was signed with organization X's secret," and organization X is itself read out of that same attacker-supplied body, an attacker who legitimately possesses (or can obtain, e.g. as an admin of their own low-privilege GitHub org configured in the same Shipit instance) the webhook secret for **any** configured organization can sign an arbitrary payload with that secret while setting the repository/stack-identifying fields to point at a **different** organization's repository. `verify_signature` will select and validate against the attacker's own org's secret and pass, and the handler will then process the forged repository/ref/sha fields as if they came from the target organization.

### Impact Explanation
This breaks the equality that should hold: `organization whose secret validated the signature == organization/repository the handler subsequently acts on`. An attacker with only a webhook secret for one configured (low-trust) GitHub organization can forge push/status/check_suite events attributed to a repository under a different, higher-trust organization also configured on the same Shipit instance, causing `GithubSyncJob` to run and internal state (commit statuses, sync of unmerged/forced SHAs, CI state) to be written for a repository they do not control — a cross-organization/cross-repository write achieved without ever authenticating to the target organization. Depending on deployment configuration and status-driven automation (e.g., deployable/merge status handlers), this can influence which commits are considered deployable and can trigger unauthorized syncs/deploy-adjacent state changes for a repository the attacker does not own.

### Likelihood Explanation
Exploitability requires the Shipit instance to be configured with more than one GitHub organization (a supported, documented configuration) and requires the attacker to know a legitimate `webhook_secret` for at least one of those configured organizations — e.g., by being an administrator of their own, lower-trust org that is also wired into the same Shipit deployment. This is a real deployment pattern for shared/internal Shipit instances serving multiple teams/orgs, making the precondition plausible rather than purely theoretical, though it does not apply to single-organization deployments.

### Recommendation
Do not select the verifying webhook secret from a field embedded in the very payload being verified without also verifying the payload's actual repository ownership matches. Bind verification to a value that cannot be forged independently of the target: e.g., verify the signature against every configured organization's secret (or a global secret, or the secret tied to the resolved `Repository`/`Stack` record once looked up) and reject the request if the repository identified in the payload does not belong to the organization whose secret validated it.

### Proof of Concept
1. Configure Shipit with two organizations, `org-low` and `org-high`, each with its own `webhook_secret` (as in `config/secrets.development.shopify.yml`).
2. As an attacker who administers `org-low` (or otherwise knows its webhook secret), craft a `push` event JSON body:
   - `repository.owner.login = "org-low"` (or `organization.login = "org-low"`)
   - `repository.full_name`, `ref`, `after` fields set to target a repository/stack that belongs to `org-high`.
3. Sign the raw body with `org-low`'s `webhook_secret` and send it to `POST /github/webhooks` with the correct `X-Hub-Signature` header.
4. `verify_signature` resolves `Shipit.github(organization: "org-low")` and successfully verifies the signature against `org-low`'s secret. [5](#0-4) 
5. `Shipit::Webhooks.for_event('push')` dispatches to `PushHandler`, which locates stacks by the forged `ref`/branch and full-name fields belonging to `org-high` and calls `stack.sync_github`, all without the attacker ever authenticating to `org-high`. [6](#0-5)

### Citations

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

**File:** app/models/shipit/webhooks.rb (L1-44)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    class << self
      def default_handlers
        {
          'push' => [Handlers::PushHandler],
          'pull_request' => [
            Handlers::PullRequest::OpenedHandler,
            Handlers::PullRequest::ClosedHandler,
            Handlers::PullRequest::ReopenedHandler,
            Handlers::PullRequest::EditedHandler,
            Handlers::PullRequest::AssignedHandler,
            Handlers::PullRequest::LabeledHandler,
            Handlers::PullRequest::UnlabeledHandler,
            Handlers::PullRequest::LabelCapturingHandler
          ],
          'status' => [Handlers::StatusHandler],
          'membership' => [Handlers::MembershipHandler],
          'check_suite' => [Handlers::CheckSuiteHandler]
        }
      end

      def handlers
        @handlers ||= reset_handlers!
      end

      def reset_handlers!
        @handlers = default_handlers
      end

      def register_handler(event, callable = nil, &block)
        handlers[event] ||= []
        handlers[event] << callable if callable
        handlers[event] << block if block_given?
      end

      def for_event(event)
        handlers.fetch(event) { [] }
      end
    end
  end
end
```
