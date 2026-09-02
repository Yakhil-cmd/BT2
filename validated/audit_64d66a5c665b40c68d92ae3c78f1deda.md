### Title
Webhook signature verification is keyed on `repository.owner.login`/`organization.login` while the handler acts on the unrelated `repository.full_name` field, allowing cross-repository forged events - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary

### Finding Description
`WebhooksController#verify_signature` selects which GitHub App/organization config (and therefore which `webhook_secret`) is used to validate the HMAC signature by reading `repository_owner`, which is derived from `params.dig('repository', 'owner', 'login')` or, as a fallback, `params.dig('organization', 'login')`: [1](#0-0) [2](#0-1) 

That field is used only to pick the correct `webhook_secret` for HMAC verification of the raw body (`Shipit.github(organization: repository_owner)` → `verify_webhook_signature`): [3](#0-2) 

Once the signature is accepted, the payload is dispatched unmodified to the registered event handlers, e.g. `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`: [4](#0-3) 

Every handler, however, determines the actual `Repository`/`Stack` to operate on from a **different** field: `payload.dig('repository', 'full_name')`, via `Handler#repository_name`/`#stacks`: [5](#0-4) 

For example `PushHandler#process` looks up stacks solely via that `repository_name`-derived `stacks` scope and immediately calls `stack.sync_github`: [6](#0-5) 

Because the value that gates *which secret authenticates the request* (`repository.owner.login` / `organization.login`) is never cross-checked against the value that gates *which repository/stack is mutated* (`repository.full_name`), an attacker who legitimately controls the webhook secret for **any one** organization configured in this Shipit instance can craft a payload where:
- `organization.login` (or `repository.owner.login`) = their own organization (so the signature validates with their own known secret), and
- `repository.full_name` = `"other-org/other-repo"` (any repository already tracked by Shipit, belonging to a completely different organization).

The equality that should hold — `organization authenticating the request == organization owning the repository being written` — is broken: the engine verifies org A's signature but performs the write on org B's repository/stack.

### Impact Explanation
This is a High-impact escalation: an attacker with legitimate control of one tenant's webhook secret can forge `push`, `status`, `check_suite`, `pull_request`, or `membership` events attributed to *any other* repository/organization already configured on the shared Shipit instance. Concretely:
- `PushHandler` triggers `stack.sync_github`, causing Shipit to resync/re-evaluate deploy state for a foreign stack.
- `StatusHandler` can inject fake CI/commit statuses on a foreign repository's commits, which `deploy_spec`/merge-status logic uses to gate deploys and merges — potentially enabling an unauthorized deploy/merge on a stack the attacker has no legitimate access to.
- `MembershipHandler` (`Shipit::Webhooks.default_handlers['membership']`) creates/removes `Team`/`Membership` records; if it also keys off `organization.login`/`team.organization` fields uncorrelated with the verified organization, an attacker could manipulate `Shipit.github_teams` authorization state for a foreign team.

This directly matches the "authorization escalation" and "unauthorized deploy" impact classes called out in scope.

### Likelihood Explanation
Requires the attacker to be a legitimate administrator/webhook-owner of at least one organization already onboarded to a shared/multi-tenant Shipit deployment (i.e., they know that organization's `webhook_secret`), and requires the target repository to already be tracked by Shipit under a different organization. This is a realistic configuration for any Shipit instance serving multiple GitHub organizations, matching the deployment model implied by `config/secrets.development.shopify.yml`'s multi-org `github:` map. No GitHub App private key, `api_clients_secret`, or session access is needed — only knowledge of one tenant's own webhook secret, which is unprivileged relative to other tenants.

### Recommendation
In `WebhooksController#verify_signature`, after successfully verifying the signature for the organization derived from `repository_owner`, re-validate that the organization implied by `params.dig('repository', 'full_name')` (i.e., the owner segment of `full_name`) matches `repository_owner` before dispatching to handlers; reject (422) on mismatch. Equivalently, harden `Shipit::Webhooks::Handlers::Handler#repository_name`/`#stacks` to require that the resolved `Repository`'s owner equals the already-authenticated organization, rather than trusting `full_name` independently.

### Proof of Concept
1. Shipit is configured (per `config/secrets*.yml`) with two tenants: `org-attacker` (webhook secret known to the attacker, who administers that org's GitHub webhook) and `org-victim` (an unrelated tracked repository/stack, e.g. `org-victim/prod-app`).
2. Attacker crafts a `push` (or `status`) webhook JSON body with:
   - `repository.owner.login` = `"org-attacker"` (or `organization.login` = `"org-attacker"`)
   - `repository.full_name` = `"org-victim/prod-app"`
   - `ref` = `refs/heads/main`, `after` = attacker-chosen SHA
3. Attacker computes `X-Hub-Signature` using `org-attacker`'s own known `webhook_secret` over the raw JSON body, per `Hook::DeliverySigner`/`verify_webhook_signature` (`lib/shipit/github_app.rb#L76-83`).
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: 'org-attacker')` and successfully verifies the signature (attacker used the correct secret for that lookup key).
5. `Shipit::Webhooks.for_event('push')` dispatches to `PushHandler.call(params)`, which resolves `stacks` via `payload.dig('repository', 'full_name')` = `"org-victim/prod-app"` and calls `stack.sync_github(expected_head_sha: ...)` on the victim organization's stack — an operation the attacker was never authorized to trigger. [7](#0-6) [5](#0-4) [8](#0-7)

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

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
