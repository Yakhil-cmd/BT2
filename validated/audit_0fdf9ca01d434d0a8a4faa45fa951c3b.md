### Title
Webhook signing-organization is never bound to the repository the handlers act on - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App config (and therefore which `webhook_secret`) to use for HMAC verification based on `repository_owner`, a value read straight out of the untrusted JSON body (`params.dig('repository','owner','login')` or `params.dig('organization','login')`). Every event handler, however, resolves the stack/repository to act on from a *different* field of the same body: `payload.dig('repository','full_name')` (`Shipit::Webhooks::Handlers::Handler#repository_name`). Nothing ties these two fields together, so the signature only proves "this body was signed by the App belonging to organization X," never "this body legitimately concerns repository X/Y." [1](#0-0) [2](#0-1) 

### Finding Description
The binding that should hold is:

`organization whose webhook_secret signed the request == owner of the repository the handler mutates`

`verify_signature` computes `repository_owner` from the payload and fetches `Shipit.github(organization: repository_owner)` to verify the `X-Hub-Signature` HMAC: [3](#0-2) [4](#0-3) 

Once verification passes, `Shipit::Webhooks.for_event(event)` dispatches the *entire raw payload* to handlers such as `PushHandler`, `StatusHandler`, `PullRequest::OpenedHandler`, etc. Every one of them derives the target repository independently via `Handler#repository_name` / `Repository.from_github_repo_name(params.repository.full_name)`: [5](#0-4) [6](#0-5) 

Because `Shipit.github(organization: ...)` is a per-organization config lookup (`config/secrets.*.yml` shows multiple independent orgs, each with its own `webhook_secret`), any organization that has been legitimately onboarded onto the same Shipit instance already knows its own valid `webhook_secret` - that is not a privileged secret belonging to the victim, it is the attacker's own. An attacker who administers `attacker-org` (with its own GitHub App/webhook configured on this Shipit instance) can POST a webhook body where `repository.owner.login` (or `organization.login`) is `"attacker-org"` (so `verify_signature` picks *their own* correct secret and the HMAC passes) while `repository.full_name` is forged to `"victim-org/victim-repo"`. The signature check never inspects `repository.full_name`, so the forged full_name flows unchecked into every handler. [7](#0-6) 

### Impact Explanation
With a correctly-self-signed-but-cross-repository payload, an attacker can drive any webhook-handled behaviour against a stack they do not own or have any GitHub permission on, including:
- `PushHandler`: force `stack.sync_github(expected_head_sha:)` on a victim stack with an attacker-chosen `after` SHA. [8](#0-7) 
- `StatusHandler`/commit-status handlers: inject arbitrary CI/status records for a victim commit, which can satisfy `required_statuses` gating and enable continuous-deployment jobs to auto-deploy an unreviewed commit.
- `PullRequest` handlers: archive/unarchive or otherwise mutate a victim's review stacks.

This crosses a repository-write / unauthorized-deploy boundary using only a self-owned webhook signing secret, matching the "Critical: cross-repository writes / unauthorized deploy" bar.

### Likelihood Explanation
Requires the attacker to have their own organization/App onboarded to the same multi-tenant Shipit instance (a normal, unprivileged position relative to the victim organization) and the ability to send an arbitrary HTTP POST with a body they fully control and sign with their own known secret - no access to the victim's `webhook_secret`, `GITHUB_TOKEN`, or any Shipit session/API token is needed. This is straightforward for any onboarded org.

### Recommendation
In `WebhooksController#verify_signature`, after selecting the signing organization, cross-check that every repository/organization reference used later by handlers (`repository.full_name`, `organization.login`) actually belongs to the same GitHub organization/App that produced the valid signature (e.g., verify `repository.full_name.split('/').first == repository_owner`) before dispatching to handlers, and reject the request otherwise.

### Proof of Concept
1. Attacker administers `attacker-org`, which is configured in this Shipit instance's `github:` secrets with its own `webhook_secret`.
2. Attacker crafts a `push` event body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature` using `attacker-org`'s own `webhook_secret` (known to them) over the exact raw body.
4. POST to `/github/webhooks`. `verify_signature` calls `Shipit.github(organization: "attacker-org")` and the HMAC matches, so the request passes. [9](#0-8) 
5. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `sync_github(expected_head_sha: "<attacker-chosen sha>")` on the victim's stack, despite the request having been authenticated only against `attacker-org`. [2](#0-1) [8](#0-7)

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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
