### Title
Webhook signature verified against `repository.owner.login`, but stack lookup keyed on independent `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate the inbound HMAC signature against using `repository_owner`, which is read from `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`). [1](#0-0)  However, every webhook `Handler` resolves the repository/stack that the event actually acts on using a completely different field in the same JSON body: `payload.dig('repository', 'full_name')`. [2](#0-1)  Nothing ties these two values together after signature verification succeeds.

### Finding Description
Shipit supports hosting multiple GitHub organizations from a single installation, each with its own `webhook_secret`, exactly as shown in the sample multi-org configuration (`somegithuborg`, `someothergithuborg`). [3](#0-2)  The signature-check binding is:

`organization whose secret authenticated the request == params['repository']['owner']['login']`

but the binding actually enforced by the handlers that execute side effects is:

`repository acted upon == payload['repository']['full_name']`

These two identifiers are never cross-checked against each other. In a legitimate GitHub payload they always agree (both come from the same `repository` object), but an attacker who can produce a validly-signed body for *any one* organization configured on the instance (e.g., an org they administer, which has its own legitimate webhook pointed at this shared Shipit instance) can freely edit the JSON payload before signing it with that org's secret. They can set `repository.owner.login` to their own (authenticating) org while setting `repository.full_name` to `other-org/other-repo` — a repository belonging to a completely different, unrelated organization tracked by the same Shipit instance. `verify_signature` passes (their org's secret matches), and control passes to `Handler#repository_name`, `PushHandler#process`, or the pull-request handlers, all of which resolve the target `Repository`/`Stack` purely from `full_name`, with no relation back to the authenticating organization. [4](#0-3) [5](#0-4) 

This is the class of bug described in the report — an unbounded action is taken during automated processing on a piece of state (`repository.full_name`) that was never covered by the verification that gated the operation (`repository.owner.login`) — mapped here onto shipit-engine's trust boundary between "the org that authenticated the webhook" and "the repository whose stacks/pull-requests get written."

### Impact Explanation
Exploiting this confused-deputy gap allows cross-repository writes against a stack the attacker does not control:
- Via `PushHandler`, forged sync events (`stack.sync_github(expected_head_sha:)`) can be delivered for any tracked stack in any org on the shared instance, and if that stack has `continuous_deployment` enabled, this can trigger unauthorized deploys.
- Via the pull-request handlers (`OpenedHandler`, `LabeledHandler`, `UnlabeledHandler`, `ReopenedHandler`), an attacker can archive/unarchive/provision review stacks belonging to a foreign repository by forging `pull_request` events signed with their own org's secret while pointing `repository.full_name` at the victim repo. [6](#0-5) 

This matches the required High/Critical impact bar of "cross-repository writes" / "an unauthorized deploy."

### Likelihood Explanation
This requires the attacker to control (or register) a GitHub App/webhook secret for at least one organization that is configured on the shared Shipit instance — a realistic scenario for any Shipit deployment that serves multiple orgs/teams (as documented in the multi-org secrets format), since onboarding a new org typically only requires adding entries to `secrets.yml`, not vetting cross-org trust. No GitHub write access, session, or API token is required — only the ability to sign an arbitrary JSON body with one authenticated org's `webhook_secret` and POST it to `/webhooks`.

### Recommendation
After signature verification, require that the organization derived from `params['repository']['owner']['login']` (the one whose secret validated the request) matches the organization portion of `payload['repository']['full_name']` used by the handlers, rejecting the webhook (422) on mismatch. Alternatively, scope `Shipit.github(organization:)` lookup and the resulting `webhook_secret` check to be keyed from the same canonical field the handlers use (`repository.full_name`'s owner segment), so a single authoritative identifier drives both authentication and repository resolution.

### Proof of Concept
1. Deploy Shipit configured with two orgs in `secrets.yml`, e.g. `org-a` (attacker-controlled webhook secret `SECRET_A`) and `org-b` (victim org, tracked stack `org-b/victim-repo`).
2. Attacker crafts a `pull_request` payload:
```json
{
  "action": "opened",
  "number": 1,
  "pull_request": { "...": "valid pull_request fields..." },
  "repository": { "owner": { "login": "org-a" }, "full_name": "org-b/victim-repo" },
  "sender": { "login": "attacker" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(SECRET_A, body)` and POSTs to `/webhooks` with `X-Github-Event: pull_request`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: 'org-a')` and successfully verifies the signature against `SECRET_A`. [7](#0-6) 
5. `Shipit::Webhooks.for_event('pull_request')` dispatches to `OpenedHandler`, which resolves `Shipit::Repository.from_github_repo_name('org-b/victim-repo')` and provisions/archives review stacks belonging to `org-b`, entirely outside the authenticating org's authority. [8](#0-7)

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-54)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L59-68)
```ruby
          def stack
            @stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end

          def repository
            @repository ||= Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
                            Shipit::NullRepository.new
          end
```
