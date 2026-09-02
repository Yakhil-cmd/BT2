### Title
Webhook signature is verified against an organization derived from HTTP query-string parameters while the payload actually processed comes from the raw body, allowing cross-organization webhook forgery - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to validate the `X-Hub-Signature` against by calling `repository_owner`, which reads `params.dig('repository', 'owner', 'login')` using Rails' merged `params` object [1](#0-0) [2](#0-1) . But the payload actually dispatched to event handlers is parsed independently from `request.raw_post` inside `create` [3](#0-2) . Because Rails `params` is the union of query-string and body parameters (with query-string values able to clobber a top-level body key such as `repository` in a shallow merge), an attacker can make `repository_owner` resolve to an organization/App config different from the organization/repository actually contained in the signed JSON body that `create` processes.

### Finding Description
Shipit supports multiple GitHub App configurations, one per organization, each with its own `webhook_secret`, resolved via `Shipit.github(organization:)` / `Shipit.github_app_config(organization)` [4](#0-3) . The webhook signature is verified per-request against the secret belonging to whichever organization `repository_owner` returns:

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
``` [1](#0-0) 

`repository_owner` is computed from the controller's `params` accessor, not from `request.raw_post`:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [2](#0-1) 

`ActionController::Parameters#params` is built from the union of `query_parameters` and `request_parameters` (the parsed JSON body), and for a JSON POST it merges the two parameter sources at the top level. A top-level key present in both the query string and the JSON body (e.g. `repository`) is not deep-merged; whichever source is applied last wins for that entire sub-hash. This means an attacker who controls the query string of the webhook URL (`POST /webhooks?repository[owner][login]=attacker-org`) can force `repository_owner` to resolve to an arbitrary organization, independent of the JSON body's real `repository.owner.login`/`full_name`.

Meanwhile, the actual event dispatch uses a value parsed fresh from `request.raw_post`, entirely unaffected by the query string:
```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
  head(:ok)
end
``` [3](#0-2) 

Handlers such as `PushHandler`/`Handler#repository_name` resolve the target `Stack`/`Repository` from that raw-body payload's `repository.full_name`, not from anything touched by `verify_signature` [5](#0-4) [6](#0-5) .

This exactly mirrors the referenced bug class: the field used to satisfy the trust/verification check (the organization queried for signature validation) is not the same field that is subsequently acted upon (the repository actually written to via the raw body payload) — a binding of `verified_organization == acted_upon_repository.owner` that the code assumes but does not enforce, breakable by an attacker who controls request query parameters (fully unauthenticated, since `/webhooks` requires no session/token).

### Impact Explanation
An attacker who knows (or controls) the `webhook_secret` for any organization configured in this Shipit instance (e.g., their own org in a multi-org deployment, or one leaked/rotated secret) can forge a validly-"signed" webhook whose signature is checked against that known-secret organization, while the JSON body inside actually targets a different organization/repository's stack. Handlers like `PushHandler` will then trigger `GithubSyncJob` against the victim stack `sync_github(expected_head_sha:)`, and other handlers (status, check_suite, membership, pull_request) can mutate commit statuses, memberships/teams, or pull-request/merge state on a repository the attacker was never authorized for. This is a cross-repository/cross-organization write achieved without any repository write access or session — matching the Critical "cross-repository writes" / "unauthorized deploy" impact bucket.

### Likelihood Explanation
The `/webhooks` endpoint is intentionally public/unauthenticated (no session, no `ApiClient` token) [7](#0-6) . The only prerequisite is that the deployment uses (or has ever used) the multi-organization GitHub App config schema described in the setup docs, and the attacker knows one organization's `webhook_secret` (e.g. because they are a legitimate customer/admin of one tenant organization in a multi-tenant Shipit install) [8](#0-7) . Exploitation requires only crafting a raw POST body plus a query string — no special access, making likelihood high wherever multi-org configuration is used.

### Recommendation
Verify the webhook signature using the same parsed structure that will be dispatched to handlers (the JSON parsed from `request.raw_post`), not the framework's merged `params`. Concretely, parse the body once (e.g. `payload = JSON.parse(request.raw_post)`), derive `repository_owner` from that `payload` hash exclusively, and pass the same `payload` to both `verify_signature` and `create`'s handler dispatch, eliminating any dependence on `ActionController::Parameters`/query-string merging for the organization used in the trust decision.

### Proof of Concept
1. Deploy Shipit with the multi-org github config schema, having at least two organizations configured: `attacker-org` (secret known to attacker) and `victim-org` (Shipit-tracked stack, secret unknown to attacker).
2. Attacker computes `X-Hub-Signature: sha1=<hmac>` over a JSON body whose `repository.full_name` is `victim-org/victim-repo` and event type `push`, using `attacker-org`'s webhook secret.
3. Attacker sends:
```
POST /webhooks?repository[owner][login]=attacker-org
X-Github-Event: push
X-Hub-Signature: sha1=<hmac computed with attacker-org secret>
Content-Type: application/json

{"ref":"refs/heads/main","after":"<attacker chosen sha>","repository":{"full_name":"victim-org/victim-repo","owner":{"login":"victim-org"}}}
```
4. `verify_signature` computes `repository_owner` = `"attacker-org"` (from the query string, since `params.dig('repository','owner','login')` reflects the query-string-supplied `repository` hash), fetches `attacker-org`'s `webhook_secret`, and the signature verifies successfully.
5. `create` re-parses `request.raw_post` (unaffected by query string) and dispatches `PushHandler` against the payload whose `repository.full_name` is `victim-org/victim-repo`, causing Shipit to sync/act on the victim's stack despite the attacker never possessing `victim-org`'s webhook secret. [9](#0-8)

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-17)
```ruby
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
```

**File:** config/secrets.development.example.yml (L18-38)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
```
