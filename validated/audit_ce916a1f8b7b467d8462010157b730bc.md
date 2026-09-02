### Title
Webhook signature verified against the org derived from an unauthenticated payload field, letting any tenant org forge events for another tenant's repository - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to check the `X-Hub-Signature` against by reading `repository.owner.login` (or `organization.login`) straight out of the *unverified* JSON body. Every webhook handler, however, resolves the repository/stack to act on from a *different*, independent payload field: `repository.full_name`. Nothing ties these two fields together, so in a multi-organization Shipit deployment (the officially documented "Using Multiple Github Applications" setup) a sender who legitimately controls one configured organization's webhook secret can sign a payload as their own org while setting `repository.full_name` to a repository belonging to a different, unrelated tenant org, and the handler will act on that other org's stack.

### Finding Description
`verify_signature` computes the signing org before the signature is checked:

<cite repo="hirayap/shipit-engine--003" path="app/controllers/shipit/webhooks_controller.rb" start="24="30" /> [1](#0-0) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [2](#0-1) 

`Shipit.github(organization:)` looks up a per-organization `webhook_secret` from `secrets.github`, as documented for multi-org setups: [3](#0-2) [4](#0-3) 

The signature is HMAC over the raw body using that org's secret: [5](#0-4) 

Once verification passes, the *entire unmodified* JSON payload — including `repository.full_name` — is dispatched to handlers: [6](#0-5) 

But every handler resolves the actual `Repository`/`Stack` it will mutate from `repository.full_name`, not from `repository.owner.login`: [7](#0-6) 

For example `PushHandler` uses that repository resolution to enqueue a sync against arbitrary stacks with an attacker-chosen `expected_head_sha`: [8](#0-7) 

and `StatusHandler` writes a commit status purely from `params.sha`, independent of any repository/org binding at all: [9](#0-8) 

**Binding broken:** *organization authenticated (signature verified against `repository.owner.login`'s webhook secret) ≠ repository written (`repository.full_name` acted on by the handler)*. The controller never asserts that `repository.full_name`'s owner segment matches `repository_owner`, so the field covered by the cryptographic check and the field that drives the write are decoupled.

### Impact Explanation
In a multi-tenant Shipit instance (multiple GitHub orgs configured under `secrets.github`, each with its own `webhook_secret`, exactly as documented), any org that can produce a validly signed webhook for itself can forge events attributed to any other org's repository tracked by the same Shipit instance. This allows:
- Triggering `GithubSyncJob` for a victim stack with a forged `expected_head_sha`, an unauthorized action against another tenant's repository.
- Writing arbitrary commit statuses (`StatusHandler`) against commits belonging to another tenant's repository, since `StatusHandler` doesn't even check ownership.
- Potentially influencing review-stack lifecycle/pull_request driven flows for repositories the attacker does not own.

This crosses a tenant/repository trust boundary using only credentials the attacker legitimately possesses for their own org, matching the "cross-repository writes" / unauthorized-action class of impact.

### Likelihood Explanation
Requires the Shipit instance to be configured with multiple GitHub organizations (a supported, documented configuration), and requires the attacker to control (or be granted) the webhook secret for at least one of those configured orgs — which is expected for any legitimate tenant onboarded to a shared Shipit instance. No GitHub App private key, `api_clients_secret`, or Shipit session is needed; the attacker only needs the ability to sign a webhook as their own tenant, which is the intended capability given to every onboarded org.

### Recommendation
After computing `repository_owner` and verifying the signature, also validate that `repository.full_name`'s owner segment (and/or `organization.login`) is consistent with `repository_owner` before dispatching to handlers — i.e., ensure the org bound to the verified secret matches the org that owns the repository being mutated. Alternatively, scope handler repository resolution (`Handler#repository_name`) to only resolve repositories within the same organization that was authenticated by `verify_signature`, rejecting cross-organization payloads outright.

### Proof of Concept
Given Shipit configured with two orgs, `attacker-org` (webhook secret known to the attacker) and `victim-org` (repository `victim-org/victim-repo` tracked by Shipit):

1. Attacker builds a `push` payload:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
2. Attacker signs the raw body with `attacker-org`'s known `webhook_secret` and sets `X-Hub-Signature: sha1=<hmac>` and `X-Github-Event: push`.
3. `WebhooksController#verify_signature` resolves `repository_owner => "attacker-org"`, fetches `attacker-org`'s `GitHubApp`, and the signature check passes (attacker signed correctly for that org). [10](#0-9) 
4. `PushHandler.call(params)` runs, resolving `repository_name` from `full_name` = `"victim-org/victim-repo"`, and enqueues `GithubSyncJob` against `victim-org`'s stack with the attacker's forged `expected_head_sha`, even though the attacker never authenticated as `victim-org`. [7](#0-6) [11](#0-10)

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

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-24)
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

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-25)
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
```
