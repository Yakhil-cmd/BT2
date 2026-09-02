This confirms the multi-tenant configuration model: `Shipit.github(organization:)` looks up a per-organization `GitHubApp` config (each with its own `webhook_secret`) via `github_app_config` [1](#0-0) , matching the documented multi-org secrets layout [2](#0-1) .

### Title
Webhook Signature Verification Uses `repository.owner.login`/`organization.login` While Event Handlers Act On The Independently-Controlled `repository.full_name` Field, Enabling Cross-Organization Webhook Forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to verify a webhook against using `repository_owner`, derived from `params.dig('repository','owner','login')` or `params.dig('organization','login')` [3](#0-2) . Once verification passes, the actual event `Handler` subclasses (e.g. `PushHandler`) resolve the target `Repository`/`Stack` using a *different* field of the same payload: `payload.dig('repository', 'full_name')` [4](#0-3) . Because these two fields are never cross-checked against each other, an attacker who legitimately controls a GitHub App installation (and thus knows the `webhook_secret`) for one organization configured on a shared, multi-tenant Shipit instance can craft a signed payload where `repository.owner.login`/`organization.login` names their own org (to pass signature verification) while `repository.full_name` names a victim's repository hosted on the same Shipit instance.

### Finding Description
Shipit supports hosting multiple GitHub organizations from a single instance, each with its own `webhook_secret`, via `Shipit.github(organization:)` and `github_app_config` [1](#0-0) . `WebhooksController#verify_signature` picks the app/secret to verify against solely based on `repository_owner`:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  head(422) unless verified
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [3](#0-2) 

The signature itself is a valid HMAC over the full raw request body, computed with the secret belonging to whichever organization `repository_owner` names — that binding is internally consistent. The break is downstream: `create` re-parses the same raw body and dispatches to handlers, e.g. `PushHandler#process`, which locate the `Stack`s to mutate purely from `payload.dig('repository', 'full_name')` via `Handler#stacks`/`#repository_name` [4](#0-3) , and similarly in `PullRequest::OpenedHandler#repository` [5](#0-4) . There is no check anywhere that `full_name`'s owner segment equals the `repository_owner`/`organization.login` value that was authenticated. Both fields live in the same attacker-authored JSON body and are equally attacker-controlled prior to signing.

This is the structural analog of the reported bug class: the report's `SessionKeyData` storage key was derived from one field (`sessionKeyId` truncated) while intended to bind per-key permissions, causing unrelated keys to share the same permission slot — a derivation mismatch between what is verified/keyed and what governs the actual effect. Here, the organization whose secret authenticates the request (`repository.owner.login`/`organization.login`) is decoupled from the repository whose stacks are actually written (`repository.full_name`), breaking the intended equality `authenticated_org == written_repository_org`.

### Impact Explanation
An attacker who operates their own GitHub organization/App installed on a shared Shipit instance (a legitimate, supported multi-tenant deployment per `config/secrets.development.shopify.yml`) knows their own `webhook_secret`. Using it, they can sign an arbitrary payload naming any other tenant's repository in `repository.full_name`, causing unauthorized cross-repository writes: enqueuing `GithubSyncJob` for a victim's stack (pulling attacker-supplied `ref`/`after` SHAs and driving deploy-relevant commit/stack state) [6](#0-5) , forging `pull_request` events that create/mutate review stacks for a victim's repository [7](#0-6) , or posting fabricated commit statuses/check-suite events against a victim's commits. This satisfies the "cross-repository writes" Critical impact criterion.

### Likelihood Explanation
Requires only that the attacker control a GitHub App installation/webhook secret for one organization on a shared multi-org Shipit deployment — a normal, supported configuration mode, not a privileged Shipit account or session. No repository write access, GitHub token theft, or social engineering is needed; only a crafted HTTP POST to `/webhooks` with a validly-signed but internally inconsistent payload.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handlers::Handler`), require that the organization derived from `repository.full_name`'s owner segment matches `repository_owner`/`organization.login`, rejecting the webhook with `422` if they diverge. Alternatively, resolve the target repository/stack for handler dispatch using the same authenticated `repository_owner` value rather than trusting `full_name` independently.

### Proof of Concept
On a shared instance configured per `config/secrets.development.shopify.yml` with organizations `attacker-org` and `victim-org`, each with a distinct `webhook_secret`:
```ruby
payload = {
  ref: "refs/heads/master",
  after: "deadbeef",
  repository: {
    owner: { login: "attacker-org" },   # used only for signature verification
    full_name: "victim-org/victim-repo" # used by PushHandler to select the Stack to sync
  }
}.to_json

signature = "sha1=" + OpenSSL::HMAC.hexdigest("sha1", attacker_orgs_webhook_secret, payload)

post "/webhooks", body: payload, headers: {
  "X-Github-Event" => "push",
  "X-Hub-Signature" => signature
}
# verify_signature succeeds (attacker-org's secret matches),
# but PushHandler#process enqueues GithubSyncJob for victim-org/victim-repo's stacks.
```

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
