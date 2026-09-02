This confirms the multi-org GitHub App configuration supports per-organization `webhook_secret` values [1](#0-0) , and an attacker who legitimately owns/administers any one of the configured GitHub organizations (and thus knows its `webhook_secret`) can forge an HMAC-valid webhook request whose *payload* content is fully under their control.

### Title
Webhook signature verified against `repository.owner.login`/`organization.login` while stack-mutating handlers act on the attacker-controlled `repository.full_name` field - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to use for HMAC verification based on `repository.owner.login` (falling back to `organization.login`) taken from the *unverified* JSON body [2](#0-1) . Once the signature is accepted, `WebhooksController#create` dispatches the whole raw payload to handlers [3](#0-2) . Those handlers (e.g. `PushHandler`, and the pull-request handlers) resolve the `Stack`/`Repository` to mutate using a *different* payload field, `repository.full_name`, via `Repository.from_github_repo_name` [4](#0-3) [5](#0-4) [6](#0-5) . Nothing ties `repository.full_name` back to `repository.owner.login`/the org whose secret validated the request.

### Finding Description
Shipit supports a multi-organization GitHub App configuration where each org has its own `webhook_secret` [1](#0-0) . `verify_signature` computes `repository_owner` purely from request JSON, uses it to pick the org's `GitHubApp`, and then verifies the raw HMAC-SHA1 body against *that org's* secret [7](#0-6) [8](#0-7) . Because the attacker controls the entire raw body (this is a direct HTTP POST to the webhook endpoint, not something GitHub validates end-to-end for arbitrary content), they can set `repository.owner.login` to an organization they administer (and for which they therefore know the configured `webhook_secret`), while setting `repository.full_name` to `"victim-org/victim-repo"` for a completely different, unrelated repository/stack tracked by the same Shipit instance. The signature check only binds the secret-selection field (`owner.login`); it never binds `full_name` to that same organization. Handlers such as `PushHandler` then look up and mutate the *victim* stack via `Repository.from_github_repo_name(payload.dig('repository','full_name'))` [4](#0-3) , enqueuing `GithubSyncJob` for that stack with an attacker-chosen `ref`/`after` SHA [9](#0-8) , or archiving/unarchiving/creating review stacks for a repository the attacker doesn't own via the pull-request handlers [10](#0-9) [11](#0-10) .

This is the exact binding-break pattern called out in scope: **"an organization that authenticated versus the repository that is written."** Before the PR/attack: `verified_org == acted_upon_repo.owner` always holds because both derive from the same trusted GitHub-originated payload. After the attack: `verified_org` (attacker's own org, secret known to attacker) `!= acted_upon_repo.owner` (victim's org), yet the code proceeds as if the whole payload were trustworthy for the victim repository.

### Impact Explanation
An attacker who is an owner/admin of *any* GitHub organization configured in this Shipit instance (a low, unprivileged bar relative to the target — they need no access to the victim repository, Shipit account, or Shipit API token) can trigger `GithubSyncJob`/commit-ingestion, review-stack archive/unarchive/creation, and other webhook-driven side effects against arbitrary stacks/repositories they don't own. Depending on what downstream logic trusts (e.g., `sha`/commit ingestion feeding deploy eligibility, review-stack provisioning tied to `provisioning_behavior`), this can influence deploy state and stack lifecycle for repositories outside the attacker's control — an unauthorized cross-repository state change reachable purely as an unprivileged, remote attacker.

### Likelihood Explanation
Exploitability requires the instance to use the multi-org GitHub App config (documented and supported, see `config/secrets.development.shopify.yml` example) [12](#0-11) , and the attacker must control at least one of the configured orgs' webhook secret — a realistic scenario in shared/multi-tenant Shipit deployments serving multiple organizations, exactly the use case that config style exists for.

### Recommendation
In `WebhooksController#verify_signature` / handler base class, cross-check that the org used to select the webhook secret actually matches the owner of the repository being acted upon (i.e., verify `repository.owner.login` used for secret lookup equals the owner encoded in `repository.full_name`), and reject the request if they diverge, before dispatching to any handler.

### Proof of Concept
1. Shipit configured with two orgs, `attacker-org` (secret known to attacker, who administers that org's GitHub App/webhook) and `victim-org/victim-repo` (a real tracked stack).
2. Attacker POSTs directly to `/github/webhooks` with `X-Github-Event: push`, body:
```json
{
  "ref": "refs/heads/production",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. `X-Hub-Signature` is computed as `sha1=` HMAC of the raw body using `attacker-org`'s known `webhook_secret` [8](#0-7) .
4. `verify_signature` resolves `repository_owner => "attacker-org"`, fetches that org's `GitHubApp`, and the signature validates successfully [13](#0-12) .
5. `PushHandler#process` resolves the stack via `full_name => "victim-org/victim-repo"` and enqueues `GithubSyncJob` for the victim stack with the attacker-supplied `after` SHA [9](#0-8) .

I was not able to trace what downstream consequences `GithubSyncJob`/review-stack mutation have on actual deploy/rollback triggering within the excluded scope (e.g. `app/assets`, `db/migrate`), so the concrete blast radius (whether this alone reaches "unauthorized deploy") depends on additional continuous-deployment configuration not fully explored here.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-53)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end

          private

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
