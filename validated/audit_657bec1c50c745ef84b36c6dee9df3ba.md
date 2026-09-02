### Title
Webhook signature is verified against the organization named in `repository.owner.login`, but handlers act on the unrelated `repository.full_name` field, letting a webhook signed for one tenant org write commit statuses / trigger syncs on any other tenant's stack - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks *which* GitHub App/secret to validate the HMAC against using `repository_owner`, computed from `params.dig('repository', 'owner', 'login')` (or `organization.login`). Every downstream handler, however, resolves the actual `Stack`/`Repository`/`Commit` to mutate using the completely independent `repository.full_name` field. In Shipit's multi-tenant configuration (`Shipit.github(organization:)`, keyed by org in `secrets.github`), these two fields are never cross-checked against each other, so a payload that is validly signed for organization "A" but whose `repository.full_name` points at organization "B"'s repo will be accepted and processed against B's stacks.

### Finding Description
`Shipit.github` supports per-organization app configs (`app_id`, `installation_id`, `webhook_secret`, etc.), each keyed by organization name in `secrets.github`: [1](#0-0) 

`WebhooksController#verify_signature` uses `repository_owner` — derived only from `repository.owner.login` (falling back to `organization.login`) — to select which organization's `GitHubApp` (and thus which `webhook_secret`) is used to validate `X-Hub-Signature`: [2](#0-1) 

Once the signature check passes, `create` hands the raw parsed JSON to every registered handler for the event, unmodified and with no re-binding to `repository_owner`: [3](#0-2) 

Every handler resolves the target `Repository`/`Stack` using `payload.dig('repository', 'full_name')`, a field that is completely separate from `repository.owner.login` used for signature-key selection: [4](#0-3) 

For example, `PushHandler` uses this repository resolution to call `stack.sync_github(expected_head_sha: params.after)` on whatever stacks match `full_name`: [5](#0-4) 

And `StatusHandler` creates a commit `Status` (CI/deploy-gate signal) for any `Commit` matching the attacker-supplied `sha`, with attacker-controlled `state`/`context`/`description`, entirely independent of which org's key signed the request: [6](#0-5) 

**The broken binding, as an equality that should hold but doesn't:**
`organization key used to authenticate the signature (repository.owner.login)` == `organization/repository actually written to (repository.full_name)`

Before the attacker's request: for a legitimate GitHub-originated webhook, GitHub always sets `repository.owner.login` and `repository.full_name` consistently (they describe the same repo), so the equality holds implicitly.

After the attacker's request: since the webhooks endpoint is a plain unauthenticated HTTP POST protected only by the per-org HMAC, an attacker who is themselves an administrator of some tenant organization "A" configured on this Shipit instance (and therefore legitimately knows/controls A's `webhook_secret`, as GitHub webhook secrets are chosen by whoever configures the webhook) can craft an arbitrary JSON body, set `repository.owner.login = "A"` (so `verify_signature` selects and validates against A's secret) while setting `repository.full_name = "B/victim-repo"` (or `organization.login = "A"` while `repository.full_name` targets B). The HMAC is computed over the raw body they control, so they can freely sign this crafted payload with A's own secret. `verify_signature` passes because it only checks `repository.owner.login`/`organization.login` == A. The handler then acts on `full_name = "B/victim-repo"`, an org/stack the attacker has no relationship to.

### Impact Explanation
This breaks the tenant-isolation trust boundary that the per-organization webhook secret design is supposed to provide: possessing organization A's webhook secret should only authorize acting on organization A's repositories, not on any other configured organization's stacks. Concretely, an attacker who controls tenant A can:
- Forge `status` events to create/overwrite `Commit` statuses (`state`, `context`, `description`, `target_url`) on commits belonging to victim org B's stacks, which can influence deploy-gating logic that consults commit statuses.
- Forge `push` events to trigger `GithubSyncJob`/`sync_github` on victim stacks with an attacker-chosen `expected_head_sha`.
- Forge `pull_request`/`check_suite` events to mutate PR/review-stack state (unarchive, close, label, assignment) for repositories under organization B.

This is a cross-tenant/cross-organization write achieved purely by crossing an authentication boundary the engine believes it enforces (organization-scoped webhook secret ⇒ organization-scoped writes), matching the "organization that authenticated versus the repository that is written" analog class, and can lead to unauthorized manipulation of deploy-relevant state on a stack the attacker does not control.

### Likelihood Explanation
Requires the Shipit instance to be configured in the multi-organization mode (`secrets.github` keyed by multiple orgs) — a first-class, documented feature (`Shipit.github(organization:)`, `github_app_config`) rather than a misconfiguration. Any party who administers one of the several tenant organizations on such a shared instance already knows/controls that organization's webhook secret (they configure it when wiring up the GitHub webhook), and the webhooks endpoint takes arbitrary raw bodies with no other authentication, so crafting a mismatched `owner.login`/`full_name` payload is a simple, no-privilege network request.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler#repository_name`), require that the organization/owner used to select the verifying secret is derived from — and equal to — the owner segment of `repository.full_name` (and reject payloads where `repository.owner.login`/`organization.login` disagrees with the owner portion of `repository.full_name`). Alternatively, resolve the target `Repository` first and verify the signature using that repository's actual owning organization's secret, never a value taken from an independently-controlled field.

### Proof of Concept
1. Configure Shipit with two tenant orgs in `secrets.github`: `A` (attacker-controlled, secret known to attacker) and `B` (victim, secret unknown to attacker), each with an installed `Stack` on repo `A/attacker-repo` and `B/victim-repo` respectively.
2. Attacker crafts a `status` webhook body:
```json
{
  "sha": "<victim commit sha in B/victim-repo>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "full_name": "B/victim-repo", "owner": { "login": "A" } }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<hmac-sha1(secret_A, body)>` using A's known webhook secret and sends `POST /webhooks` with header `X-Github-Event: status`.
4. `verify_signature` calls `Shipit.github(organization: "A")` (from `repository.owner.login`), verifies the HMAC against A's secret — succeeds since the attacker signed with the correct key for org A.
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` and creates a forged status on the victim commit belonging to `B/victim-repo`, despite the request never being authenticated for organization `B`.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-24)
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
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-27)
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
    end
  end
```
