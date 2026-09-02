Confirmed: this is a genuine multi-tenant deployment configuration, since `Shipit.github(organization:)` supports a keyed hash of per-organization GitHub App configs (`secrets.github[org]`), each with its own `webhook_secret` [1](#0-0) . That confirms an attacker who controls (or is a maintainer/webhook admin of) one configured organization on a shared Shipit instance possesses a valid webhook secret for that org and can forge a validly-signed webhook whose `repository.full_name` field points at a different organization's repository.

### Title
Webhook signature verification binds to `repository.owner.login`, but event handlers act on the unverified `repository.full_name` field — ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to verify a webhook against using `repository_owner`, computed from `params.dig('repository', 'owner', 'login')` (or `organization.login`) [2](#0-1) . Once the signature is accepted, `create` dispatches the *entire raw payload* to handlers [3](#0-2) , and every handler resolves the target `Stack`/`Repository` using a completely different, independently-attacker-controlled field: `payload.dig('repository', 'full_name')` [4](#0-3) . Neither field is cross-checked against the other, so the signature only proves "this request was signed with Org A's secret," not "this request is about a repository owned by Org A."

### Finding Description
The intended equality is: `organization whose secret verified the signature == organization owning the repository the handlers act on`. In this codebase these are two unrelated JSON keys inside the same untrusted, attacker-supplied HTTP body:
- Signature secret selection key: `repository.owner.login` / `organization.login` [5](#0-4) 
- Repository/stack resolution key: `repository.full_name` [6](#0-5) 

`Shipit.github(organization:)` supports per-organization GitHub App configs, each with its own independent `webhook_secret`, for multi-tenant Shipit deployments [1](#0-0) . An attacker who has legitimate access to Org A's webhook secret (e.g., they administer Org A's GitHub App installation on a shared Shipit instance, or Org A's secret leaked) can craft a payload where `repository.owner.login` is `"OrgA"` (so the correct, low-privilege secret is used and `verify_webhook_signature` passes) while `repository.full_name` is set to `"OrgB/some-repo"`. Because handlers such as `PushHandler`, `StatusHandler`, `CheckSuiteHandler`, and the pull-request family handlers all key off `repository.full_name` via `Handler#stacks`/`Repository.from_github_repo_name`, the forged, validly-signed webhook is applied to Org B's stack — e.g. queuing `GithubSyncJob`, creating commit statuses, or archiving/unarchiving review stacks for a repository the attacker's org never authenticated for [7](#0-6) [8](#0-7) [9](#0-8) .

This mirrors the M-8 pattern precisely: the check ("is this signature valid for organization X") is performed on one identity, but the write ("act on repository Y") is performed using a second, unchecked identity extracted from the same untrusted input, and the code never asserts `X == owner(Y)`.

### Impact Explanation
This crosses a genuine repository/organization trust boundary: a party with limited-scope credentials for their own org's GitHub App installation can cause unauthorized writes against another organization's stack state on the same Shipit instance — including triggering `GithubSyncJob`/commit ingestion, injecting fabricated commit `Status`/check-run state (which factors into merge-gating decisions in `MergeRequest::StatusChecker`), and archiving/unarchiving review stacks. Falsified CI status injected via the `status` webhook can influence `MergeRequest#reject_unless_mergeable!` / `all_status_checks_passed?`, which gates automated merges [10](#0-9) . This is a cross-repository/cross-organization write achieved without holding credentials for the victim org, satisfying the "cross-repository writes" Critical-impact bar, contingent on the instance hosting more than one organization's GitHub App configuration (a documented, supported configuration per `github_app_config`/`github_organizations`).

### Likelihood Explanation
Requires: (1) the Shipit instance to be configured for multiple organizations (each with a distinct `webhook_secret` under `secrets.github[org]`), and (2) the attacker to control one such organization's legitimate webhook secret (e.g., as an admin of their own org's GitHub App installation, or via leak of that org's secret) — which is not itself a "privileged" credential with respect to the victim org, only to their own. Given multi-tenant Shipit deployments are an explicitly supported configuration shape, this is a realistic, moderate-likelihood path for cross-tenant instances.

### Recommendation
After signature verification, re-derive `repository_owner` from the same field used by `Repository.from_github_repo_name`/`payload.dig('repository','full_name')` and assert it matches the organization whose secret verified the signature, rejecting (422) on mismatch. Alternatively, pass the verified `organization` down to `Shipit::Webhooks.for_event(...).each { |handler| handler.call(params, organization:) }` and have `Handler#stacks` scope repository lookup to `Repository.where(owner: organization)` rather than trusting the unchecked `full_name` in isolation.

### Proof of Concept
1. Configure Shipit multi-tenant with `secrets.github["orga"]` and `secrets.github["orgb"]`, each with distinct `webhook_secret` values.
2. As an attacker who has (or leaks) Org A's `webhook_secret`, craft a `push` webhook payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": { "owner": { "login": "orga" }, "full_name": "orgb/victim-repo" }
}
```
3. Compute `X-Hub-Signature` using Org A's `webhook_secret` over the raw body.
4. POST to `/webhooks` with `X-Github-Event: push`. `verify_signature` calls `Shipit.github(organization: "orga")` and successfully verifies the signature [11](#0-10) .
5. `PushHandler#stacks` resolves `Repository.from_github_repo_name("orgb/victim-repo")` and enqueues `GithubSyncJob`/updates commit state for Org B's stack, despite the signature only proving knowledge of Org A's secret [12](#0-11) [4](#0-3) .

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-28)
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
end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L49-54)
```ruby

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/merge_request.rb (L193-206)
```ruby
    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end

    def any_status_checks_failed?
      status = StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec)
      status.failure? || status.error?
    end

    def any_status_checks_missing?
      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).missing?
    end
```
