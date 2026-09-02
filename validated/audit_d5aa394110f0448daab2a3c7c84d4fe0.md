Confirmed: `Handler#stacks` and `Handler#repository_name` resolve exclusively from `payload.dig('repository', 'full_name')` [1](#0-0) , while `WebhooksController#verify_signature` selects the GitHub App/secret to verify against using a *different* field pair: `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [2](#0-1) . Nothing enforces that `repository.owner.login` matches `repository.full_name`'s owner segment. This confirms the binding break I hypothesized.

### Title
Webhook signature verified against `repository.owner.login`/`organization.login`, but every event handler acts on the independent, unauthenticated `repository.full_name` field, letting any org's webhook secret sign events against another org's stacks - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
In a multi-GitHub-App deployment (`config/secrets.yml` with per-organization `github:` sub-keys, as documented in `docs/setup.md` "Using Multiple Github Applications" section), `WebhooksController#verify_signature` picks which organization's `webhook_secret` to validate the HMAC against using `repository_owner`, derived from `params.dig('repository', 'owner', 'login')` or `params.dig('organization', 'login')`. Once the HMAC check passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` hands the *entire, attacker-controlled* JSON body to handlers. Every handler (`PushHandler`, `StatusHandler`, all `PullRequest::*Handler`s) resolves the target `Stack`/`Repository` purely from `payload.dig('repository', 'full_name')` via `Handler#stacks`/`Handler#repository_name`, a field that is completely independent of the `repository.owner.login`/`organization.login` value used for signature selection. Nothing cross-checks that these two fields refer to the same repository.

### Finding Description
The binding that should hold is: *organization whose secret authenticated the request* == *organization/repository the handler is permitted to mutate*. It does not hold, because:

1. `verify_signature` in `app/controllers/shipit/webhooks_controller.rb` computes `repository_owner` from `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` and fetches `Shipit.github(organization: repository_owner)`, then verifies the raw POST body's HMAC using only that organization's `webhook_secret` [2](#0-1) .
2. On success, `create` dispatches the *entire raw JSON body* to every registered handler for the event [3](#0-2) .
3. `Shipit::Webhooks::Handlers::Handler#stacks` and `#repository_name` resolve the acted-upon repository strictly from `payload.dig('repository', 'full_name')` [1](#0-0) , and every concrete handler (`PushHandler`, `StatusHandler`, `PullRequest::OpenedHandler`, etc.) does the same via `Shipit::Repository.from_github_repo_name(params.repository.full_name)` [4](#0-3) [5](#0-4) [6](#0-5) .
4. `Shipit.github` resolves apps per-organization from `secrets.github`, and the multi-org schema is explicitly documented and supported (`lib/shipit.rb#github`, `docs/setup.md` "Using Multiple Github Applications") [7](#0-6) .

Because the raw HMAC only proves knowledge of *some* configured org's `webhook_secret` - not that the payload's `repository.full_name` belongs to that org - anyone who legitimately administers (or has otherwise obtained the webhook secret of) any one of the multiple GitHub organizations configured on a shared Shipit instance can forge a webhook body where `repository.owner.login`/`organization.login` names their own org (to select their known secret) while `repository.full_name` names a *different* org's tracked repository, and sign it with their own secret. The equality that breaks is: `org authenticated via webhook_secret` ≠ `repository the handler is allowed to write`.

### Impact Explanation
This lets an attacker who legitimately controls webhooks for Org A (one tenant on a shared multi-org Shipit instance) inject forged GitHub events against Org B's tracked stacks:
- `StatusHandler` lets them create arbitrary commit `Status` records (`state: success`) for any commit SHA already known to Shipit under Org B's repository, which can flip a commit to `deployable?` and trigger `stack.schedule_continuous_delivery` / `ProcessMergeRequestsJob`, causing an **unauthorized deploy** through continuous deployment for a repository they don't own, bypassing GitHub's real CI checks (`app/models/shipit/status.rb`, `app/models/shipit/commit.rb`).
- `PushHandler` lets them queue `GithubSyncJob` with an attacker-chosen `expected_head_sha` for Org B's branch.
- The `PullRequest::*Handler`s let them create/archive/unarchive Org B's review stacks by crafting `pull_request`/`repository` fields.

This satisfies the "unauthorized deploy" High/Critical impact bar without requiring any Shipit session, `ApiClient` token, or privileged Shipit account - only knowledge of a webhook secret belonging to any one org configured on the instance.

### Likelihood Explanation
Requires: (a) the deployment to use the documented multi-organization `github:` secrets schema (explicitly supported, not a misconfiguration), and (b) the attacker to know the `webhook_secret` for at least one of the configured organizations (e.g., they administer that org's GitHub App/webhook settings, or the secret otherwise leaks) while targeting a different org tracked on the same instance. This is a realistic scenario for shared/multi-tenant Shipit deployments serving several GitHub orgs, which is exactly the use case the multi-org config exists for.

### Recommendation
After selecting the GitHub App by `repository_owner` for signature verification, re-derive the owner from `params.dig('repository', 'full_name')` (or `params.dig('repository', 'owner', 'login')`) and require it to match the organization whose secret validated the signature before dispatching to handlers; alternatively, have `Handler#repository_name`/`#stacks` cross-check against the verified organization passed down from the controller instead of trusting `repository.full_name` alone.

### Proof of Concept
1. Configure Shipit with two orgs, `OrgA` and `OrgB`, each with its own `webhook_secret` (multi-org schema per `docs/setup.md`).
2. Attacker knows `OrgA`'s `webhook_secret` (e.g., they are the GitHub org admin who configured `OrgA`'s Shipit webhook).
3. Attacker builds a `status` event body:
```json
{
  "sha": "<existing-org-b-commit-sha>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" }
}
```
4. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(OrgA_webhook_secret, raw_body)>` and POSTs to `/webhooks` with `X-Github-Event: status`.
5. `WebhooksController#verify_signature` computes `repository_owner = "OrgA"`, fetches `Shipit.github(organization: "OrgA")`, and successfully verifies the HMAC using `OrgA`'s secret.
6. `Shipit::Webhooks::Handlers::StatusHandler#process` runs `Commit.where(sha: params.sha)` - resolved purely from the global `Commit` table (not scoped by verified org) - and calls `create_status_from_github!`, creating a `success` status for a commit belonging to `OrgB/victim-repo`, potentially unblocking continuous deployment for a repository the attacker does not control.

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-24)
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
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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
