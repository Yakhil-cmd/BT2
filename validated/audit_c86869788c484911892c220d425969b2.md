This confirms the multi-tenant configuration: `Shipit.github(organization:)` looks up a distinct `GitHubApp` (with its own `webhook_secret`) per organization key in `secrets.github` [1](#0-0) . Combined with the webhook controller and handler behavior, this establishes the exploitable binding mismatch.

### Title
Webhook signature verified against attacker-chosen organization while the acted-upon repository is taken from a separate unverified field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to use for HMAC verification based on `params.dig('repository', 'owner', 'login')` (or `organization.login`), a field read straight from the untrusted, attacker-supplied JSON body [2](#0-1) . Once the signature is accepted, the actual event handler (`Handler#stacks`/`Handler#repository_name`, and every `PullRequest::*Handler#repository`) determines which `Repository`/`Stack` to mutate using a **different** field: `payload.dig('repository', 'full_name')` [3](#0-2) . Nothing ties `repository.owner.login` (the field whose GitHub App secret validated the signature) to `repository.full_name` (the field that actually drives stack lookup, sync, merge, archive, or provisioning actions).

### Finding Description
This mirrors the analog bug class precisely: the signature/authorization is checked against one identity (the organization credited/verified) while the state-changing action is performed using another, unverified identity (the actual repository written to). In the Pod contract, `transferFrom` pulled funds from `operator` (checked) but credited `from` (acted upon) — a mismatch between the verified party and the affected party. Here:

- **Verified side**: `repository_owner` = `params.dig('repository','owner','login')`, used solely to pick which multi-tenant `GitHubApp`'s `webhook_secret` is used in `verify_webhook_signature` [4](#0-3) .
- **Acted-upon side**: `repository.full_name`, used by every handler (`PushHandler` via `Handler#stacks`/`#repository_name`, and the `PullRequest::*` handlers) to resolve `Shipit::Repository.from_github_repo_name(...)` and mutate its stacks [5](#0-4) [6](#0-5) .

In a multi-organization Shipit deployment (`Shipit.github(organization:)` supports one `GitHubApp`/`webhook_secret` per org key under `secrets.github`) [1](#0-0) , any organization owner that has legitimately installed their own GitHub App on Shipit knows their own `webhook_secret` (it's configured by them / their admin, not secret from the org's perspective, and can also leak via their own GitHub App settings). Because the two JSON fields are independently attacker-controlled and never cross-checked, that organization can:

1. Build a JSON payload where `repository.owner.login` = their own org (`attacker-org`), but `repository.full_name` = `victim-org/victim-repo`.
2. Sign the raw body with `attacker-org`'s known `webhook_secret` and set `X-Hub-Signature`.
3. POST to `/webhooks`. `verify_signature` looks up `Shipit.github(organization: 'attacker-org')`, verifies successfully since the signer used the correct secret for that lookup key [4](#0-3) .
4. `Shipit::Webhooks.for_event(event)` dispatches to handlers that resolve the target repository purely from `full_name` — e.g. `PushHandler` triggers `stack.sync_github(expected_head_sha: params.after)` for `victim-org/victim-repo`'s stacks [7](#0-6) , or `PullRequest::ClosedHandler` archives `victim-org/victim-repo`'s review stack [8](#0-7) .

### Impact Explanation
This lets an attacker who legitimately controls (or has installed the Shipit GitHub App on) any single organization forge webhook events against **any other repository/stack registered in the same Shipit instance**, without ever needing that victim organization's `webhook_secret`. Depending on the event/handler exercised this can force out-of-band syncs, archive/unarchive review stacks, or otherwise manipulate merge/deploy state for repositories the attacker has no access to — a cross-repository/cross-tenant integrity break that fits the "cross-repository writes" / "unauthorized deploy" impact bar, since `PushHandler` directly drives `sync_github`, which feeds the deploy pipeline.

### Likelihood Explanation
Exploitable only in multi-organization Shipit configurations (`secrets.github` keyed per-organization) where the attacker legitimately controls one org onboarded to the same Shipit instance — a realistic setup for shared internal deploy tooling serving many teams/orgs. No privileged Shipit session, `ApiClient` token, or GitHub App private key is required; only knowledge of one's own org's webhook secret (which the attacker's org admins possess by design) and the ability to send an HTTP POST.

### Recommendation
Cross-validate that the organization used to select the verifying `GitHubApp` (`repository.owner.login` / `organization.login`) matches the owner embedded in `repository.full_name` before dispatching to handlers, and reject the request (422) on mismatch. Alternatively, derive the app-selection key and the repository-resolution key from the exact same payload field, so verification and action always refer to the same organization/repository.

### Proof of Concept
```
POST /webhooks HTTP/1.1
X-Github-Event: push
X-Hub-Signature: sha1=<HMAC-SHA1 of body using attacker-org's webhook_secret>
Content-Type: application/json

{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
`verify_signature` resolves and validates using `Shipit.github(organization: 'attacker-org')`'s secret (signature matches) [4](#0-3) ; `PushHandler#process` then looks up stacks via `Repository.from_github_repo_name('victim-org/victim-repo')` and calls `sync_github` on them [7](#0-6) , forging a push event for a repository the attacker does not own.

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
