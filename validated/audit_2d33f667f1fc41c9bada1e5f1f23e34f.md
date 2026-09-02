### Title
Webhook signature is verified against the `repository.owner.login` GitHub App while the mutation is driven by the independent `repository.full_name` field, allowing cross-repository writes - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App secret to validate the HMAC signature against using `repository_owner`, which is read from `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`) [1](#0-0) . That method resolves `repository_owner` from a distinct field in the same attacker-supplied JSON body [2](#0-1) . However, every event handler that actually mutates state resolves the target `Stack`/`Repository` from a *different* field of the same body: `payload.dig('repository', 'full_name')` [3](#0-2) , used by `PushHandler#process` to look up and sync stacks [4](#0-3)  and by `CheckSuiteHandler#process` to schedule check-run refreshes [5](#0-4) .

### Finding Description
The binding that should hold is: **the organization whose GitHub App secret authenticated the payload == the repository that the payload's handler acts on.** The controller only verifies the payload is a validly-signed webhook for *some* app tied to `repository.owner.login`/`organization.login`; it never checks that `repository.full_name` actually belongs to that same owner. Since `repository.owner.login` and `repository.full_name` are two independent, attacker-controlled JSON keys in the same POST body, and the `WebhooksController` route is public/unauthenticated (only signature-gated, no session or `ApiClient` token required) [6](#0-5) , an attacker who legitimately installs the multi-tenant GitHub App on their own organization can craft a webhook body whose `repository.owner.login`/`organization.login` names their own org (so `verify_signature` picks and matches their own app's secret) while `repository.full_name` names a victim org/repo whose `Stack` is tracked by this Shipit instance. `Handler#stacks` resolves via `Repository.from_github_repo_name(repository_name)` purely from `full_name` with no cross-check against the verified owner [3](#0-2) .

### Impact Explanation
Because `PushHandler` calls `stack.sync_github(expected_head_sha: params.after)` on stacks resolved purely from `repository.full_name` [4](#0-3) , and `Stack#trigger_continuous_delivery`/`continuous_delivery_resumed!` react to newly-synced commits for stacks with `continuous_deployment: true` [7](#0-6) , this can cause GithubSyncJob-driven state changes and potentially trigger an unauthorized deploy against a victim's stack that the attacker does not own — meeting the "unauthorized deploy" Critical-impact bar. It is analogous to the reported bug class: a single payload call overwrites/acts on state (`Stack`/deploy pipeline) that should be scoped and protected by a separate binding (owner-of-signature) which the code fails to re-verify, mirroring how `VaderBond.deposit()` blindly overwrote existing bond state using attacker-influenced call data without re-validating the binding to the correct depositor.

### Likelihood Explanation
Likelihood is moderate-to-high in any deployment where the GitHub App is (or can be) installed by multiple, mutually-untrusted organizations (the documented multi-tenant secrets setup supports multiple apps, see `config/secrets.development.example.yml`/`test/dummy/config/secrets_double_github_app.yml` referenced by `lib/shipit/github_app.rb`). Any org that can install the app (a normal, unprivileged GitHub action) obtains a validly-signed webhook channel and can freely set `repository.full_name` to any tracked repo string without further authorization checks.

### Recommendation
In `WebhooksController#verify_signature`, after resolving the app via `repository_owner`, explicitly assert that `repository_owner` equals the owner segment of `repository.full_name` (and of `organization.login` when both are present) before dispatching to handlers; alternatively, have `Handler#stacks`/`Handler#repository_name` cross-check the resolved `Repository#owner`/organization against the value used to select the verifying `github_app`, and reject the webhook (422) on mismatch.

### Proof of Concept
1. Attacker creates GitHub organization `attacker-org` and installs the Shipit GitHub App on it, obtaining a legitimately signed webhook delivery channel (webhook secret is per-app, shared across all installs of that app).
2. Attacker crafts and POSTs to `/webhooks` with `X-Github-Event: push`, a valid `X-Hub-Signature` computed with the app secret tied to `attacker-org`, and a JSON body: `{"repository": {"owner": {"login": "attacker-org"}, "full_name": "victim-org/victim-repo"}, "ref": "refs/heads/main", "after": "<attacker-chosen sha already known to exist>"}`.
3. `verify_signature` resolves `repository_owner` = `"attacker-org"`, loads that org's app, and successfully verifies the signature [8](#0-7) .
4. `PushHandler#process` resolves stacks via `Repository.from_github_repo_name("victim-org/victim-repo")` (from `Handler#repository_name`) and calls `stack.sync_github(expected_head_sha: ...)` for every matching branch stack, even though the signature only proves control of `attacker-org`, not `victim-org` [4](#0-3) [3](#0-2) .

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L1-16)
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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```

**File:** app/models/shipit/stack.rb (L129-133)
```ruby
    def self.schedule_continuous_delivery
      not_archived.where(continuous_deployment: true).find_each do |stack|
        ContinuousDeliveryJob.perform_later(stack)
      end
    end
```
