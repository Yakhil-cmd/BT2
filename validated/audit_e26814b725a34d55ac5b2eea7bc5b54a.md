### Title
`StatusHandler#process` writes commit statuses to any repository's commits via unscoped `Commit.where(sha:)`, bypassing repo-scope authorization for the `status` webhook - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`Shipit::Webhooks.for_event('status')` resolves to exactly one handler, `Handlers::StatusHandler`, and `WebhooksController#create` invokes `handler.call(params)` for it with no repository-scope check of its own. `StatusHandler#process` queries `Commit.where(sha: params.sha)` globally across every stack/repository in the database, so the controller's org-signature check is the only gate, and that gate authenticates the sender as the claimed GitHub organization, not that the `sha` in the payload belongs to that organization's repository.

### Finding Description
Binding claimed by the question: `verify_signature(repository_owner) ∧ StatusHandler#process-scope == REPOSITORY_SCOPE`. Trace:

- `WebhooksController#create` parses the body and does `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` with no further scoping logic in the controller itself. [1](#0-0) 
- `Shipit::Webhooks.default_handlers` maps `'status' => [Handlers::StatusHandler]` only, and `for_event` returns exactly that array. [2](#0-1) 
- `verify_signature` authenticates using `Shipit.github(organization: repository_owner)` and the HMAC signature, i.e. it proves the sender knows the webhook secret configured for `repository_owner` (the org named in the payload's `repository.owner.login`). It does not scope anything to a specific repository or stack, nor to the `sha` value. [3](#0-2) 
- `StatusHandler#process` then runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — this is a global, unscoped ActiveRecord query against the `commits` table, matched only by `sha`, with no join/filter on `stack_id`, `repository_id`, or the `repository_owner`/`repository.full_name` that was authenticated in `verify_signature`. [4](#0-3) 
- Contrast with `CheckSuiteHandler`, which does scope to `stacks.where(branch: ...)` (derived from `Repository.from_github_repo_name(repository_name)`) before touching commits — showing the codebase's own intended pattern for repo-scoped webhook processing is absent in `StatusHandler`. [5](#0-4) 
- The base `Handler` class does define a `stacks`/`repository_name` helper meant to scope lookups to the repository named in the payload, but `StatusHandler` does not use it. [6](#0-5) 

Root cause: authentication (org signature) and authorization (repo scope) do not compose to repository scope for this handler — the handler ignores `payload['repository']` entirely when selecting which `Commit` rows to mutate, so the conjunction collapses to authentication alone, exactly as the question posits.

Attack path: An attacker who legitimately controls a GitHub organization/repo that is itself configured as a Shipit-integrated organization (has a `webhook_secret` in this Shipit instance) can pass `verify_signature` for their own org. They then send a `status` event whose `sha` matches a commit that exists in a *different* organization's/stack's `commits` table (e.g. because the target repository is public and the attacker has locally computed or observed the target's commit SHA — git SHAs are not secret, they are derived from tree content and are publicly visible on GitHub for any repo the attacker can view, and commits from a shared upstream fork can carry across forks). `StatusHandler` will happily write a `Status` record onto the victim's `Commit`, and `create_status_from_github!` → `add_status`/`schedule_continuous_delivery` can trigger `ContinuousDeliveryJob` and downstream deploy scheduling if the transition makes the commit `deployable?`. [7](#0-6) [8](#0-7) [9](#0-8) 

Existing guards checked and found insufficient: `verify_signature` only authenticates "this payload came from the org named in the payload", not "this `sha` belongs to a repository owned by that org" [10](#0-9) ; `drop_unhandled_event` only checks that a handler array is non-empty for the event name [11](#0-10) ; the `ExplicitParameters` schema for `StatusHandler` validates types (`sha`, `state`, etc.) but does not require or validate a `repository` block at all [12](#0-11) , unlike e.g. `LabelCapturingHandler` which does `requires :repository do requires :full_name, String end` [13](#0-12) . None of these enforce that the commit being mutated actually belongs to the authenticated repository/org.

### Impact Explanation
A `status` webhook authenticated only as "I know org A's webhook secret" can write a `Status` row (state/description/target_url/context) onto a `Commit` belonging to an entirely different stack/organization, and can trigger `schedule_continuous_delivery` → `ContinuousDeliveryJob`, potentially initiating an unauthorized deploy for a repository the attacker never authenticated against. This matches the "Critical" category: a payload for one repository mutating another's stack/commit, and potentially causing an unauthorized deploy. This is repeatable against any commit sha the attacker can discover (which is trivial for public repos, since SHAs aren't secrets), across every tenant/org configured on the same Shipit instance whose commits share a SHA with something reachable by the attacker.

### Likelihood Explanation
The attacker must control/have signature access to at least one org that is itself configured in this Shipit instance (has its own `webhook_secret`) — this is a real precondition and constrains the attack to a multi-tenant Shipit deployment. Given that, no further privilege is needed: no session, no maintainer role, no knowledge of the victim org's secret. Discovering a colliding SHA is easy when repos share history (forks, cherry-picks, monorepo mirrors) or when the attacker merely wants to replay a target's publicly known commit sha. The exploit is a single crafted HTTP POST, fully repeatable.

### Recommendation
In `StatusHandler#process`, scope the `Commit` lookup to the repository named in the payload (mirroring `Handler#stacks`/`CheckSuiteHandler`'s pattern), e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or `Commit.where(sha: params.sha, stack_id: stacks.ids)`, and add `requires :repository do requires :full_name, String end` to the `StatusHandler` params schema so the repository is present and used for scoping instead of only being used for the org-level signature check.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
require 'test_helper'

module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerCrossTenantTest < ActiveSupport::TestCase
        test "status event authenticated for org A writes a status on org B's commit sharing the same sha" do
          victim_commit = shipit_commits(:first) # belongs to stack under a different repo/org than attacker
          attacker_repo_full_name = "attacker-org/unrelated-repo"

          payload = {
            'sha' => victim_commit.sha,
            'state' => 'success',
            'context' => 'ci/attacker',
            'repository' => { 'full_name' => attacker_repo_full_name, 'owner' => { 'login' => 'attacker-org' } }
          }

          # Equality claimed by controller: signature-auth(attacker-org) == authorization(repository scope)
          # Left side: verify_signature only checks attacker-org's secret (simulated true)
          # Right side: StatusHandler#process should only touch commits under attacker-org's repository
          assert_difference -> { victim_commit.statuses.count }, 1 do
            StatusHandler.call(payload)
          end
          # Demonstrates the two sides do NOT match: an org-A-authenticated payload
          # mutated a commit that belongs to an unrelated org/stack.
        end
      end
    end
  end
end
```

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L19-22)
```ruby
    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
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

**File:** app/models/shipit/webhooks.rb (L6-41)
```ruby
      def default_handlers
        {
          'push' => [Handlers::PushHandler],
          'pull_request' => [
            Handlers::PullRequest::OpenedHandler,
            Handlers::PullRequest::ClosedHandler,
            Handlers::PullRequest::ReopenedHandler,
            Handlers::PullRequest::EditedHandler,
            Handlers::PullRequest::AssignedHandler,
            Handlers::PullRequest::LabeledHandler,
            Handlers::PullRequest::UnlabeledHandler,
            Handlers::PullRequest::LabelCapturingHandler
          ],
          'status' => [Handlers::StatusHandler],
          'membership' => [Handlers::MembershipHandler],
          'check_suite' => [Handlers::CheckSuiteHandler]
        }
      end

      def handlers
        @handlers ||= reset_handlers!
      end

      def reset_handlers!
        @handlers = default_handlers
      end

      def register_handler(event, callable = nil, &block)
        handlers[event] ||= []
        handlers[event] << callable if callable
        handlers[event] << block if block_given?
      end

      def for_event(event)
        handlers.fetch(event) { [] }
      end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L6-18)
```ruby
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
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/commit.rb (L24-25)
```ruby
    after_commit :schedule_refresh_statuses!, :schedule_refresh_check_runs!, :schedule_fetch_stats!,
                 :schedule_continuous_delivery, on: :create
```

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L33-35)
```ruby
            requires :repository do
              requires :full_name, String
            end
```
