This confirms the vulnerable divergence: `PushHandler#process` and `CheckSuiteHandler#process` both scope through `stacks` (which resolves `Repository.from_github_repo_name(repository_name)&.stacks`), but `StatusHandler#process` does not — it queries `Commit.where(sha: params.sha)` globally across the entire database, ignoring `payload.dig('repository', 'full_name')` entirely.### Title
StatusHandler#process resolves commits by SHA across all repositories, allowing a cross-tenant Status write - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits solely by `sha` via `Commit.where(sha: params.sha)`, with no scoping to the repository that originated the webhook. Every other comparable handler (`PushHandler`, `CheckSuiteHandler`) scopes its writes through the `stacks` helper, which resolves `Repository.from_github_repo_name(payload.dig('repository','full_name'))` first. `StatusHandler` skips this entirely, so a validly-signed webhook claiming to be from repository A can write a `Status` against a commit that actually belongs to stack/repository B, as long as the two share a commit SHA.

### Finding Description
The claimed binding, made explicit: `repository_of(commit.stack) == repository_of(payload)` must hold before any `Status` write is performed for that commit. Tracing the code shows this equality is never checked for the `status` event.

- `Shipit::WebhooksController#create` dispatches the raw parsed JSON payload to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [1](#0-0) , after `verify_signature` checks the HMAC signature against `Shipit.github(organization: repository_owner)` — i.e. against the webhook secret configured for **whatever organization the payload claims** [2](#0-1) .
- `Handler#initialize` only parses/validates the payload shape via `ExplicitParameters`; it exposes a `stacks` helper (`Repository.from_github_repo_name(repository_name)&.stacks`) that other handlers use to scope their queries [3](#0-2) .
- `PushHandler#process` and `CheckSuiteHandler#process` both use this `stacks` scoping before touching any commit [4](#0-3) [5](#0-4) .
- `StatusHandler#process`, in contrast, does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — a global, unscoped lookup that ignores `payload.dig('repository','full_name')` entirely [6](#0-5) .
- `Commit#create_status_from_github!` calls `statuses.replicate_from_github!(stack_id, github_status)` on whichever commit was matched [7](#0-6) .
- `Status` only validates `state` inclusion in `STATES = %w[pending success failure error]` [8](#0-7)  — no repository/authorization check exists at this layer either.

Exploit flow: an attacker who legitimately controls a Shipit-integrated organization/repo (a supported multi-tenant configuration, see `docs/setup.md` "Using Multiple Github Applications" and `test/dummy/config/secrets_double_github_app.yml`) can compute a valid `X-Hub-Signature` for their own org's webhook secret. They send a `status` event whose `sha` matches a commit that also exists in a victim's stack (trivially achievable if the victim repo is public and the attacker forks it — Git SHAs are content-addressed and identical across forks for shared history). The `verify_signature` check passes (it validates against the attacker's own org, which is legitimate), `drop_unhandled_event`/`ExplicitParameters` pass (payload shape is valid), but `StatusHandler#process` then matches and mutates the victim's `Commit`/`Status`/stack state, because no `repository.full_name` equality check is performed. Existing guards (`verify_signature`, `ExplicitParameters` schema, `Status` state validation) never test the repository-match binding, so they cannot prevent this divergence.

### Impact Explanation
An attacker with legitimate access to only their own (unrelated) repository/organization inside a shared Shipit instance can create/mutate `Shipit::Status` records tied to another tenant's commit and stack. Since `Status#state` transitions drive `Commit#add_status`, which fires `deployable_status` webhooks and can enqueue `ProcessMergeRequestsJob` (see `test/models/commits_test.rb` transition table and merge-request scheduling test), this can flip a victim commit from `pending`/`failure` to `success`, unblocking or triggering an unauthorized deploy/merge decision for a stack the attacker has no rights over — a payload for one repository mutating another's stack/commit, matching the Critical impact category. This is repeatable against any commit SHA the attacker can reproduce (e.g. via forking public upstream repos), across all repositories configured on the same Shipit instance.

### Likelihood Explanation
Requires a multi-tenant Shipit deployment (explicitly documented and supported: `docs/setup.md` "Using Multiple Github Applications") where the attacker legitimately owns/controls at least one integrated GitHub organization/repo (so they can produce a validly-signed webhook for their own org) and can find or force a SHA collision with the victim's commit history (trivial for forks of public repos, or for merge commits/cherry-picks that preserve upstream SHAs). Cost is low: no Shipit secrets, sessions, or team membership of the victim are needed — only the attacker's own legitimate webhook credentials for their own tenant. This is fully repeatable and requires no live GitHub access to reproduce (only knowledge of one's own configured webhook secret).

### Recommendation
In `StatusHandler#process`, scope the commit lookup through `stacks` (as `PushHandler`/`CheckSuiteHandler` do) instead of a global `Commit.where(sha:)`, e.g. resolve commits via `stacks.flat_map(&:commits).where(sha: params.sha)` or equivalently restrict to `Repository.from_github_repo_name(repository_name)`'s stacks before matching by SHA, enforcing `repository_of(commit.stack) == repository_of(payload)` before any write.

### Proof of Concept
```ruby
# test/models/webhooks/handlers/status_handler_test.rb
require 'test_helper'

module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerCrossTenantTest < ActiveSupport::TestCase
        test "status event for repo A must not mutate a commit belonging to repo B's stack" do
          victim_repo  = Repository.create!(owner: 'victim-org', name: 'victim-repo')
          victim_stack = Stack.create!(repository: victim_repo, environment: 'production', branch: 'master')
          shared_sha   = '0' * 40 # simulate a SHA shared via fork/shared history
          victim_commit = victim_stack.commits.create!(sha: shared_sha, author: shipit_users(:walrus), authored_at: Time.now, committer: shipit_users(:walrus), committed_at: Time.now, message: 'shared')

          # Attacker's payload claims a different repository (their own), signature verification for
          # that org would pass in the controller layer -- StatusHandler never checks payload['repository'].
          attacker_payload = {
            'sha' => shared_sha,
            'state' => 'success',
            'repository' => { 'full_name' => 'attacker-org/attacker-repo' }
          }

          assert_difference -> { victim_commit.statuses.count }, 1 do
            StatusHandler.call(attacker_payload)
          end

          # Binding check: repository_of(victim_commit.stack) != repository_of(attacker_payload),
          # yet the write succeeded -- proving no repository-match/authorization predicate was consulted.
          assert_not_equal victim_repo.full_name, attacker_payload['repository']['full_name']
          assert_equal 'success', victim_commit.reload.status.state
        end
      end
    end
  end
end
```
This demonstrates the write succeeding for `victim_stack`/`victim_commit` while the payload declares an unrelated repository, with no call to any repository-match or authorization predicate anywhere in `StatusHandler#process`, `Commit#create_status_from_github!`, or `Status` validations.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L15-38)
```ruby
        def self.call(params)
          new(params).process
        end

        attr_reader :params, :payload

        def initialize(payload)
          @payload = payload
          @params = self.class.param_parser.parse!(payload)
        end

        def process
          raise NotImplementedError
        end

        private

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/status.rb (L8-33)
```ruby
    STATES = %w[pending success failure error].freeze
    enum :state, STATES.zip(STATES).to_h

    belongs_to :stack, required: true
    belongs_to :commit, required: true

    deferred_touch commit: :updated_at

    validates :state, inclusion: { in: STATES, allow_blank: true }, presence: true

    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

    delegate :broadcast_update, to: :commit

    class << self
      def replicate_from_github!(stack_id, github_status)
        find_or_create_by!(
          stack_id:,
          state: github_status.state,
          description: github_status.description,
          target_url: github_status.target_url,
          context: github_status.context,
          created_at: github_status.created_at
        )
      end
```
