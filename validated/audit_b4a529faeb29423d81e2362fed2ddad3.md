## Title
`Shipit::Webhooks::Handlers::StatusHandler#process` writes Status rows to *every* stack with a matching commit SHA, bypassing repository scoping - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

## Summary
`PushHandler` and `CheckSuiteHandler` both scope their webhook side effects through `Handler#stacks`, which resolves stacks via `Repository.from_github_repo_name(repository_name)` from the webhook payload's `repository.full_name`. `StatusHandler`, however, calls `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` with no repository filter at all, so a validly-signed status webhook for one repository can write `Status` rows onto `Commit` records belonging to any other stack that happens to persist a commit with the same SHA.

## Finding Description
The binding this engine is supposed to maintain is: every `Status` persisted for a `Commit` == a status that `commit.stack.github_api.statuses(commit.stack.github_repo_name, commit.sha)` actually returned for **that stack's own repository** [1](#0-0) .

`refresh_statuses!` upholds this: it fetches statuses through `stack.github_api.statuses(github_repo_name, sha, ...)`, which is scoped to the stack's own repo/installation token, then calls `create_status_from_github!` per result [1](#0-0) .

The webhook path breaks this binding. `Handler` exposes a properly-scoped `stacks` helper that resolves stacks strictly from the payload's `repository.full_name` [2](#0-1) , and both `PushHandler` [3](#0-2)  and `CheckSuiteHandler` [4](#0-3)  use it. `StatusHandler` instead does:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [5](#0-4) 

This query is global across the `commits` table, unfiltered by `stack_id`/`repository`, even though the payload carries `repository.full_name` (used only for signature verification's `repository_owner`, not for scoping the write) [6](#0-5) .

`create_status_from_github!` then persists a `Status` row keyed on `stack_id` taken from `commit.stack_id`, i.e. the stack that happens to own the matching `Commit` row, not the stack that generated the webhook [7](#0-6) , [8](#0-7) .

Exploit path: Shipit is commonly configured with multiple `Stack` rows tracking the **same** `github_repo_name` (multiple environments, or review-stack-per-PR provisioning, which this engine implements natively) . When a commit SHA is shared across those stacks' commit histories (e.g. a shared ancestor commit on `main` that also exists in a feature/review branch the attacker controls, or a fork with identical history), a status webhook that GitHub legitimately signs and delivers for the attacker-controlled branch/stack's repository will match `Commit.where(sha:)` rows belonging to *other* stacks too - including a protected production stack - and will silently persist a forged `Status` (arbitrary `state`, `description`, `context`, `target_url`, since these are attacker-influenced values in the `status` event body they emitted) onto that unrelated stack's commit, without that stack's own `github_api` ever being called.

None of the listed guards stop this: `verify_signature` only authenticates *that GitHub sent the payload for some known org*, it says nothing about which stacks' commits may be mutated [6](#0-5) ; `drop_unhandled_event` only checks the event type is registered; the `ExplicitParameters` schema in `StatusHandler.params` validates field types/presence, not repository scoping [9](#0-8) ; and no `Repository`/`Stack` model validation restricts `Status.replicate_from_github!` to the stack that produced the webhook.

## Impact Explanation
A forged `Status` can land on a `Commit` belonging to a stack the attacker does not control, without ever passing through that stack's own `github_api.statuses` call. Since `Status` creation drives `enable_ci_on_stack`, `schedule_continuous_delivery`, and deployability checks used to gate merges/deploys [10](#0-9) , this can influence deploy/merge gating logic on a stack/repository the webhook did not originate from - satisfying the "payload for one repository mutating another's stack/commit" Critical impact category. This is repeatable for any pair of stacks that share commit history (multi-environment setups and review-stack provisioning, both first-class Shipit features), and scales to every tenant/stack sharing a base repository, not just a single victim.

## Likelihood Explanation
Requires: (a) the attacker owns/controls a repository or branch for which they can legitimately trigger a signed `status` webhook (achievable by setting a commit status via GitHub's API/UI/CI on their own repo or PR, which the threat model explicitly grants), and (b) a `Commit` with the same SHA also exists under a different stack in the same Shipit install - a condition naturally satisfied by shared ancestor commits across environment stacks or review-stack-per-PR setups, both supported natively by this engine. No secrets, sessions, or elevated GitHub permissions are needed beyond what the threat model already grants.

## Recommendation
Scope `StatusHandler#process` the same way as `PushHandler`/`CheckSuiteHandler`: resolve the target stacks via `Repository.from_github_repo_name(repository_name)` (the inherited `stacks` helper) and restrict the commit lookup/update to `stacks.map(&:commits)` (or a joined query filtering `commits.stack_id` to those stacks), rather than an unscoped `Commit.where(sha:)` across the whole table.

## Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
require 'test_helper'

module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerCrossStackTest < ActiveSupport::TestCase
        test "status webhook must not write a Status onto a commit belonging to a different stack's repository" do
          victim_stack = shipit_stacks(:shipit) # tracks "shopify/shipit-engine"
          attacker_stack = shipit_stacks(:cyclimse) # different repo entirely

          shared_sha = "deadbeef" * 5
          victim_commit = victim_stack.commits.create!(sha: shared_sha, author: shipit_users(:shipit), authored_at: Time.now, committer: shipit_users(:shipit), committed_at: Time.now, message: "shared ancestor")

          # This webhook payload claims to come from attacker_stack's repository, NOT victim_stack's
          payload = {
            'sha' => shared_sha,
            'state' => 'success',
            'description' => 'forged',
            'context' => 'ci/forged',
            'branches' => [{ 'name' => attacker_stack.branch }],
            'repository' => { 'full_name' => attacker_stack.github_repo_name }
          }

          # Binding under test:
          # LHS: victim_commit.statuses created via stack.github_api.statuses scoped to victim_stack's own repo
          # RHS: victim_commit.statuses created by this webhook, whose repository field names attacker_stack's repo
          assert_no_difference -> { victim_commit.statuses.count } do
            StatusHandler.call(payload)
          end
        end
      end
    end
  end
end
```
Expected today: the assertion fails (a `Status` is created on `victim_commit` despite the webhook payload naming `attacker_stack`'s repository), demonstrating that `StatusHandler` violates the scoping binding enforced by `refresh_statuses!`/`github_api.statuses`.

### Citations

**File:** app/models/shipit/commit.rb (L156-169)
```ruby
    def refresh_statuses!
      github_statuses = stack.handle_github_redirections do
        stack.github_api.statuses(github_repo_name, sha, per_page: 100)
      end
      github_statuses.each do |status|
        create_status_from_github!(status)
      end
    end

    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L7-18)
```ruby
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

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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
```

**File:** app/models/shipit/status.rb (L18-22)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

    delegate :broadcast_update, to: :commit

```

**File:** app/models/shipit/status.rb (L23-33)
```ruby
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
