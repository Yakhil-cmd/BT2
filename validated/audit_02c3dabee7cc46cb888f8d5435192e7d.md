This confirms the pattern: `PushHandler#process` and `CheckSuiteHandler#process` scope strictly through `stacks` (derived from `Repository.from_github_repo_name(repository_name)`), but `StatusHandler#process` does not — it looks up commits by `Commit.where(sha: params.sha)` globally, with no repository check at all.### Title
`StatusHandler#process` applies forged CI statuses to commits in any stack sharing the target sha, with no repository check - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
Unlike `PushHandler` and `CheckSuiteHandler`, which resolve the target `stacks` from the webhook's `repository.full_name` before touching any commit, `StatusHandler#process` looks up commits purely by `Commit.where(sha: params.sha)` and calls `commit.create_status_from_github!(params)` on every match, regardless of which repository the payload names. Because `Commit` rows are only unique per `(sha, stack_id)` and not globally, a `status` event that is legitimately signed for one tracked repository can attach a `Status` row to a `Commit` belonging to a completely different stack/repository if that stack happens to have a `Commit` record with the same sha.

### Finding Description
The binding that should hold is: `UndeployedCommit#deploy_state` for a victim stack's commit == a state derived only from `Status` rows created from webhook payloads whose `repository.full_name` matches that same stack's repository.

Code path:
- `WebhooksController#create` dispatches the parsed JSON payload to `Shipit::Webhooks.for_event(event)` handlers [1](#0-0) , after `verify_signature` checks the HMAC against `Shipit.github(organization: repository_owner)` [2](#0-1) .
- `Handler` exposes a `stacks` helper that correctly resolves the target stacks from `payload.dig('repository', 'full_name')` via `Repository.from_github_repo_name` [3](#0-2) .
- `PushHandler#process` and `CheckSuiteHandler#process` both use this `stacks` scope before touching any commit [4](#0-3) [5](#0-4) .
- `StatusHandler#process`, however, never calls `stacks` or checks `repository_name` at all - it queries `Commit.where(sha: params.sha)` globally and writes a `Status` for every match: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [6](#0-5) .
- `create_status_from_github!` writes the status using that individual commit's own `stack_id` [7](#0-6) , and the `commits` table only enforces uniqueness on `(sha, stack_id)`, not on `sha` alone [8](#0-7) , i.e. the same sha can legitimately exist as separate `Commit` rows in unrelated stacks.
- `UndeployedCommit#deploy_state` and `Stack#branch_status`/`deployable?` then derive their green/red state purely from those `Status` rows [9](#0-8) , feeding `Api::DeploysController#create` -> `Stack#trigger_deploy`.

Root cause: `StatusHandler` is the only webhook handler in this class hierarchy that omits the `repository_name`/`stacks` scoping check present in its siblings, so the repository claimed in the payload is never validated against the commit being mutated.

Attacker path: this requires the same commit sha to exist as tracked `Commit` rows in two different stacks (a "victim" stack and a stack the attacker can trigger a genuinely-signed `status` event for, e.g. their own fork covered by the same GitHub App/webhook secret as the victim's org, or a second Shipit stack pointing at a shared-history repository). Given that, the attacker sets a `success` status on that shared-sha commit in their own controllable repo; GitHub delivers a validly-signed `status` webhook; `StatusHandler#process` applies it to every `Commit` with that sha, including the victim's, flipping `UndeployedCommit#deploy_state` to `allowed` on the victim's dashboard for a commit that never actually passed CI in the victim's own pipeline.

Existing guards do not stop this: `verify_signature` only authenticates that the payload came from a known GitHub organization/App, not that the payload's repository matches the commit being updated; `drop_unhandled_event` and the `ExplicitParameters` schema for `StatusHandler` (`sha`, `state`, `branches`, etc.) never require or check `repository.full_name`.

### Impact Explanation
This is a payload for one repository (or fork) mutating another stack's commit state (`Status` rows), matching the Critical category "a payload for one repository mutating another's stack, commit, task or team." A falsified `allowed`/`success` `deploy_state` on the victim dashboard can lead an authorized operator to click deploy, causing `Stack#trigger_deploy` to run `Command#start` against the victim's real repository/host using the app's `GITHUB_TOKEN` for a commit whose actual CI state on the victim repo was `pending`/`blocked`/`failure`. Repeatability is bounded by how many times an sha collision with a victim's tracked commit can be engineered/found; it is not a one-shot bug, but it is not trivially reusable against *arbitrary* unrelated repositories without a shared commit sha (either shared git ancestry via forks or a deliberately reproduced commit with identical tree/parents/author/committer metadata).

### Likelihood Explanation
Exploitation requires: (1) the attacker's own repository (or another repo they can produce genuinely-signed `status` events for) to be covered by the same GitHub App installation/webhook secret Shipit trusts for the victim's organization (`Shipit.github(organization: repository_owner)`), and (2) a `Commit` row with an identical sha already tracked under the victim stack — realistically achievable via forks that share unmerged/merged ancestor commits, or by an attacker recreating a commit with byte-identical tree/parent/author/committer/timestamp/message to reproduce the same sha, both of which are plausible for public open-source repositories but require specific, non-trivial setup (GitHub App scope covering the attacker's repository is typically controlled by org admins, not the attacker). This makes the finding architecturally real and demonstrable in isolation (calling `StatusHandler.call` directly with a payload whose `repository` doesn't match the target commit's stack), but its full end-to-end exploitation against an arbitrary victim depends on infrastructure/org configuration outside strict attacker control.

### Recommendation
Scope `StatusHandler#process` the same way as `PushHandler`/`CheckSuiteHandler`: resolve the webhook's `repository.full_name` to `stacks`, and only update `Status` rows on commits belonging to those stacks, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or `Commit.where(sha: params.sha, stack: stacks)`, instead of the unscoped `Commit.where(sha: params.sha)`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
require 'test_helper'

module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerCrossRepoTest < ActiveSupport::TestCase
        test "a status payload for a different repository must not flip an unrelated stack's commit state" do
          victim_stack = shipit_stacks(:shipit) # repo: shopify/shipit-engine (example)
          attacker_stack = shipit_stacks(:cyclimse) # different repo entirely

          shared_sha = "deadbeef" * 5

          victim_commit = victim_stack.commits.create!(sha: shared_sha, message: "victim work", authored_at: Time.now, committed_at: Time.now)
          attacker_stack.commits.create!(sha: shared_sha, message: "attacker work", authored_at: Time.now, committed_at: Time.now)

          # sanity: victim commit currently has no successful status -> not deployable/allowed
          undeployed = UndeployedCommit.new(victim_commit, index: 0)
          before_state = undeployed.deploy_state
          refute_equal 'allowed', before_state

          # forged payload names the ATTACKER's repository, not the victim's
          forged_payload = {
            'sha' => shared_sha,
            'state' => 'success',
            'context' => 'ci/forged',
            'repository' => { 'full_name' => attacker_stack.repository.full_name },
            'branches' => [{ 'name' => attacker_stack.branch }]
          }

          StatusHandler.call(forged_payload)

          # BROKEN BINDING: victim commit's deploy_state flips to 'allowed'
          # even though no status naming victim_stack.repository.full_name was ever sent.
          after_state = UndeployedCommit.new(victim_commit.reload, index: 0).deploy_state
          assert_equal before_state, after_state, "victim stack's deploy_state must not change from a status naming a different repository"
        end
      end
    end
  end
end
```
This test creates two `Commit` rows sharing one sha under two unrelated stacks, sends a `StatusHandler` payload naming only the attacker's repository, and asserts the victim's `UndeployedCommit#deploy_state` is unaffected. As written against current code, this assertion fails, demonstrating the cross-stack mutation.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb (L1-5)
```ruby
class IndexCommitsOnStackIdAndSha < ActiveRecord::Migration[5.1]
  def change
    add_index :commits, %i(sha stack_id), unique: true
  end
end
```

**File:** app/models/shipit/undeployed_commit.rb (L18-31)
```ruby
    def deploy_state(bypass_safeties = false)
      state = deployable? ? 'allowed' : status.state

      unless bypass_safeties
        if blocked?
          state = 'blocked'
        elsif locked?
          state = 'locked'
        elsif stack.active_task?
          state = 'deploying'
        end
      end
      state
    end
```
