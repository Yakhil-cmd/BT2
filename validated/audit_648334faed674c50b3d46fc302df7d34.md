### Title
Cross-repository status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves target commits purely by `sha`, with no check that the commit's owning `stack`/`repository` matches the repository that authenticated the incoming webhook. Since the `Handler` base class already provides a `repository_name`/`stacks` scoping helper that this handler ignores, any repository whose webhook signature verifies (e.g., an attacker's own fork that shares a SHA with `victim`'s repo through common git history) can write a `Status` onto a commit belonging to a completely different tenant's stack, including one currently inside an active `Task`'s deploy range.

### Finding Description
The binding the security model requires is: `payload.dig('repository','full_name') == commit.stack.repository.full_name` for every commit mutated by a webhook. This binding is violated.

Trace:
- `WebhooksController#create` dispatches the parsed JSON payload to `Shipit::Webhooks.for_event(event)` handlers [1](#0-0) .
- `verify_signature` only checks that the payload was HMAC-signed by the GitHub App belonging to `repository_owner` (`params.dig('repository','owner','login')`); it says nothing about which commits may be mutated, only that *some* registered organization's app produced the payload [2](#0-1) .
- The base `Handler` class exposes a `stacks`/`repository_name` helper intended to scope work to the repository named in the payload [3](#0-2) , but `StatusHandler#process` does not use it at all:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [4](#0-3) 
- `Commit` has no uniqueness constraint tying `sha` to a single stack/repository in this query — the lookup is global across the entire `commits` table, matching any commit row with that SHA regardless of which `stack_id`/repository it belongs to.
- `create_status_from_github!` unconditionally creates/replicates the status for whatever commit was matched [5](#0-4) .
- Downstream, `Commit#active?` (`stack.active_task.includes_commit?(self)`) and `Stack#active_task` (`tasks.current`) consult exactly this mutated status/state through `deployable?`, `blocked?`, `deploy_state`, and `next_expected_commit_to_deploy` [6](#0-5) [7](#0-6) [8](#0-7) .

Attack: an attacker who owns a repository/fork that shares a commit SHA with `victim`'s stack (git preserves SHAs across forks until history diverges) sends a legitimately-signed `status` webhook from their own repo/organization. `verify_signature` passes because it only validates that the payload came from a real, registered GitHub organization — the attacker's own. `StatusHandler#process` then looks up `Commit.where(sha: ...)` globally, finds the row belonging to `victim`'s stack, and writes a forged `Status` (`state: 'success'`, `'failure'`, etc.) onto it, mutating `deployable?`/`blocked?`/`active?` for a commit inside `victim`'s in-flight `Task` range — despite `victim`'s repository never having authenticated this mutation.

None of the existing guards prevent this: `verify_signature` authenticates the *organization*, not the *commit ownership*; `drop_unhandled_event` only filters unsupported event types; `ExplicitParameters` only validates the shape of `sha`/`state`/etc., not their target scope; there is no `Repository`/`Stack` equality check anywhere in `StatusHandler`.

### Impact Explanation
An attacker who controls any repository onto which Shipit's GitHub App is installed can forge commit status state for a commit belonging to an unrelated tenant's stack, as long as the SHA is shared (typical of forks). This can flip `deployable?`/`blocked?` for a commit currently inside `victim`'s active deploy/rollback range, interfering with in-flight deploy validation decisions (e.g., making a commit appear passing/failing to logic that consults `commit.status`/`deployable?`), and generally corrupts `victim`'s commit/status history — this is a payload from one repository mutating another repository's `Commit`/`Status` records, matching the "Critical: a payload for one repository mutating another's stack, commit, task" category. It is repeatable against any tenant sharing a SHA with an attacker-controlled repository (most straightforwardly, any public fork relationship).

### Likelihood Explanation
Preconditions: (1) attacker owns/controls a repository with Shipit's GitHub App/webhook installed (feasible if Shipit is used as a multi-tenant service where any GitHub org can install the app), (2) that repository shares at least one commit SHA with `victim`'s tracked stack (trivially true for any fork that hasn't fully diverged, or for any repo that merged/cherry-picked the same commit), (3) `victim` has an active `Task` whose range includes that SHA. Attacker cost is a single signed webhook POST from their own repository — no secrets, tokens, or privileged roles required. This is fully repeatable and requires no timing race beyond having an active task in progress.

### Recommendation
Scope `StatusHandler#process` (and any other SHA-keyed webhook handler) to only mutate commits belonging to the stack(s) associated with the authenticated `repository_name` from the payload, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or equivalently filter `Commit.where(sha: params.sha)` by `stack_id: stacks.pluck(:id)`, reusing the existing `Handler#stacks` helper instead of a bare global `Commit.where(sha:)` lookup.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
require 'test_helper'

module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerCrossRepoTest < ActiveSupport::TestCase
        setup do
          @victim_repo  = Repository.create!(owner: 'victim', name: 'app')
          @victim_stack = Stack.create!(repository: @victim_repo, environment: 'production', branch: 'main')
          @shared_sha   = 'a' * 40
          @commit = @victim_stack.commits.create!(sha: @shared_sha, message: 'shared history', author: AnonymousUser.new)

          # victim has an active task whose range includes @commit
          @task = @victim_stack.trigger_deploy(@commit, AnonymousUser.new)
          assert @victim_stack.active_task?
          assert @commit.active?

          @attacker_repo = Repository.create!(owner: 'attacker', name: 'fork')
          # attacker repo never contains @victim_stack; only shares the sha value
        end

        test "status webhook authenticated by attacker's repository must not mutate victim's in-range commit" do
          before_state = @commit.reload.status.state

          payload = {
            'sha' => @shared_sha,
            'state' => 'failure',
            'repository' => { 'full_name' => @attacker_repo.full_name, 'owner' => { 'login' => 'attacker' } }
          }
          StatusHandler.call(payload)

          after_state = @commit.reload.status.state

          # Binding under test: repository that authenticated the webhook == repository owning the mutated commit
          refute_equal @attacker_repo.full_name, @victim_repo.full_name
          assert_equal before_state, after_state,
            "attacker-authenticated webhook must not change victim's in-flight commit status/active? state"
        end
      end
    end
  end
end
```
This test demonstrates that, with the current implementation, `StatusHandler#process`'s unscoped `Commit.where(sha:)` lookup allows the `after_state` assertion to fail (the status mutates), proving the cross-repository forgery against `victim`'s active-task commit range.

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

**File:** app/models/shipit/commit.rb (L221-237)
```ruby
    def active?
      return false unless stack.active_task?

      stack.active_task.includes_commit?(self)
    end

    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end

    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
    end
```

**File:** app/models/shipit/stack.rb (L459-467)
```ruby
    def active_task?
      !!active_task
    end

    def active_task
      return @active_task if defined?(@active_task)

      @active_task ||= tasks.current
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
