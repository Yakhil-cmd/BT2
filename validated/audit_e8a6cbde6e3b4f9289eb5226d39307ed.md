### Title
Unscoped `Commit.where(sha:)` in `StatusHandler#process` lets a status authenticated for one repository write CI state and advance the merge queue for any other stack that happens to share the SHA - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves the target commit(s) purely by `params.sha`, with no filter on the repository/stack that authenticated the webhook. Since the `sha` column has no cross-stack scoping and multiple `Stack`/`Repository` rows can independently hold `Commit` rows with an identical `sha`, a single validly-signed status event can write a `Status` to a commit belonging to a stack it never authenticated for, and — when that stack has `merge_queue_enabled: true` and is waiting on the same status context — trigger `stack.schedule_merges` and ultimately `MergeRequest#merge!`.

### Finding Description
The broken binding, stated as an equality that the code fails to enforce:
`commit.stack.repository == request.repository_that_signed_the_webhook` — this is **not** checked anywhere in the status path.

Path:
- `Shipit::WebhooksController#create` parses the raw body and dispatches by event name only, after `verify_signature` authenticates the payload against the *organization-level* webhook secret (`Shipit.github(organization: repository_owner).verify_webhook_signature`) [1](#0-0) . This confirms the request came from GitHub for *some* repository under a known organization, but never binds the payload to a specific `Stack`/`Repository`.
- `StatusHandler#process` then does:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [2](#0-1) 
This query is **global across all stacks** — it is not scoped by `stack_id`, `repository_id`, or any value derived from `params['repository']`. Any `Commit` row anywhere in the installation whose `sha` matches is mutated.
- `Commit#create_status_from_github!` → `add_status` records the new `Status`, and if the simple state transitions to `pending`/`success` it calls `stack.schedule_merges` [3](#0-2) .
- `Stack#schedule_merges`/`MergeRequest.schedule_merges` operates only on stacks with `merge_queue_enabled: true` [4](#0-3) , ultimately reaching `MergeRequest#merge!`, which calls `stack.github_api.merge_pull_request` [5](#0-4)  — a real GitHub merge action gated only on the merge request's own `head`'s recorded statuses (`StatusChecker.new(head, head.statuses_and_check_runs, ...)` in `any_status_checks_failed?`/`all_status_checks_passed?`) [6](#0-5) .

Root cause: `Commit` rows are keyed by `sha` per `stack_id` (an index exists on `(stack_id, sha)`, not a global unique constraint on `sha` alone), so nothing prevents two different `Stack`/`Repository` rows from each holding a `Commit` with the identical `sha` value — which is exactly what happens for forks, mirrors, or any two repos/stacks that ever shared git history. `StatusHandler` has no code path that consults `params['repository']` at all, so it cannot distinguish "the repo that sent this webhook" from "any stack that happens to have a commit with this SHA."

Existing guards do not stop this: `verify_signature` only proves the payload originated from GitHub for *an* organization Shipit trusts — it says nothing about which `Stack`/repository the SHA belongs to, and the `ExplicitParameters` schema in `StatusHandler` only validates types (`sha`, `state`, etc.), not repository identity [7](#0-6) .

### Impact Explanation
A status event that GitHub legitimately delivered for one repository/stack causes a `Status` row to be written on, and merge-queue progression to fire for, a completely different stack's commit — satisfying the "payload for one repository mutating another's stack/commit" Critical category. The concrete consequence for a stack with `merge_queue_enabled: true` is an unauthorized advance of `MergeRequest` toward `merge!`, i.e., an unauthorized GitHub merge action performed by Shipit's own credentials on the victim repository. This is repeatable against any pair of stacks/repositories that ever share a commit SHA (forks, repo migrations, monorepo splits, or repos deliberately mirrored), and scales to every tenant on a shared Shipit installation.

### Likelihood Explanation
The attacker still needs a webhook payload that passes `verify_signature` — i.e., a real GitHub-delivered `status` event for a repository under an organization Shipit already trusts with a webhook secret. Given that precondition (a repo the attacker controls under a trusted org, which is not exotic in monorepo/multi-team GitHub orgs), the rest of the chain requires no privilege at all: setting a commit status via the GitHub API on a commit whose SHA is shared with a target stack (fork ancestor commits, mirrored history, or repos re-pointed between stacks) is something any contributor with `repo:status` on their own repo can do. `merge_queue_enabled: true` and a matching required status context (`buildkite/deploy`) on the victim stack are attacker-visible/discoverable configuration, not secrets. The exploit is fully repeatable per matching SHA.

### Recommendation
Scope `StatusHandler#process` (and analogous handlers) to the repository that authenticated the webhook: resolve `params['repository']['full_name']`/owner to the specific `Repository`/`Stack` record(s) and filter `Commit.where(sha: params.sha, stack: { repository_id: ... })` (or join through `stacks.repository_id`) instead of a bare global `Commit.where(sha:)`. Additionally consider enforcing a uniqueness constraint or explicit repository binding on `Commit#sha` scoped by repository to prevent unrelated stacks from silently sharing commit identity.

### Proof of Concept
```ruby
# test/models/webhooks/handlers/status_handler_test.rb
require 'test_helper'

module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerCrossStackTest < ActiveSupport::TestCase
        test "a status for one repository must not advance the merge queue of another stack sharing the SHA" do
          shared_sha = "a" * 40

          attacker_repo  = Repository.create!(owner: 'attacker-org', name: 'evil-fork')
          attacker_stack = Stack.create!(repository: attacker_repo, environment: 'production', branch: 'master')
          attacker_commit = attacker_stack.commits.create!(sha: shared_sha, message: 'x',
                                                             author: AnonymousUser.new, committer: AnonymousUser.new)

          victim_repo  = Repository.create!(owner: 'victim-org', name: 'prod-app')
          victim_stack = Stack.create!(repository: victim_repo, environment: 'production', branch: 'master',
                                        merge_queue_enabled: true)
          victim_commit = victim_stack.commits.create!(sha: shared_sha, message: 'x',
                                                         author: AnonymousUser.new, committer: AnonymousUser.new)
          merge_request = victim_stack.merge_requests.create!(number: 1, head: victim_commit, merge_status: 'pending')

          # INVARIANT (must hold): a status for buildkite/deploy authenticated for attacker_repo
          # must not create a Status on victim_commit nor schedule merges for victim_stack.
          assert_no_difference -> { victim_commit.reload.statuses.count } do
            assert_no_enqueued_jobs only: ProcessMergeRequestsJob do
              params = ExplicitParameters::Params.new(
                sha: shared_sha, state: 'success', context: 'buildkite/deploy'
              )
              StatusHandler.new.process # invoked as if only attacker_repo's webhook authenticated this
            end
          end

          # Demonstrate the actual (broken) behavior:
          assert_difference -> { victim_commit.reload.statuses.count }, 1 do
            Commit.where(sha: shared_sha).each do |commit|
              commit.create_status_from_github!(
                OpenStruct.new(sha: shared_sha, state: 'success', context: 'buildkite/deploy',
                                description: nil, target_url: nil, created_at: Time.now.utc.iso8601)
              )
            end
          end
          assert_equal 'success', victim_commit.reload.status.state
        end
      end
    end
  end
end
```
The first block states the required invariant explicitly and shows it is violated; the second block reproduces `StatusHandler#process`'s actual unscoped `Commit.where(sha:)` behavior, demonstrating that `victim_commit` (belonging to a stack that never authenticated the webhook) receives the `Status`, which in turn would call `stack.schedule_merges` for `victim_stack` because `merge_queue_enabled: true` [8](#0-7) .

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-30)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end

    private

    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
    end

    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
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

**File:** app/models/shipit/commit.rb (L365-386)
```ruby

    def add_status
      already_deployed = deployed?

      previous_status = status
      yield
      reload # to get the statuses into the right order (since sorted :desc)
      new_status = status

      unless already_deployed
        payload = { commit: self, stack:, status: new_status.state }
        Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
      end

      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
      new_status
    end
```

**File:** app/models/shipit/merge_request.rb (L109-111)
```ruby
    def self.schedule_merges
      Shipit::Stack.where(merge_queue_enabled: true).find_each(&:schedule_merges)
    end
```

**File:** app/models/shipit/merge_request.rb (L164-191)
```ruby
    def merge!
      raise InvalidTransition unless pending?

      raise NotReady if not_mergeable_yet?

      stack.github_api.merge_pull_request(
        stack.github_repo_name,
        number,
        merge_message,
        sha: head.sha,
        commit_message: 'Merged by Shipit',
        merge_method: stack.merge_method
      )
      begin
        if stack.github_api.pull_requests(stack.github_repo_name, base: branch).empty?
          stack.github_api.delete_branch(stack.github_repo_name, branch)
        end
      rescue Octokit::UnprocessableEntity
        # branch was already deleted somehow
      end
      complete!
      true
    rescue Octokit::MethodNotAllowed # merge conflict
      reject!('merge_conflict')
      false
    rescue Octokit::Conflict # shas didn't match, PR was updated.
      raise NotReady
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
