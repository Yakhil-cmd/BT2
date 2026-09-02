### Title
`StatusHandler#process` writes commit statuses without verifying the webhook's repository matches the target commit's stack repository - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`Commit#refresh_statuses!` (the polling path) always scopes its GitHub API read to the owning stack's repository via `stack.github_api.statuses(github_repo_name, sha, ...)`, but `StatusHandler#process` (the live webhook path) looks up commits purely `Commit.where(sha: params.sha)` and calls `create_status_from_github!` directly — with no check that the webhook's `payload['repository']['full_name']` matches the found commit's `stack.github_repo_name`. This is the same underlying write method (`create_status_from_github!`) reached through two paths with different scoping guarantees.

### Finding Description
Binding claimed broken: `github_repo_name` used to fetch/authorize the status write in the pull path == `github_repo_name` used to authorize the status write in the push path, for the same `Status` row. This is false.

- Pull path: `Commit#refresh_statuses!` in `app/models/shipit/commit.rb` (lines 156-163) calls `stack.github_api.statuses(github_repo_name, sha, per_page: 100)`, i.e. the GitHub API call itself is scoped to `stack.github_repo_name` before any `create_status_from_github!` write occurs. [1](#0-0) 
- Push path: `StatusHandler#process` in `app/models/shipit/webhooks/handlers/status_handler.rb` (lines 20-24) does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — it never references `repository_name`/`payload['repository']`, never calls the `stacks` helper defined on the base `Handler` class, and never compares the matched commit's `stack.github_repo_name` against the webhook's originating repository. [2](#0-1) 
- The base `Handler` class does define a `stacks`/`repository_name` scoping helper used by other handlers (e.g. pull-request handlers), but `StatusHandler` does not use it at all. [3](#0-2) 
- `create_status_from_github!` performs the actual write via `statuses.replicate_from_github!(stack_id, github_status)` inside `add_status`, unconditionally, for whichever `Commit` record was found by bare SHA lookup. [4](#0-3) 

Root cause: `Commit.where(sha: params.sha)` is a global, cross-stack query. Because git commit SHAs are content-derived and preserved across forks, mirrors, or repositories sharing history, the same SHA can legitimately exist as a `Commit` row in multiple `Stack`s tracking different `github_repo_name`s. A GitHub `status` webhook delivered for repository A, referencing a SHA that also exists as a commit in stack B (a different repository), will cause `StatusHandler` to write a `Status` row against stack B's commit — a payload for one repository mutating another's commit/stack state, with no repository-identity check anywhere in the call graph.

Existing guards do not close this gap: `verify_signature`/`GitHubApp#verify_webhook_signature` validate that the webhook body was sent by the configured GitHub App and stops arbitrary unsigned `POST /webhooks` forgery, but they only prove the payload originated from *some* installed repository — they do not constrain which `Commit`/`Stack` rows the handler is permitted to mutate. `drop_unhandled_event` and the `ExplicitParameters` schema for `StatusHandler` only validate shape (`sha`, `state`, etc.), not repository ownership. No `Repository`/`Stack` validator intervenes because the write happens directly on `Commit`/`Status`, not through a repository-keyed lookup.

### Impact Explanation
Any legitimately signed `status` webhook (from a repository the attacker controls, or naturally emitted from CI on any repo that has ever shared commit history with a repository tracked by Shipit — forks, mirrors, template-derived repos) can cause a `Status` row to be created/updated on a `Commit` belonging to an unrelated `Stack`/repository, as long as a `Commit` with the identical SHA exists there. This lets an attacker inject arbitrary `state`/`description`/`target_url`/`context` status data onto another tenant's commit. Since deployability logic (`Commit#deployable?`, `blocked?`, CI-gating checks) reads from `Status`/`status`, and `add_status` can trigger `stack.schedule_merges` and `Hook.emit(:deployable_status, ...)`, this can influence continuous-delivery/merge decisions for a stack the attacker does not own. This matches the Critical category "a payload for one repository mutating another's stack, commit, task or team."

### Likelihood Explanation
Exploitation requires: (1) a genuine, signature-valid `status` webhook delivery for some repository the attacker controls or that emits real webhooks to the Shipit host, and (2) a `Commit` row with the identical SHA already present in a victim `Stack` (realistic for forks/mirrors/shared-history repos, or any monorepo/template setup where commits are cherry-picked/rebased identically across repos). This is not a raw unauthenticated-forgery bug — it depends on shared SHA collision-by-legitimate-history rather than attacker-chosen arbitrary SHAs, and signature verification (`verify_signature`) still gates delivery. It is nonetheless attacker-repeatable at zero cost against any victim stack that happens to share history with a repository the attacker controls, with no maintainer or operator privilege required.

### Recommendation
In `StatusHandler#process`, scope the commit lookup by repository, not just SHA: resolve the target `Stack`(s) via the existing `Handler#stacks` helper (`Repository.from_github_repo_name(repository_name)`) and restrict `Commit.where(sha: params.sha)` to `stacks.flat_map(&:commits)` (or `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`), mirroring the scoping already enforced in `Commit#refresh_statuses!` via `stack.github_repo_name`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
require 'test_helper'

module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerTest < ActiveSupport::TestCase
        test 'push (webhook) path writes a status onto a commit belonging to an unrelated stack sharing the same sha' do
          victim_stack = shipit_stacks(:shipit)
          attacker_repo_full_name = 'attacker/unrelated-repo'

          shared_sha = 'a' * 40
          victim_commit = victim_stack.commits.create!(sha: shared_sha, message: 'shared history commit')

          payload = {
            'sha' => shared_sha,
            'state' => 'failure',
            'context' => 'ci/malicious',
            'description' => 'forged from unrelated repo',
            'repository' => { 'full_name' => attacker_repo_full_name },
          }

          assert_difference -> { victim_commit.statuses.count }, 1 do
            StatusHandler.call(payload)
          end

          victim_commit.reload
          assert_equal 'failure', victim_commit.status.state
        end

        test 'refresh_statuses! is scoped to the commit stack github_repo_name, unlike StatusHandler#process' do
          stack = shipit_stacks(:shipit)
          commit = stack.commits.first

          stack.github_api.expects(:statuses).with(stack.github_repo_name, commit.sha, per_page: 100).returns([])
          commit.refresh_statuses!

          # StatusHandler#process never calls github_api.statuses / never reads stack.github_repo_name
          Shipit::Stack.any_instance.expects(:github_api).never
          StatusHandler.call(
            'sha' => commit.sha,
            'state' => 'success',
            'repository' => { 'full_name' => 'some/other-repo' }
          )
        end
      end
    end
  end
end
```
The first test demonstrates the cross-repository write: a status for `attacker/unrelated-repo`'s SHA lands on `victim_stack`'s commit purely because `Commit.where(sha:)` ignores repository identity. The second test asserts the divergence stated in the question directly: `refresh_statuses!` invokes `github_api` scoped by `stack.github_repo_name`, while `StatusHandler#process` never touches `github_api`/`github_repo_name` at all for the identical write method `create_status_from_github!`.

### Citations

**File:** app/models/shipit/commit.rb (L156-163)
```ruby
    def refresh_statuses!
      github_statuses = stack.handle_github_redirections do
        stack.github_api.statuses(github_repo_name, sha, per_page: 100)
      end
      github_statuses.each do |status|
        create_status_from_github!(status)
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
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
