This confirms `commits` table has a unique index scoped to `(stack_id, sha)` — not a global uniqueness constraint — so the same SHA can legitimately exist as rows belonging to different stacks/repositories in the same database. [1](#0-0) 

This is sufficient to finalize the analysis: `StatusHandler#process` performs a global, unscoped `Commit.where(sha:)` lookup, matching any commit row across any stack/repository, and applies attacker-supplied status data to it, with the repository-scoping method (`Handler#stacks`) available but never invoked.

### Title
StatusHandler applies webhook status data to any Commit matching a SHA, ignoring `repository.full_name` scoping - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits with `Commit.where(sha: params.sha)` across the *entire* `commits` table and calls `commit.create_status_from_github!(params)` on every match, without ever restricting the query to the webhook's own repository via `Handler#stacks`/`repository_name`. Because `commits.sha` is only unique per `(stack_id, sha)` and not globally, a validly-delivered status webhook whose `repository.full_name` names one repository can write a `Status` onto a `Commit` belonging to a completely different stack/repository, as long as the SHA values coincide.

### Finding Description
The claimed binding is: `payload.dig('repository','full_name') == head.stack.repository.full_name` before a status is attached to `head`. Tracing the code shows this binding is never checked:

- `Handler#stacks` exists precisely to scope a handler's effect to the repository named in the webhook payload: `Repository.from_github_repo_name(repository_name)&.stacks`, where `repository_name = payload.dig('repository', 'full_name')`. [2](#0-1) 
- `PushHandler#process` correctly uses this scoping: `stacks.not_archived.where(branch:).find_each { ... }`. [3](#0-2) 
- `StatusHandler#process`, by contrast, never calls `stacks` or `repository_name` at all. It runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`, a global lookup across every stack/repository tracked by the Shipit instance. [4](#0-3) 
- The `params` schema for this handler requires only `sha`/`state` and optional fields; it never requires or validates `repository`, so nothing downstream re-derives or checks the claimed owner of the SHA. [5](#0-4) 
- `Commit` rows are only unique per `(stack_id, sha)`, not globally, so identical SHAs legitimately coexist across unrelated stacks (e.g., a PR head commit that lives, byte-identically, in both `victim/repo` and the contributor's own fork). [1](#0-0) 
- `create_status_from_github!` unconditionally creates a `Status` and fires `ProcessMergeRequestsJob`, feeding directly into `MergeRequest#all_status_checks_passed?` via `head.statuses_and_check_runs`. [6](#0-5) [7](#0-6) 

Exploit flow: an attacker who is the author of a queued pull request on `victim/repo` already possesses a repository (their own fork) that legitimately contains the exact commit object at `MergeRequest#head` (PR head commits live in the contributor's fork by construction, so no SHA collision needs to be engineered). If a status event is delivered for that SHA carrying `repository.full_name` for the attacker's own repo — a payload GitHub itself will generate and sign whenever Shipit's GitHub App (or a shared-secret App installation) processes an event tied to that repository/account — `verify_signature` passes (it authenticates the *sender App/installation*, not that the payload's repository matches the SHA's owning stack), and `StatusHandler` then blindly attaches a forged "success" status to the `victim/repo` `Commit` row sharing that SHA. This flips `all_status_checks_passed?` to true and unblocks `MergeRequest#merge!` for `victim/repo`.

None of the listed guards catch this: `verify_signature`/`GitHubApp#verify_webhook_signature` only proves the payload was signed by a legitimate GitHub App delivery, not that its `repository.full_name` matches the target commit's actual stack; `drop_unhandled_event` only filters unregistered event types; the `ExplicitParameters` schema for `StatusHandler` doesn't require/validate `repository` at all; and `Handler#stacks`, which was built for exactly this purpose, is simply never invoked by `StatusHandler`.

### Impact Explanation
An attacker can inject a forged/self-controlled `success` (or any) `Status` onto a `victim/repo` commit that happens to share a SHA with a commit in a repository the attacker controls, without any relationship to `victim/repo`'s actual CI state. Since `MergeRequest#all_status_checks_passed?` reads directly from `head.statuses_and_check_runs`, this can flip a queued `MergeRequest` on `victim/repo` from CI-pending/failing to CI-passing, unblocking `MergeRequest#merge!` and causing an unauthorized merge into `victim/repo` — matching the Critical category "a payload for one repository mutating another's stack, commit ... or an unauthorized deploy, rollback or merge". The most direct, always-available trigger is a PR head commit, which by git's content-addressing already exists identically in the attacker's own fork, requiring no cryptographic SHA collision. This is repeatable per pull request/merge-request cycle and applies to any stack tracked by the same Shipit instance.

### Likelihood Explanation
The application-layer bug (missing `stacks`/`repository_name` scoping in `StatusHandler#process`) is unconditional and requires no special configuration — it is demonstrable purely at the model/handler level, as shown in the PoC below, independent of how webhook delivery/signing is configured. Full remote exploitability additionally depends on the attacker being able to get a validly-signed status webhook delivered with `repository.full_name` under their control (e.g., a GitHub App whose webhook secret is shared across installations/organizations, which is a real, common GitHub Apps deployment pattern), but the code-level flaw itself — applying status data to any commit row matching a SHA, regardless of which repository the webhook claims — is present and unguarded today.

### Recommendation
In `StatusHandler#process`, scope the lookup through `stacks` (as `PushHandler` does) instead of a bare `Commit.where(sha:)`, e.g. restrict to `Commit.where(sha: params.sha, stack: stacks)` (or `stacks.flat_map(&:commits).select { _1.sha == params.sha }`), so a status webhook can only ever mutate commits belonging to the stack(s) tied to `payload.dig('repository','full_name')`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_scope_test.rb
require 'test_helper'

module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerScopeTest < ActiveSupport::TestCase
        test "status webhook claiming a different repository still mutates a commit " \
             "in an unrelated stack sharing the same SHA" do
          victim_stack = shipit_stacks(:shipit) # tracks 'shopify/shipit-engine' style repo
          shared_sha = 'deadbeef' * 5
          head_commit = victim_stack.commits.create!(
            sha: shared_sha,
            author: shipit_users(:walrus),
            committer: shipit_users(:walrus),
            authored_at: Time.now,
            committed_at: Time.now
          )
          merge_request = victim_stack.merge_requests.create!(
            number: 999,
            head: head_commit,
            merge_status: 'pending',
            merge_requested_at: Time.now.utc,
            revalidated_at: Time.now.utc
          )

          refute merge_request.all_status_checks_passed?

          # binding claimed to be enforced: payload.repository.full_name == victim's repo
          # here it is an ATTACKER-CONTROLLED, unrelated repo, sharing only the SHA
          forged_payload = {
            'sha' => shared_sha,
            'state' => 'success',
            'context' => 'ci/attacker',
            'repository' => { 'full_name' => 'attacker/unrelated-repo' }
          }

          assert_difference '-> { head_commit.statuses.count }', 1 do
            StatusHandler.new(forged_payload).process
          end

          assert merge_request.reload.all_status_checks_passed?,
                 "attacker-controlled repo's status must not satisfy victim/repo's merge queue checks"
        end
      end
    end
  end
end
```
This directly demonstrates that `StatusHandler#process` (bypassing only the outer controller's signature check, per the "no live GitHub" requirement) applies status data to `head_commit` — which belongs to the victim's stack — using a payload whose `repository.full_name` names an unrelated, attacker-controlled repository, and that this flips `MergeRequest#all_status_checks_passed?` from `false` to `true`.

### Citations

**File:** db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb (L1-20)
```ruby
class IndexCommitsOnStackIdAndSha < ActiveRecord::Migration[5.1]
  def change
    add_index :commits, %i(sha stack_id), unique: true
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** app/models/shipit/commit.rb (L144-169)
```ruby
    def statuses_and_check_runs
      statuses + check_runs
    end

    def schedule_refresh_statuses!
      RefreshStatusesJob.perform_later(commit_id: id)
    end

    def schedule_refresh_check_runs!
      RefreshCheckRunsJob.perform_later(commit_id: id)
    end

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

**File:** app/models/shipit/merge_request.rb (L193-197)
```ruby
    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end
```
