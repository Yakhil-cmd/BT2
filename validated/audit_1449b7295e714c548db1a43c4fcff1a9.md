### Title
`StatusHandler#process` writes a `Status` for any `Commit` matching the payload's `sha`, without checking the payload's `repository` against the commit's stack repository - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits purely `Commit.where(sha: params.sha)` and calls `commit.create_status_from_github!(params)` for every match, across the whole `commits` table, with no scoping to the repository that actually sent the webhook. Every other handler in this codebase is expected to scope via the `Handler#stacks`/`repository_name` helpers (`Repository.from_github_repo_name(repository_name)&.stacks`), but `StatusHandler` never calls it. Because git commit SHAs are content-addressed and identical across forks/shared history, a webhook legitimately signed for one repository (owned/controlled by the attacker) can inject a `Status` row onto a `Commit` that belongs to a completely different stack/repository/tenant, permanently corrupting `commit.status` for the victim.

### Finding Description
The binding that should hold is: for every `Status` row `s` contributing to `commit.status` on stack `S`, `s` was created from a webhook payload whose `payload.dig('repository','full_name') == S.repository.full_name`.

Code path:
- `WebhooksController#create` dispatches to `Shipit::Webhooks.for_event(event)` handlers after `verify_signature`, which only checks that the raw body is signed with the secret configured for `Shipit.github(organization: repository_owner)` [1](#0-0) . This proves the webhook came from *some* repo/org for which the attacker's request produced a valid signature (which the attacker can obtain by emitting webhooks from a repository they own/control, per this exercise's threat model) — it does **not** bind the payload to any specific target `Stack`/`Repository`.
- `Handler` exposes a `stacks`/`repository_name` helper specifically meant to scope processing to the correct `Repository` [2](#0-1) .
- `StatusHandler#process`, however, ignores this scoping entirely and matches commits by SHA alone:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [3](#0-2) 

- `create_status_from_github!` → `add_status { statuses.replicate_from_github!(stack_id, github_status) }` [4](#0-3)  then `Status.replicate_from_github!` does a bare `find_or_create_by!` keyed on `state/description/target_url/context/created_at`, with no repository check [5](#0-4) .

Because `Commit.sha` is not unique per repository (it's a git content hash), any commit that is an ancestor shared between the attacker's own repo/fork and the victim's tracked repo (or, in degenerate cases, any repo whose history happens to include that SHA) will match `Commit.where(sha: ...)` for the victim's `Commit` row too, even though the webhook's `repository.full_name` is the attacker's own repo. This writes a `Status` for a repository that never authenticated (or produced) that data, directly violating the binding. `refresh_statuses!` afterward calls `stack.github_api.statuses(github_repo_name, sha)` against the *victim's real repo* [6](#0-5) ; since GitHub has no status for that SHA in the victim's real repo (the SHA only has statuses in the attacker's repo), the refresh only appends new rows via `find_or_create_by!` and never deletes the forged row — `Commit#status` still computes from the full set of `statuses` via `Status::Group.compact`/`select_significant_status`, so the forged entry keeps influencing `commit.status.state` [7](#0-6) [8](#0-7) .

None of the listed guards prevent this: `verify_signature` authenticates the *sender org*, not the *target repository*; `ExplicitParameters` (`params do ... end` in `StatusHandler`) validates field types/presence but never cross-checks `sha` against `repository`; there is no `Stack`/`Repository` model validation that could catch this because the write path never even queries `Repository`.

### Impact Explanation
A `Status` (and thus deployability/CI signal) can be written for a repository/stack that never produced or authorized it — this is a "payload for one repository mutating another's stack/commit" case, explicitly named Critical in the rules. Concretely, this can flip `commit.deployable?` (`success? && !blocked?`) or unblock `stack.blocking_statuses`/`stack.schedule_merges` (auto-merge via `ProcessMergeRequestsJob`) for a victim stack, based entirely on CI data the attacker controls in their own repository. It is repeatable against any stack whose tracked commit history shares a SHA with a repo the attacker controls (trivial via forking, since forked history is byte-identical and shares SHAs with the upstream/victim repo tracked by Shipit).

### Likelihood Explanation
The attacker needs to be able to send a webhook that passes `verify_signature` for some organization/repo they control (granted under this exercise's threat model as "emit webhooks from a repository they own"), and needs a SHA shared between their own repo's history and the victim stack's tracked commit history — trivially achieved by forking the victim repository, since forks share identical commit objects/SHAs for all common ancestors. No Shipit secrets, sessions, or privileged roles are required beyond that.

### Recommendation
Scope `StatusHandler#process` to the repository that sent the webhook, mirroring the pattern used elsewhere in `Handler`:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
using the existing `stacks` helper (`Repository.from_github_repo_name(repository_name)&.stacks`) so a `Status` can only ever be attached to a `Commit` belonging to the repository that the webhook payload actually names.

### Proof of Concept
Minitest plan (model/controller test, e.g. `test/models/shipit/webhooks/handlers/status_handler_test.rb`):
1. Create two stacks/repositories, `victim_repo` and `attacker_repo`, each with their own `Stack`.
2. Create a `Commit` with the same `sha` (`"deadbeef...".freeze`) under both `victim_repo`'s stack and `attacker_repo`'s stack (simulating shared git ancestry from a fork).
3. Build a status payload with `repository.full_name == attacker_repo.full_name` and `sha == shared_sha`, `state: 'success'`.
4. Call `StatusHandler.call(payload)` directly (bypassing signature verification, as the controller test suite does with `GithubHook.any_instance.stubs(:verify_signature).returns(true)`).
5. Assert the binding both before and after:
   - Before: `victim_commit.statuses.count == 0`.
   - After: assert `victim_commit.reload.statuses.count == 1` **and** `victim_commit.status.state == 'success'`, proving a `Status` was written to the victim's commit from a payload whose `repository.full_name` (`attacker_repo.full_name`) does NOT equal the victim stack's repository (`victim_repo.full_name`) — i.e. `payload_repository != commit.stack.repository.full_name` while `commit.statuses.count` still increased, demonstrating the broken binding. [9](#0-8)

### Citations

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-28)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
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

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
      end
    end
  end
end
```

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

**File:** app/models/shipit/commit.rb (L304-306)
```ruby
    def status
      @status ||= Status::Group.compact(self, statuses_and_check_runs)
    end
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

**File:** app/models/shipit/status/group.rb (L75-83)
```ruby
      def select_significant_status(statuses)
        statuses = reject_allowed_to_fail(statuses)
        return Status::Unknown.new(commit) if statuses.empty?

        non_success_statuses = statuses.reject(&:success?)
        return statuses.first if non_success_statuses.empty?

        non_success_statuses.reject(&:pending?).first || non_success_statuses.first || Status::Unknown.new(commit)
      end
```
