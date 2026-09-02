### Title
`StatusHandler#process` mutates commit statuses without repository/stack scoping, allowing cross-repository status forgery - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits globally by SHA (`Commit.where(sha: params.sha)`) and never checks that the SHA belongs to a commit ingested from the repository that sent the webhook. Every sibling handler (`PushHandler`, `PullRequest::OpenedHandler`, etc.) resolves the mutation set through `Handler#stacks`/`repository_name`, which is derived from `Repository.from_github_repo_name(payload['repository']['full_name'])`; `StatusHandler` is the only handler that skips this binding.

### Finding Description
The invariant enforced everywhere else in this engine is:

`Handler subclass's row-mutation set == Repository.from_github_repo_name(payload.repository.full_name).stacks`

`Handler#stacks` implements exactly this: [1](#0-0) 

`PushHandler#process` uses it before writing anything: [2](#0-1) 

`PullRequest::OpenedHandler#process` similarly resolves `repository` from `params.repository.full_name` before scoping any writes to `repository.review_stacks`: [3](#0-2) 

`StatusHandler#process`, by contrast, never touches `stacks` or `repository_name` at all: [4](#0-3) 

It matches commits purely on `sha` across the entire `commits` table, and for every match calls `commit.create_status_from_github!(params)`, which writes the status against that commit's *actual* `stack_id`, not any stack belonging to the reporting repository: [5](#0-4) , [6](#0-5) 

Git commit SHAs are stable across forks/clones — forking a repository preserves the SHA of every commit that has not been rewritten. Since GitHub Apps/webhooks can be installed on any repository the attacker owns (including a fork of a repository whose upstream is tracked as a Shipit stack), the attacker can:

1. Fork the victim's tracked repository (or otherwise obtain/create a repository containing a commit whose SHA matches a commit already ingested into a victim's `Stack`).
2. Using their own GitHub credentials/GitHub App installation on their own fork (no Shipit secret needed — GitHub itself computes and sends a correctly signed webhook for events on the attacker's own repository, since the shared `webhook_secret`/GitHub App key is configured per-installation, not per-repo-ownership), create/update a commit status on that commit via the GitHub Statuses API (`POST /repos/{owner}/fork/statuses/{sha}`), which the attacker can do because they own the fork.
3. GitHub delivers a legitimately-signed `status` webhook event to the Shipit host, with `repository.full_name` = attacker's fork, `sha` = the shared commit SHA, `state` = e.g. `"success"`.
4. `StatusHandler#process` ignores `repository.full_name` entirely, matches the SHA against the victim's existing `Commit` row, and writes the attacker-controlled status onto the victim's commit/stack.

None of the existing guards stop this: `verify_signature`/`GitHubApp#verify_webhook_signature` only prove the event came from GitHub for *some* repo the app is installed on — they say nothing about which stack the payload is authorized to mutate; `drop_unhandled_event` and the `ExplicitParameters` schema validate shape, not repository authorization; there is no `Repository`/`Stack` scoping check anywhere in `StatusHandler`.

### Impact Explanation
A successful forged status can flip a victim commit from pending/failure to `success`, which in `Commit#add_status` triggers `stack.schedule_merges` and can unblock `deployable?`/`schedule_continuous_delivery`, i.e. it can enable an unauthorized deploy or auto-merge on a stack the attacker does not own and never authenticated against: [7](#0-6)  This is a cross-tenant mutation ("a payload for one repository mutating another's stack, commit, task or team"), matching the Critical impact category, and is repeatable against any commit SHA the attacker can reproduce in a repository they control (trivial via forking).

### Likelihood Explanation
Preconditions are low-cost and fully within an unprivileged attacker's reach: fork any public repository tracked by a Shipit stack (or otherwise share commit history with it), ensure the Shipit GitHub App/webhook is installed for that fork (typical for GitHub Apps installable by any user on their own repos), and call the Statuses API on their own fork for the shared SHA. No Shipit secrets, sessions, or team membership are required — the signature is legitimately produced by GitHub for the attacker's own repository event.

### Recommendation
Scope `StatusHandler#process` the same way as `PushHandler`: resolve `stacks` from `repository_name` (`Repository.from_github_repo_name(payload.dig('repository','full_name'))`) and restrict the `Commit` lookup/update to commits belonging to those stacks, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`, before calling `create_status_from_github!`.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`, or as a source-grep test as suggested):

```ruby
test "StatusHandler does not reference `stacks`/`repository_name` while sibling handlers do" do
  status_src = File.read(Shipit::Webhooks::Handlers::StatusHandler.instance_method(:process).source_location.first)
  push_src   = File.read(Shipit::Webhooks::Handlers::PushHandler.instance_method(:process).source_location.first)

  assert_no_match(/stacks|repository_name/, status_src)
  assert_match(/stacks/, push_src)
end

test "status webhook from an unrelated repository mutates a victim stack's commit" do
  victim_stack = shipit_stacks(:shipit)
  victim_commit = victim_stack.commits.create!(sha: "deadbeef" * 5, message: "victim commit")

  attacker_payload = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'context' => 'ci/attacker',
    'repository' => { 'full_name' => 'attacker/unrelated-fork' } # not victim_stack's repo
  }

  Shipit::Webhooks::Handlers::StatusHandler.call(attacker_payload)

  victim_commit.reload
  assert victim_commit.status.success?, "attacker-controlled repo mutated the victim stack's commit status"
end
```

Both assertions demonstrate the missing `stacks`/`repository_name` scoping and the resulting cross-repository write, matching the binding violation described.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-54)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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

**File:** app/models/shipit/commit.rb (L366-386)
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
