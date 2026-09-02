## Title
Cross-repository status forgery in `StatusHandler#process` mutates unrelated stacks' commits/merge queues - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

## Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits to update purely by `sha`, with no check that the commit's owning stack/repository matches the `repository.full_name` in the (signature-verified) webhook payload. Every other webhook handler in this codebase (`OpenedHandler`, `ClosedHandler`, `LabeledHandler`, etc.) explicitly scopes its query through `Repository.from_github_repo_name(params.repository.full_name)`, but `StatusHandler` does not, so a signature-valid `status` event for repository A can mutate `Commit`/`Status` rows and trigger `stack.schedule_merges` for a completely different stack B whose commit happens to share the same `sha`.

## Finding Description
The claimed broken binding, stated as an equality that should hold but does not:

`commit.stack.repository.full_name == params.repository.full_name` for every `commit` mutated by a `status` webhook.

Code path:
- `app/controllers/shipit/webhooks_controller.rb` verifies the HMAC signature against `Shipit.github(organization: repository_owner)`'s `webhook_secret` (`verify_signature`, lines 24-49) and then dispatches to handlers via `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` (line 12). This only proves the raw body was signed with the secret for the claimed organization — it says nothing about which specific repository's commits may be touched.
- `StatusHandler#process` then does: [1](#0-0) 
i.e. `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — **no** `Repository.from_github_repo_name(params.repository.full_name)` filter, unlike every PR-related handler which does exactly that filtering, e.g. `ClosedHandler#repository`: [2](#0-1) 
- `Commit#create_status_from_github!` calls `add_status`: [3](#0-2) 
- `add_status` suppresses `Hook.emit(:commit_status, ...)` and `Hook.emit(:deployable_status, ...)` when the commit is `already_deployed`, but unconditionally calls `stack.schedule_merges` whenever the new status is `pending?` or `success?`, regardless of `already_deployed`: [4](#0-3) 

Because `Commit.where(sha:)` is global across the whole `commits` table (not scoped per stack/repository), any two `Shipit::Stack` records whose tracked repositories share a commit with an identical SHA — a routine situation for forks, mirrors, or a repository tracked under two different `Shipit::Repository`/`Stack` records — cause a webhook that is legitimately signed for repository A's organization to write a `Status` and invoke `schedule_merges` for stack B's actual owning stack (`commit.stack`, correctly resolved from the matched `Commit` row, not from the payload's `repository` field — but that row was wrongly selected in the first place because nothing constrained the sha lookup to the verified repository).

Existing guards do not stop this:
- `verify_signature` only authenticates "this body came from an app config for this claimed org"; it does not authenticate "and only affects that org's own commits" — the payload's `repository.full_name` field is never cross-checked against the matched `Commit`'s stack.
- `already_deployed` in `add_status` only gates `Hook.emit`, not `stack.schedule_merges`.
- No `ExplicitParameters` schema check enforces that `params.sha`'s matched commits belong to `params.repository.full_name`.

## Impact Explanation
A payload authenticated for one repository can write a `Status` row and invoke `Stack#schedule_merges` for an entirely different repository/stack that the attacker does not control, causing that victim stack's queued merges to be re-evaluated (`ProcessMergeRequestsJob`) off attacker-controlled status data. This matches the "Critical" category: "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy, rollback or merge." It is repeatable against any pair of stacks sharing overlapping git history/SHAs (forks, mirrors, repository renames re-tracked as new `Repository` rows, monorepo splits), for as long as the sha collision persists.

## Likelihood Explanation
Exploitation requires (a) the attacker to be able to produce a signature-valid webhook for *some* repository/org tracked by Shipit (typically their own repo under an org Shipit already manages, or any org where `webhook_secret` legitimately validates the raw body), and (b) a `Commit` row to exist in a victim stack with the same `sha` as a commit the attacker's own repository actually has (achievable deterministically via forking/mirroring, since unmodified history retains identical SHA1s). Given those two realistic preconditions, the attacker's own legitimately-triggered `status` webhook is sufficient — no additional secret material is needed, and the attack is fully repeatable per matching sha.

## Recommendation
In `StatusHandler#process`, scope the `Commit` lookup to the repository actually named in the verified payload, mirroring the pattern used by the PR handlers, e.g. restrict to `stacks` derived from `Repository.from_github_repo_name(params.repository.full_name)` before matching by `sha`:
```ruby
def process
  stacks.flat_map(&:commits).select { |c| c.sha == params.sha }.each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
or equivalently `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`. Additionally, `Commit#add_status` should gate `stack.schedule_merges` behind the same `already_deployed` check that already protects the hook emissions, since re-evaluating the merge queue for an already-deployed commit provides no legitimate signal.

## Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`, no live GitHub):
1. Create `repo_a` / `stack_a` and `repo_b` / `stack_b` as two independent `Shipit::Repository`/`Shipit::Stack` fixtures.
2. Create `commit_victim` under `stack_b` with `sha: "deadbeef..."`, and mark it deployed (create a successful `Deploy` covering it) so `commit_victim.deployed?` is `true`.
3. Create `commit_attacker` under `stack_a` with the **same** `sha: "deadbeef..."`, not deployed.
4. Build a `status` webhook payload: `{ sha: "deadbeef...", state: "success", repository: { full_name: repo_a.full_name } }`.
5. Stub `stack_b.schedule_merges` (`Shipit::Stack.any_instance.expects(:schedule_merges)` scoped to `stack_b`, or mock the specific instance) and assert it **is** called even though the payload only named `repo_a`:
   ```ruby
   assert_equal commit_victim.sha, commit_attacker.sha # binding precondition
   refute_equal commit_victim.stack, commit_attacker.stack

   Shipit::Webhooks::Handlers::StatusHandler.any_instance.stubs(:stacks).returns(Shipit::Stack.where(id: stack_a.id)) if needed

   stack_b_double_called = false
   Shipit::Stack.any_instance.stubs(:schedule_merges).with { |*| stack_b_double_called = true if self == stack_b }

   Shipit::Webhooks::Handlers::StatusHandler.call(payload)

   assert stack_b_double_called, "victim stack_b.schedule_merges was invoked from a payload naming repo_a"
   ```
6. Assert the equality that should have held but did not: `commit_victim.stack.repository.full_name == params.repository.full_name` is `false`, yet `commit_victim`'s status/merge-queue state was still mutated.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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
