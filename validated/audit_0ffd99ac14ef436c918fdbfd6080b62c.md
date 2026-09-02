### Title
`StatusHandler#process` applies GitHub commit statuses to `Commit` records without scoping to the repository or branch named in the payload - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` with no check that `commit.stack.repository` matches `payload.dig('repository', 'full_name')`, and no use of the declared `params.branches` to confirm the SHA is on the tracked branch. Every other mutating handler (e.g. `PushHandler`) scopes its effect through `Handler#stacks`, which filters by `repository_name`; `StatusHandler` does not.

### Finding Description
The broken binding: the handler implicitly assumes `commit.stack.repository.full_name == payload.dig('repository', 'full_name')` for every `Commit` matched by `Commit.where(sha: params.sha)`, but that equality is never checked in code. [1](#0-0) 

Compare with `PushHandler`, which restricts effects to stacks resolved from `payload['repository']['full_name']` via `Handler#stacks`: [2](#0-1) [3](#0-2) 

`Commit#sha` has no uniqueness constraint scoped away from other stacks in this query path, and `create_status_from_github!` unconditionally writes a `Status` row and re-evaluates `deployable?`/`schedule_continuous_delivery` for whatever stack the matched commit belongs to: [4](#0-3) [5](#0-4) 

Exploit flow: an attacker forks a public repository that Shipit tracks. Git forks share commit objects (identical SHA-1) for all history up to the fork point, so the ancestor commits in the target's tracked branch also exist, byte-identically, in the attacker's own fork. If the attacker's fork is itself registered with the same Shipit instance (a legitimate, unprivileged action — Shipit supports many repos/stacks), the attacker uses their own push/write access to their fork to call GitHub's Status API (`POST /repos/:attacker/:fork/statuses/:sha`) for one of those shared ancestor SHAs, setting an arbitrary `state`/`context` (e.g. `state: "success", context: "ci/required-check"`). GitHub delivers a legitimately signed `status` webhook to Shipit, with `payload['repository']['full_name']` equal to the attacker's fork but `sha` equal to a commit that also belongs to the victim's tracked stack. Because `StatusHandler#process` never checks `repository_name`/`branches` against the matched `Commit`'s stack, it writes the forged status onto the victim stack's `Commit`, which can flip `Commit#deployable?` for a required status/context and trigger `Commit#schedule_continuous_delivery`, causing an unauthorized deploy trigger for a repository the attacker never had write access to.

Existing guards do not stop this: `verify_signature`/`GitHubApp#verify_webhook_signature` only prove the webhook came from GitHub for the attacker's own (legitimately registered) repository — they say nothing about which `Commit`/stack the SHA should affect. The `ExplicitParameters` schema accepts `branches` but the handler discards it. `drop_unhandled_event`, `force_github_authentication`, `User#authorized?`, and the `stacks` scope used by other handlers are not invoked here at all.

### Impact Explanation
A payload delivered for the attacker's own (unprivileged, self-owned) repository mutates commit/state belonging to a different, victim repository's stack. This is a direct match for "a payload for one repository mutating another's stack, commit, task" and can lead to "an unauthorized deploy" if the affected commit is the stack head and continuous deployment or a manual deploy gate depends on that status. Repeatable against any repository sharing git history with an attacker-controlled fork that is also onboarded to the same Shipit instance.

### Likelihood Explanation
Requires: (1) the target repository is fork-able/public so history (and thus SHAs) is shared, (2) the attacker's fork is also registered as a Shipit-tracked repository/stack on the same instance, and (3) the SHA of interest predates the fork point (very commonly true — e.g. the current `main` HEAD at the moment of forking, or any older commit). Attacker cost is a normal GitHub fork plus one authenticated GitHub Status API call on their own repo — no Shipit credentials, no secrets, no privileged GitHub role needed. Feasible and repeatable per victim commit that is shared history.

### Recommendation
In `StatusHandler#process`, resolve commits only within stacks belonging to `payload.dig('repository', 'full_name')` (mirroring `Handler#stacks`), e.g. `stacks.joins(:commits).merge(Commit.where(sha: params.sha))`, and additionally validate `params.branches` names the stack's own tracked `branch` before calling `create_status_from_github!`, discarding statuses for shas/branches that don't belong to the reporting repository.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "status handler does not update commits belonging to a different repository" do
  victim_stack = shipit_stacks(:shipit)
  victim_commit = victim_stack.commits.create!(sha: 'a' * 40, message: 'victim commit')

  attacker_repository = Shipit::Repository.create!(owner: 'attacker', name: 'fork')
  attacker_stack = Shipit::Stack.create!(repository: attacker_repository, environment: 'production', branch: 'main')

  payload = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'context' => 'ci/required-check',
    'branches' => [{ 'name' => 'main' }],
    'repository' => { 'full_name' => attacker_repository.full_name }, # attacker's own repo
  }

  Shipit::Webhooks::Handlers::StatusHandler.call(payload)

  victim_commit.reload
  assert_not_equal 'success', victim_commit.status.state,
    "status for the attacker's repository must not mutate the victim stack's commit"
end
```
Before the fix this assertion fails, proving `Commit.where(sha: params.sha)` writes across repository/stack boundaries; after scoping by `repository_name`/`branches`, the assertion passes.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```
