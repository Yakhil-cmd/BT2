### Title
Cross-repository commit-sha collision in `StatusHandler#process` triggers continuous delivery for a stack never named in the webhook payload - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves target commits by SHA alone (`Commit.where(sha: params.sha)`) without scoping the query to the repository named in the verified webhook payload, unlike every other handler in the engine. Because `sha` is not unique per repository in the Shipit database (forks and any repository sharing commit ancestry with a tracked stack will contain identical commit SHAs), a validly-signed status webhook for repository A can create a `Status` on a `Commit` belonging to repository B's stack, which via `Status#after_commit :schedule_continuous_delivery` unconditionally invokes `commit.schedule_continuous_delivery` and `stack.schedule_merges` for B's stack.

### Finding Description
The claimed binding is:
`stack_for_which_CD_is_scheduled == stack(repository_named_in(verified_webhook_payload))`

Tracing the call path shows this binding is **not enforced** in `StatusHandler`:

- `Handler` (the base class) exposes a repository-scoped helper, `stacks`, derived from `payload.dig('repository', 'full_name')`: [1](#0-0) 
- `PushHandler` correctly uses this scoping (`stacks.not_archived.where(branch:)`), so a push webhook can only affect stacks belonging to the named repository: [2](#0-1) 
- `StatusHandler#process`, however, bypasses this scoping entirely and queries `Commit` globally by `sha`, ignoring `repository_name`/`stacks`: [3](#0-2) 

Once a matching `Commit` row exists in *any* stack with the attacker-supplied SHA, `create_status_from_github!` persists a `Status` for that commit's stack: [4](#0-3) 

`Status` then unconditionally schedules continuous delivery on `after_commit`, with no re-check of which repository authenticated the webhook: [5](#0-4) [6](#0-5) 

`Commit#schedule_continuous_delivery` and `add_status` then drive the victim stack's continuous-delivery and merge-queue machinery: [7](#0-6) [8](#0-7) 

**Root cause**: `StatusHandler` never intersects the resolved `Commit` set with `stacks` (repository-scoped), so a SHA collision across repositories — trivially achievable via a fork sharing commit ancestry with the victim's tracked branch, or any repository that happens to contain an identical commit object — lets an attacker's own, validly-signed webhook (signed under the attacker-controlled repository/org's own webhook secret, per the threat model's stated capability to "emit webhooks from a repository they own") mutate state belonging to a repository/stack the attacker never authenticated for.

**Why existing guards don't catch this**: `verify_signature`/`GitHubApp#verify_webhook_signature` only proves the payload was signed for the organization named in the payload (the attacker's own org) — it says nothing about which `Commit`/`Stack` rows the handler is allowed to touch. `ExplicitParameters` validates the shape of `sha`/`state`, not their scope. There is no `stacks`/repository check anywhere in `StatusHandler`, unlike `PushHandler`.

### Impact Explanation
A repository/webhook the attacker fully controls (e.g., their own fork of a public victim repository, sharing commit ancestry/SHAs with the victim's tracked branch) can cause Shipit to write a `Status` row against the **victim's** `Commit`/`Stack`, and unconditionally trigger `ContinuousDeliveryJob.perform_later(stack)` and `stack.schedule_merges` (→ `ProcessMergeRequestsJob`) for the **victim's stack**, provided the victim stack has continuous deployment/merge-queue configured and the colliding commit is otherwise deployable. This is a payload for one repository mutating another repository's stack/commit state and triggering an unauthorized deploy pathway — matching the Critical impact category ("a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy, rollback or merge"). It is repeatable against any victim stack whose tracked branch shares commit ancestry (forks, shared upstream history, cherry-picks producing identical commit objects) with a repository the attacker controls.

### Likelihood Explanation
Requires: (1) a victim stack with continuous deployment or merge-queue enabled and a commit that is otherwise deployable, and (2) a `Commit` row with identical SHA reachable in the victim stack (realistically achieved by forking a public victim repository being tracked by Shipit, since fork commits share identical SHAs with upstream history) and (3) the attacker's own repository being wired to send validly-signed webhooks to the Shipit host (per the threat model, attacker can "emit webhooks from a repository they own"). Fork-sharing-ancestry is a common, low-cost, entirely repeatable setup requiring no secrets, no privileged role, and no brute-forced SHA1 collision — only a fork of a public repo whose history the victim stack has already ingested.

### Recommendation
Scope `StatusHandler#process` to the repository named in the verified webhook payload, mirroring `PushHandler`'s use of the `stacks` helper, e.g. restrict the `Commit` lookup to `Commit.where(sha: params.sha, stack_id: stacks.select(:id))` (or join through `stack.repository == repository_name`) before calling `create_status_from_github!`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb (proof sketch)
test "status webhook for attacker's repo must not trigger CD for a colliding-sha commit in a different stack" do
  victim_stack = shipit_stacks(:shipit)
  victim_stack.update!(continuous_deployment: true)
  colliding_sha = "a" * 40

  victim_commit = victim_stack.commits.create!(sha: colliding_sha, message: "shared ancestry commit")

  # Attacker's own repo/stack, unrelated to victim, but containing a commit
  # with the same sha (e.g. via forked history)
  attacker_stack = shipit_stacks(:cyclimse)
  attacker_stack.commits.create!(sha: colliding_sha, message: "shared ancestry commit")

  payload = {
    "sha" => colliding_sha,
    "state" => "success",
    "repository" => { "full_name" => attacker_stack.repository.full_name }, # only attacker's repo named
  }

  assert_enqueued_with(job: ContinuousDeliveryJob, args: [victim_stack]) do
    Shipit::Webhooks::Handlers::StatusHandler.call(payload)
  end
  # Binding check: stack CD was scheduled for (victim_stack) != stack(repository named in payload) (attacker_stack)
end
```
This demonstrates that `StatusHandler.call` with a payload naming only the attacker's repository enqueues continuous-delivery/merge work for `victim_stack`, violating the required binding.

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

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
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

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```

**File:** app/models/shipit/status.rb (L42-44)
```ruby
    def schedule_continuous_delivery
      commit.schedule_continuous_delivery
    end
```
