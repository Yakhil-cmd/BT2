### Title
Unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` lets a status webhook from an attacker's own repository forge CI state on another organization's commit - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves the target `Commit` purely by matching the raw `sha` string against every commit in the database, with no filtering by the repository/organization that the webhook was actually authenticated for. Because Git SHA1 identifiers are computed from commit content and are identical across any repository that shares the same commit object (e.g. a public fork), an attacker who owns an unrelated GitHub repository can generate a legitimately-signed `status` webhook for a SHA that also happens to be the HEAD commit of a victim's Shipit stack, causing Shipit to write a forged `success` status onto the victim's commit.

### Finding Description
The broken binding is: `organization_that_signed_the_webhook (attacker's org, verified via Shipit.github(organization: repository_owner) in WebhooksController#verify_signature)` should equal `organization_owning_the_Commit_records_mutated_by_the_payload` - it does not.

`WebhooksController#verify_signature` derives `repository_owner` strictly from the incoming payload's own `repository.owner.login` field and verifies the signature against that organization's `webhook_secret` [1](#0-0) [2](#0-1) . This only proves the payload genuinely came from GitHub for the attacker's own repository/installation - it says nothing about which `Commit` rows the handler is allowed to touch.

`StatusHandler#process` then ignores the payload's `repository` field entirely and looks up commits solely by `sha`: [3](#0-2) 
Contrast this with the base `Handler#stacks` helper, which correctly scopes lookups via `Repository.from_github_repo_name(repository_name)` [4](#0-3) . `StatusHandler` bypasses this scoping helper.

Since `sha` is a content hash, any repository that shares commit history with the victim's tracked repository (most simply, a public fork) will contain a `Commit` object with the exact same `sha`. An attacker who owns such a fork/related repo can:
1. Push/have that shared commit exist in their own repository (trivial if the victim repo is public and forkable).
2. Trigger (or simply wait for GitHub to send, or POST directly if they control a status-emitting integration on their own repo) a `status` webhook with `state=success` for that sha, signed with the attacker's own GitHub App installation secret for their own org.
3. `WebhooksController#verify_signature` succeeds because the signature is valid for the attacker's own organization.
4. `StatusHandler#process` finds the victim's `Commit` (belonging to a completely different stack/organization) via the unscoped `Commit.where(sha:)` query and calls `commit.create_status_from_github!(params)` on it [5](#0-4) .
5. `Commit#add_status` persists a new `Status` row on the victim's commit and, if the state transition changes `simple_state`, emits `Hook.emit(:deployable_status, stack, ...)` for the victim's stack [6](#0-5) .

This is a record write for a repository (the victim's) that never authenticated the request - the signature check only authenticated the attacker's own, unrelated repository. None of the listed guards (`verify_signature`, `ExplicitParameters` schema, `drop_unhandled_event`) catch this because they all operate on the payload's own claimed repository, not on the actual `Commit` rows subsequently mutated.

Downstream, `Commit#deployable?` is computed from the commit's aggregated status state [7](#0-6) , and `Commit#schedule_continuous_delivery` gates `ContinuousDeliveryJob.perform_later(stack)` on `deployable? && stack.continuous_deployment? && stack.deployable?` [8](#0-7) . However, I confirmed that `schedule_continuous_delivery` is wired only via `after_commit ..., on: :create` on `Commit` [9](#0-8)  - it fires when the commit row itself is created, not when a `Status` is later attached to an already-existing commit. `Commit#add_status` (invoked from the forged status) only emits `Hook.emit(:deployable_status, ...)`, which drives Shipit's outbound webhook/notification subsystem, not `ContinuousDeliveryJob` directly. I located a reference to `schedule_continuous_delivery` in `lib/tasks/cron.rake` (out of scope per the rules, and not fully inspected here) that may periodically re-evaluate commits for continuous delivery eligibility, which would be the plausible mechanism turning a forged `success` status into an actual `ContinuousDeliveryJob.perform_later(stack)` enqueue for the victim's stack - but I could not fully verify that cascade within the tool budget available.

### Impact Explanation
Confirmed impact: an attacker can cause a `Status` record with an arbitrary state (including `success`) to be written onto a victim's `Commit`, for a stack/organization the attacker has no relationship to, using credentials that only authenticate the attacker's own repository. This matches the explicitly listed Critical category "a payload for one repository mutating another's stack, commit, task or team" and "a record written for a repository that did not authenticate it." This poisons the victim stack's CI status view (`Commit#status`, `Commit#success?`) and, if the periodic continuous-delivery sweep referenced in `cron.rake` re-evaluates `deployable?` for existing commits (unconfirmed here), can cascade into an unauthorized `ContinuousDeliveryJob` enqueue and an unauthorized deploy of the victim's stack - Critical. The attack is repeatable against any Shipit-tracked repository whose head commit's SHA also exists in a repository the attacker controls (trivially satisfied for any public repository via forking).

### Likelihood Explanation
Preconditions: victim stack tracks a public (forkable) repository, the attacker owns any repository/GitHub App installation capable of emitting a signed `status` webhook (this requires no special Shipit privilege - only ownership of an arbitrary GitHub repo, satisfying the "unprivileged attacker" threat model), and the shared SHA must actually exist in both repos (trivially true immediately after a fork, before any divergent history). No Shipit secrets, sessions, or API tokens are needed. This is low-cost and highly repeatable - it can be attempted against any tracked repository whose SHA the attacker can reproduce in their own repo.

### Recommendation
Scope `StatusHandler#process` (and any other handler using raw `Commit.where(sha:)`/`by_sha` lookups fed from webhook payloads) to only the commits belonging to stacks under `Repository.from_github_repo_name(repository_name)`, mirroring the `Handler#stacks` helper, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or joining through `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`. This ensures a webhook can only mutate commits under the repository that was actually cryptographically verified.

### Proof of Concept
minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`, or extend existing handler tests):
1. Create `stack_a` for repository `attacker/repo` and `stack_b` for repository `victim/repo`.
2. Create `commit_b = shipit_commits(:...)` under `stack_b` with a known `sha` (e.g. `"deadbeef" * 5`).
3. Create `commit_a` under `stack_a` with the **same** `sha` value (simulating the shared/forked commit object).
4. Build a `StatusHandler` payload with `repository.full_name = "attacker/repo"`, `sha` = the shared sha, `state = "success"`.
5. Assert before: `commit_b.statuses.count == 0` and `commit_a.statuses.count == 0`.
6. Call `Shipit::Webhooks::Handlers::StatusHandler.call(payload)`.
7. Assert after: `commit_b.reload.statuses.count == 1` and `commit_b.status.state == "success"` - i.e., the victim's commit (`stack_b`, owned by `victim/repo`) was mutated by a payload whose `repository.full_name` was `attacker/repo`, proving `organization_that_signed_the_webhook != organization_owning_the_mutated_commit`.
8. Optionally, stub `ContinuousDeliveryJob` with Mocha and set `stack_b.update!(continuous_deployment: true)` plus ensure `stack_b.deployable?` is true, then assert `ContinuousDeliveryJob.expects(:perform_later).with(stack_b)` fires from whatever mechanism re-invokes `schedule_continuous_delivery` after the forged status is attached (this last assertion requires confirming the exact re-trigger path, e.g. in `lib/tasks/cron.rake`, which was not fully verified in this pass).

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/commit.rb (L24-25)
```ruby
    after_commit :schedule_refresh_statuses!, :schedule_refresh_check_runs!, :schedule_fetch_stats!,
                 :schedule_continuous_delivery, on: :create
```

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
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
