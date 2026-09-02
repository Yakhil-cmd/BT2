### Title
`StatusHandler#process` writes commit statuses by bare SHA with no repository scoping, allowing a status webhook authenticated for one repository to flip CI state for another stack sharing the same commit SHA - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits with `Commit.where(sha: params.sha).each` [1](#0-0)  — a global, cross-repository query — while every sibling handler (`CheckSuiteHandler`, `PushHandler`, etc.) uses the `stacks` helper that resolves `Repository.from_github_repo_name(repository_name)&.stacks` before touching any commit [2](#0-1) [3](#0-2) . Because Git commit SHAs are content-addressed, forks of a repository share identical SHAs for all commits prior to divergence, so an attacker who owns/controls a fork can send a validly-signed `status` webhook for a shared SHA and have it recorded against a victim stack tracking the upstream repository.

### Finding Description
The broken binding: `commit_status.stack_id == repository_that_authenticated_the_webhook.stack_id` is expected to hold, but `StatusHandler#process` never checks it.

Path: `POST /webhooks` → `WebhooksController#create` parses the JSON body and dispatches to handlers for the `status` event → `StatusHandler.call(params)` → `StatusHandler#process` executes `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [1](#0-0) . This `Commit` scope has no `stack_id`/repository filter at all, unlike the base `Handler#stacks` helper which resolves the stacks belonging only to the repository named in the webhook payload (`payload.dig('repository', 'full_name')`) [2](#0-1) . `StatusHandler` simply doesn't call `stacks` before writing.

`verify_signature` only checks that the HMAC signature matches the webhook secret configured for `Shipit.github(organization: repository_owner)` [4](#0-3)  — it authenticates that "the sender controls a repository/org registered with valid webhook credentials," not that "the sender controls the specific SHA's canonical repository." An attacker who owns a repository configured in Shipit (their own fork, with its own valid webhook secret) can legitimately sign a `status` event naming `context: ci/smoke`, `state: success`, and any `sha` value, including a SHA that is shared history with a victim's upstream repository (any commit predating the fork's divergence has an identical SHA in both repositories, since Git commit hashes are derived purely from content: tree, parents, author/committer, message).

`Commit.create_status_from_github!` recomputes the aggregated `status` and, if it becomes `success`/`deployable`, schedules merges and continuous delivery: `stack.schedule_merges if new_status.pending? || new_status.success?` and `schedule_continuous_delivery` triggers `ContinuousDeliveryJob` when `deployable? && stack.continuous_deployment? && stack.deployable?` [5](#0-4) [6](#0-5) . `deployable?` is purely `!locked? && (stack.ignore_ci? || (success? && !blocked?))` [7](#0-6) , with no repository-identity check. If the victim stack has `bot_login` configured (`Shipit.user`), auto-triggered continuous deployment/merge runs as that bot identity, so forging the `success` status on the shared commit record can trigger an unauthorized deploy or unblock a merge for the victim stack, even though the attacker only authenticated a webhook for their own (different) repository.

None of the existing guards prevent this: `verify_signature` validates only sender authenticity for an org/repo the attacker legitimately controls, not that the target commit's stack belongs to that repository; `drop_unhandled_event` merely checks the event type is registered; `ExplicitParameters` schema only validates the shape/types of `sha`, `state`, `context`, not repository ownership; there is no `Repository`/`Stack` scoping applied in `StatusHandler#process` unlike its siblings.

### Impact Explanation
A `status` webhook authenticated for repository A (which the attacker owns/controls) can mutate CI/status state for a `Commit` record belonging to stack of repository B, provided both share the SHA (trivial via forks, sharing pre-divergence history). This is a cross-tenant write: "a payload for one repository mutating another's stack/commit," matching the Critical impact category — unauthorized deploy/rollback/merge of code the victim did not intend to ship, driven entirely by an attacker-controlled webhook from a repository they legitimately own. The blast radius spans any stack that shares commit history with a repository under attacker control (common for open-source forks), and is repeatable per-SHA at will.

### Likelihood Explanation
Preconditions: victim stack must require the given `context` (e.g., `ci/smoke`) as part of its "required statuses" for deployability, and — per the question's specific configured scenario — have continuous deployment/`bot_login` configured so a `success` state auto-triggers a deploy or merge. The attacker needs only: (1) a Shipit-registered repository they control (a fork, or any repo they legitimately administer with a valid webhook secret), and (2) knowledge of a commit SHA shared with the victim's tracked history — trivially obtained by inspecting the victim's public commit history/fork ancestry. No Shipit session, API token, or GitHub secrets belonging to the victim are required. Cost is a single signed HTTP POST, fully repeatable.

### Recommendation
Scope `StatusHandler#process` the same way as other handlers: resolve the stacks for the repository named in the payload via the inherited `stacks` helper, and only update `commit.create_status_from_github!` for commits belonging to `stacks.flat_map(&:commits)` (or equivalently `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`), rather than a bare `Commit.where(sha: params.sha)` query.

### Proof of Concept
minitest plan (test/models/shipit/webhooks/handlers/status_handler_test.rb — hypothetical, illustrating required assertions):
1. Create `repository_a` (attacker-controlled, registered in Shipit) and `repository_b` (victim), each with their own `Stack`.
2. Create a `Commit` with `sha: "deadbeef..."` under `stack_b` (victim), with `stack_b.continuous_deployment?` true and `bot_login` set (Shipit.user configured), and `ci/smoke` as a required status.
3. Create a `Commit` with the **same** `sha` under `stack_a` (attacker's own stack), simulating shared fork history.
4. Assert baseline: `commit_b.reload.deployable?` is `false` (equality check before: `commit_b.stack_id != commit_a.stack_id` and `commit_b.deployable? == false`).
5. Invoke `Shipit::Webhooks::Handlers::StatusHandler.call('repository' => repository_a.github_payload, 'sha' => sha, 'context' => 'ci/smoke', 'state' => 'success')` — a payload validly signed/attributable only to repository A.
6. Assert the victim's commit was mutated despite the payload naming repository A: `commit_b.reload.deployable?` becomes `true` (or `stack_b.schedule_merges`/`ContinuousDeliveryJob.perform_later` was enqueued), demonstrating the equality `commit_b.stack_id == repository_that_authenticated (A).stack_id` is false yet the write still occurred.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```

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
