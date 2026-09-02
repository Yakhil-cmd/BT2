This confirms the vulnerability. `Handler` base class provides a `stacks` helper that scopes to the repository from the payload via `Repository.from_github_repo_name(repository_name)&.stacks`, and every other handler (`PushHandler`, `CheckSuiteHandler`, pull-request handlers) uses this `stacks` scope before touching commits. `StatusHandler#process`, however, bypasses it entirely and queries `Commit.where(sha: params.sha)` globally, with no repository/stack filter.

### Title
Cross-repository status write via unscoped `Commit.where(sha:)` in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits by bare SHA across the entire installation instead of scoping to the repository that authenticated the webhook via `Handler#stacks`/`Repository.from_github_repo_name`, unlike every other handler (`PushHandler`, `CheckSuiteHandler`, pull-request handlers). Because `Status` creation triggers `Commit#schedule_continuous_delivery`, a status delivered for one repository can flip CI state and trigger a ship (or block) on an unrelated stack whose `Commit` row happens to share the same SHA.

### Finding Description
The broken binding: for a `status` webhook authenticated for repository R, the intended invariant is `commit.stack.repository == R` for every `Commit` mutated. `StatusHandler#process` instead does: [1](#0-0) 
which iterates `Commit.where(sha: params.sha)` with no join/filter on repository, unlike the base class's `stacks` helper used elsewhere: [2](#0-1) 
Compare `PushHandler#process` (`stacks.not_archived.where(branch:)...`) and `CheckSuiteHandler#process` (`stacks.where(branch: ...)` then `stack.commits.where(sha: ...)`), both of which scope through `Repository.from_github_repo_name(repository_name)` before touching any `Commit`.

`create_status_from_github!` calls `add_status`, which creates a `Status` row for `stack_id` and, via `Status#after_commit :schedule_continuous_delivery`, calls `commit.schedule_continuous_delivery`: [3](#0-2) 
which enqueues `ContinuousDeliveryJob` whenever `deployable? && stack.continuous_deployment? && stack.deployable?` regardless of which repository originated the webhook.

`verify_signature` in `WebhooksController` only checks that the payload's `repository.owner.login` matches a configured GitHub org's `webhook_secret`; it never restricts which `Commit` rows the handler is allowed to mutate: [4](#0-3) 

Exploit flow: two Shipit `Stack`s (e.g. an upstream repo's production stack, and a stack tracking a fork or any other repository within the same/foreign GitHub App installation) can end up with `Commit` rows sharing an identical SHA — this happens naturally with forks, since git commit hashes are content-addressed and shared history between a fork and upstream preserves identical SHAs. An attacker who owns the fork (or any repo whose webhook is verified independently) triggers a legitimate CI job on their own repo that posts a GitHub `status` event with `context: ci/smoke`, `state: success` for that shared SHA. This webhook is legitimately signed for the attacker's repository, passes `verify_signature`, and is dispatched to `StatusHandler`. Because `StatusHandler` never restricts the update to the repository that authenticated the request, it creates a matching `Status` row against the victim stack's `Commit` with the same SHA, satisfying the victim's `required_statuses` and — if `continuous_deployment` is enabled on the victim stack — triggering `ContinuousDeliveryJob` to ship the (attacker-influenced) commit, or conversely injecting a `failure`/`error` status to block deploys.

### Impact Explanation
A payload authenticated for repository A mutates `Status`/`Commit` state belonging to stack/repository B, directly matching the specified Critical category ("a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy, rollback or merge"). On a victim stack with `continuous_deployment` enabled, this can force an unauthorized deploy of a commit the victim did not intend to ship yet, or block deploys by injecting a false failing/pending status for a shared SHA. The blast radius spans any pair of stacks/repositories in the same Shipit instance that ever end up with identical commit SHAs (very plausible for forks, cherry-picked/rebased shared history, or mirrored repos).

### Likelihood Explanation
Requires: (1) attacker controls a repository whose webhooks Shipit accepts (owns a fork or any onboarded repo, using their own legitimately-signed webhook), (2) a `Commit` row with an identical SHA exists in the victim stack (natural for forks/shared git history), (3) victim stack has `continuous_deployment` enabled and a `required_statuses`/`ci/smoke` gate. No secrets, sessions, or privileged roles are needed — the attacker only needs to emit a real, self-authenticated webhook from infrastructure they control. This is fully repeatable per shared-SHA commit and does not require live GitHub in tests since `create_status_from_github!` is unit-testable directly.

### Recommendation
Scope `StatusHandler#process` through the same repository-derived `stacks` association used by `PushHandler`/`CheckSuiteHandler`, e.g. `stacks.each { |stack| stack.commits.where(sha: params.sha).each { |c| c.create_status_from_github!(params) } }`, so a status can only mutate commits belonging to stacks of the repository that authenticated the webhook.

### Proof of Concept
minitest plan (model-level, no live GitHub):
1. Create `stack_a` (repository `org/a`) and `stack_b` (repository `org/b`, `continuous_deployment: true`, `required_statuses` including `ci/smoke`).
2. Create `commit_a` under `stack_a` and `commit_b` under `stack_b` with the identical `sha`.
3. Build a `StatusHandler` payload with `repository.full_name = 'org/a'`, `sha` = the shared sha, `context: 'ci/smoke'`, `state: 'success'`.
4. Assert: `equality_before: commit_b.deployable? == false` (or whatever the pre-state is) and after calling `Shipit::Webhooks::Handlers::StatusHandler.call(payload)`, assert `commit_b.reload.deployable? == true` and/or `assert_enqueued_with(job: Shipit::ContinuousDeliveryJob, args: [stack_b])`, proving `stack_b` (never referenced by the payload's `repository`) was mutated by a webhook authenticated only for `org/a`.

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

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
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
