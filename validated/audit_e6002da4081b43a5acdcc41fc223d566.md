### Title
Cross-repository status forgery via unscoped `Commit.where(sha:)` lookup, amplified by continuous_deployment - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves target commits by bare SHA across the entire `commits` table, with no filtering by the repository that authenticated the webhook. Every other comparable handler (`PushHandler`, `CheckSuiteHandler`) scopes writes through `Handler#stacks`, which derives the target stack set from `Repository.from_github_repo_name(repository_name)`; `StatusHandler` alone omits this scoping, so a signed status payload from repository A can mutate CI state on any stack (repository B, C, ...) whose commit table happens to contain the same SHA.

### Finding Description
The broken binding is: **the repository that signed/authenticated the webhook must equal the repository whose stack/commit record is mutated**, i.e. `repository_owner(payload) == commit.stack.repository.owner` (and by extension `full_name`). This invariant is enforced for `PushHandler` and `CheckSuiteHandler` via `Handler#stacks`: [1](#0-0) 
which restricts operations to `Repository.from_github_repo_name(payload.dig('repository','full_name'))&.stacks`.

`StatusHandler#process`, however, does: [2](#0-1) 
`Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — this is a global, unscoped query across every stack's commits table, keyed only on the bare `sha` string. There is no reference to `payload['repository']` at all in this handler.

`WebhooksController#verify_signature` only proves that the payload was signed by the GitHub App belonging to `repository_owner` (the org/user who owns the *sending* repository): [3](#0-2) 
It never checks that the `sha` in the payload actually belongs to a commit under that same repository. Once the signature check passes, `StatusHandler.call` runs unconditionally against the global `Commit` table.

Once a matching `Commit` row is found (in any stack, any repository), `create_status_from_github!` creates a `Status` row scoped to that commit's `stack_id`: [4](#0-3) 
`Status.replicate_from_github!` persists state/context/description as given by the attacker: [5](#0-4) 
and on create it schedules continuous delivery on the *victim* stack: [6](#0-5) [7](#0-6) 
which, if `stack.continuous_deployment?` is enabled, enqueues `ContinuousDeliveryJob`: [8](#0-7) 
`Stack#trigger_continuous_delivery` then evaluates `next_commit_to_deploy` based on the now-attacker-forged `success`/`failure` status and can trigger `trigger_deploy` immediately: [9](#0-8) 

Exploit path: an attacker who authenticates a webhook for repository A (owning a GitHub App/organization Shipit already knows about, e.g. a sibling repo in the same org, or any repo Shipit is configured to trust for signature verification) sends `POST /webhooks` with `X-Github-Event: status`, a body `{ "repository": {"owner": {"login": "<attacker-controlled-but-known-org>"}}, "sha": "<victim-sha>", "state": "success", "context": "ci/e2e" }`. As long as the signature validates for that owner (satisfied because `verify_signature` only checks the org-level GitHub App secret, not repo identity), and `Commit.where(sha: ...)` finds a row belonging to the victim's stack (this occurs naturally whenever two repositories/stacks share commit history — forks, template repos, monorepo splits, or multiple stacks tracking the *same* underlying repository under different environments), the forged status is written to the victim stack. If the victim stack has `continuous_deployment: true` and requires `ci/e2e`, this forged `success` satisfies `deployable?`/`next_commit_to_deploy` and drives an unauthorized deploy; a forged `failure`/`error` blocks deploys (denial of legitimate deploys).

None of the listed guards prevent this: `verify_signature` authenticates the *sender org*, not the *target commit's owning repository*; `drop_unhandled_event` only filters unknown event types; the `ExplicitParameters` schema in `StatusHandler` only validates presence/type of `sha`/`state`/`context`, not repository identity; there is no `force_github_authentication`/`User#authorized?`/`require_permission!` involved at all since this is an unauthenticated webhook path; model validations on `Repository`/`Stack` don't constrain cross-stack `Commit` lookups by SHA.

### Impact Explanation
A payload correctly authenticated for one repository/org can write a `Status` row to any stack whose `Commit` table contains a matching SHA, and — when that victim stack has `continuous_deployment` enabled — this directly triggers `ContinuousDeliveryJob` → `Stack#trigger_continuous_delivery` → `trigger_deploy`, an unauthorized deploy of already-existing victim commits, or conversely blocks legitimate deploys by forging a failing/erroring status. This matches the "unauthorized deploy" and "payload for one repository mutating another's stack/commit" Critical impact categories. The blast radius is bounded by SHA collision across stacks' commit tables (naturally occurring for forks, template-derived repos, or multiple environments/stacks tracking the same repository), and is repeatable per matching SHA per request.

### Likelihood Explanation
Requires: (1) attacker be able to get a `status` webhook accepted by `verify_signature`, i.e. control (or trigger status-setting on) a repository whose owning org is a Shipit-known GitHub App installation — realistic within any multi-repo/multi-team org that Shipit already serves, or for repos sharing commit history with a Shipit-tracked target (forks/templates); (2) a matching commit SHA exist in the victim stack's `commits` table, which is common when repos share history or when a single upstream repository is tracked by multiple Shipit stacks (e.g., staging/production). No secrets are required beyond legitimately triggering a GitHub status event on an authenticated-but-unrelated repo/commit. This is fully repeatable and requires no privileged Shipit role.

### Recommendation
Scope `StatusHandler#process` the same way as `PushHandler`/`CheckSuiteHandler`: restrict the commit lookup to commits belonging to `stacks` (i.e., `Repository.from_github_repo_name(payload.dig('repository','full_name'))`), e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or equivalently join through `Stack`/`Repository` before matching on `sha`, so a status can only ever mutate commits under the repository that authenticated the webhook.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`, or extend `test/controllers/webhooks_controller_test.rb`):
1. Seed two stacks, `victim_stack` (repository `victim/repo`, `continuous_deployment: true`, requiring `ci/e2e`) and `attacker_stack` (repository `attacker/repo`), each with a `Commit` sharing the same `sha` value (`shared_sha`).
2. Build a `status` webhook payload with `repository.full_name = "attacker/repo"` (so `verify_signature`/`repository_owner` resolves to the attacker's authenticated org), `sha: shared_sha`, `context: "ci/e2e"`, `state: "success"`.
3. Call `Shipit::Webhooks::Handlers::StatusHandler.call(payload)` directly (bypassing HTTP signature layer since that's orthogonal — the point is `process` itself is unscoped).
4. Assert: `victim_stack.commits.find_by(sha: shared_sha).statuses.where(context: "ci/e2e", state: "success").exists?` is `true` — i.e. the equality `repository_owner(payload) == victim_stack.repository.full_name` is **false**, yet the write to `victim_stack`'s commit succeeded.
5. Assert `assert_enqueued_with(job: Shipit::ContinuousDeliveryJob, args: [victim_stack])` fires, demonstrating the forged status reaches `Stack#trigger_continuous_delivery` on a stack the attacker's payload never legitimately authenticated for.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-31)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

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

**File:** app/models/shipit/status.rb (L18-20)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

```

**File:** app/models/shipit/status.rb (L23-34)
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
    end
```

**File:** app/jobs/shipit/continuous_delivery_job.rb (L10-21)
```ruby
    def perform(stack)
      return unless stack.continuous_deployment?

      # If there is a schedule defined for this stack, make sure we are within a
      # deployment window before proceeding.
      return if stack.continuous_delivery_schedule && !stack.continuous_delivery_schedule.can_deploy?

      # checks if there are any tasks running, including concurrent tasks
      return if stack.occupied?

      stack.trigger_continuous_delivery
    end
```

**File:** app/models/shipit/stack.rb (L210-229)
```ruby
    def trigger_continuous_delivery
      return if cached_deploy_spec.blank?

      commit = next_commit_to_deploy

      if should_resume_continuous_delivery?(commit)
        continuous_delivery_resumed!
        return
      end

      if should_delay_continuous_delivery?(commit)
        continuous_delivery_delayed!
        return
      end

      begin
        trigger_deploy(commit, Shipit.user, env: cached_deploy_spec.default_deploy_env)
      rescue Task::ConcurrentTaskRunning
      end
    end
```
