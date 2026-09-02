### Title
`StatusHandler#process` writes GitHub statuses by bare SHA without repository scoping, letting one authenticated repository's status webhook mutate commits belonging to another stack/repository - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits solely by `Commit.where(sha: params.sha)`, with no filter on `repository_name`/`stack`, then calls `commit.create_status_from_github!(params)` on every match across the entire database. `WebhooksController#verify_signature` only proves the payload came from the GitHub App installation matching `repository_owner` in the payload; it says nothing about which `Commit` rows the SHA is allowed to touch, so any SHA collision across repositories (a very common occurrence for forks, since forks share git history and therefore share SHAs) lets a legitimately-signed status for repo A silently update commit status/state for repo B's stack.

### Finding Description
The broken binding is: **the webhook signature authenticates a `(repository_owner, organization)` pair, but `StatusHandler#process` mutates `Commit` rows selected only by `sha`** — i.e., the code implicitly assumes `sha → repository` is unique when it is not.

Path:
- `Shipit::WebhooksController#create` parses the payload, checks `verify_signature` (validated against `Shipit.github(organization: repository_owner)` [1](#0-0) ), then dispatches to handlers with the full parsed payload: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [2](#0-1) .
- `StatusHandler#process` ignores `payload['repository']` entirely and does: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [3](#0-2) . Note the base `Handler` class does define a `stacks` helper scoped by `repository_name` [4](#0-3) , but `StatusHandler` does not use it.
- `Commit#create_status_from_github!` calls `add_status`, which replicates the status, and if the state transitions to `success`/`pending` calls `stack.schedule_merges` [5](#0-4) .
- `Stack#schedule_merges` enqueues `ProcessMergeRequestsJob`, and `Stack#allows_merges?` is gated by `merge_queue_enabled? && !locked? && merge_status == 'success'` [6](#0-5) [7](#0-6) . `Commit#deployable?` also flips based on the now-mutated status: `!locked? && (stack.ignore_ci? || (success? && !blocked?))` [8](#0-7) .

Exploit flow: An attacker owns/controls Repo A whose commit history overlaps a victim Repo B (e.g., B is forked from A, or A is a fork of B, or both share a common upstream commit that neither has rewritten). Because git SHAs are content-addressed, an unmodified commit keeps the same SHA across every clone/fork. The attacker triggers a real, validly-signed GitHub `status` event on Repo A for that shared SHA with `context: ci/coverage`, `state: success` (e.g. via their own CI, or any service they control that posts commit statuses to their own repo). `verify_signature` passes because the signature is checked only against `repository_owner` derived from `payload['repository']['owner']['login']`, which correctly matches Repo A's GitHub App/org secret. But `StatusHandler#process` then updates **every** `Shipit::Commit` row with that SHA, including the one belonging to victim Stack B, changing its computed `status`/`deployable?` and (if `merge_queue_enabled` is true on the victim stack) triggering `schedule_merges` → `ProcessMergeRequestsJob` → eventual `merge!` on the victim's PR queue.

This is not prevented by `verify_signature` (repo-owner/org signature match only, not row-level filtering), by `ExplicitParameters` (only validates payload shape, not repository scope), or by any model validation on `Commit`/`Stack` (there is no uniqueness constraint tying `sha` to a single stack — indeed `Commit` is explicitly `belongs_to :stack` with no cross-repo uniqueness enforced on `sha`).

### Impact Explanation
A payload authenticated for one repository can flip the CI status of a commit belonging to a different repository/stack that happens to share a SHA. On a victim stack with `merge_queue_enabled: true`, this can cause `Stack#allows_merges?`/`Commit#deployable?` to flip to `true` purely from an attacker-controlled, foreign-authenticated status write, driving `ProcessMergeRequestsJob`/`merge!` to merge or advance the queue, or conversely to block/stall it by writing a `failure`/`error` status. This is a critical, repeatable "payload for one repository mutating another's stack/commit" scenario as defined in the target impact categories, and it is repeatable against any pair of repositories sharing commit history (forks, mirrors, monorepo splits) as long as the attacker can trigger a legitimately-signed status webhook on any one of them.

### Likelihood Explanation
Preconditions: (1) attacker needs write access to *some* repository whose Shipit-linked GitHub App/org will sign a status webhook (they can use their own fork/repo, no special privilege needed — "any GitHub user who can push to a fork" per the threat model); (2) that repository's commit SHA space must overlap with a victim stack's commit SHA space, which is trivially true for any fork relationship or shared upstream history; (3) the victim stack must have `merge_queue_enabled: true` (or simply rely on the `deployable?`/CI-gating impact even without merge queue). All these preconditions are realistic and require no secrets, no privileged Shipit role, and no bypass of signature verification — the attack works entirely through legitimate signing of the attacker's own webhook.

### Recommendation
Scope `StatusHandler#process` (and any other handler using bare-SHA lookups against `Commit`) to only the commits belonging to stacks tied to the reporting repository. Use the existing `Handler#stacks` helper (which resolves `Repository.from_github_repo_name(repository_name)&.stacks`) to constrain the `Commit` lookup, e.g. `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`, ensuring a status payload can only ever mutate commits that belong to stacks of the repository that authenticated the webhook.

### Proof of Concept
minitest plan (no live GitHub):
1. Create two `Repository`/`Stack` fixtures, `stack_a` (owner/repo `attacker/repo`) and `stack_victim` (owner/repo `victim/repo`, `merge_queue_enabled: true`).
2. Create a `Commit` with the same `sha` (e.g. `"deadbeef" * 5`) under `stack_a` and another `Commit` with the identical `sha` under `stack_victim`, with the victim commit initially in `pending`/`failure` state (not deployable, `allows_merges?` false).
3. Build a `status` webhook payload: `{ sha: "<shared_sha>", state: "success", context: "ci/coverage", repository: { full_name: "attacker/repo", owner: { login: "attacker" } } }`.
4. Call `Shipit::Webhooks::Handlers::StatusHandler.call(payload)` directly (bypassing signature check as it's already validated in `WebhooksController`, focus is on `process`).
5. Assert: **before** — `stack_victim.commits.find_by(sha: shared_sha).deployable?` is `false` and `stack_victim.allows_merges?` is `false`.
   **after** — `stack_victim.commits.find_by(sha: shared_sha).reload.deployable?` is now `true` (or `status.success?` true), and `stack_victim.reload.allows_merges?` is `true`, proving the victim stack's merge-queue state was mutated by a webhook payload that only authenticated `attacker/repo`.
6. Additionally assert `ProcessMergeRequestsJob` was enqueued for `stack_victim` (via `assert_enqueued_with(job: ProcessMergeRequestsJob, args: [stack_victim])`), demonstrating the merge queue was advanced by cross-repository status bleed.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
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

**File:** app/models/shipit/stack.rb (L231-233)
```ruby
    def schedule_merges
      ProcessMergeRequestsJob.perform_later(self)
    end
```

**File:** app/models/shipit/stack.rb (L380-382)
```ruby
    def allows_merges?
      merge_queue_enabled? && !locked? && merge_status == 'success'
    end
```
