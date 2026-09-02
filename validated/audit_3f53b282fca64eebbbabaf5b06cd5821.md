### Title
`status` webhook applies to every stack sharing a commit SHA, enabling cross-repository status contamination and forced continuous-deployment ship/block - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` writes GitHub commit statuses to `Commit` rows by bare SHA with no repository/stack scoping, so a single signed `status` webhook can affect every stack whose `commits` table happens to contain a row with that SHA. Combined with `Commit#schedule_continuous_delivery`, a `success` status on a required context (e.g. `ci/integration`) can trigger `ContinuousDeliveryJob` on an unrelated victim stack that has `continuous_deployment` enabled.

### Finding Description
The broken binding: the code implicitly assumes `commit.stack.repository == webhook.repository`, but `StatusHandler#process` never checks it:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [1](#0-0) 

`Commit` rows are per-stack (`belongs_to :stack`) [2](#0-1) , but the handler queries across the whole `commits` table by `sha` only, with no `stack_id`/repository filter, and then writes a status onto every matching row via `create_status_from_github!` → `add_status`, which recomputes `status`, emits `Hook.emit(:deployable_status, ...)`, calls `stack.schedule_merges`, and (through `after_commit :schedule_continuous_delivery` semantics reused by `add_status`'s status-change path) can make `deployable?` flip to true, triggering `schedule_continuous_delivery`:

```ruby
def schedule_continuous_delivery
  return unless deployable? && stack.continuous_deployment? && stack.deployable?
  ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
end
``` [3](#0-2) 

and `deployable?`/`blocked?` are driven purely by the aggregated `status` object built from `statuses`, which `create_status_from_github!` just mutated:

```ruby
def deployable?
  !locked? && (stack.ignore_ci? || (success? && !blocked?))
end
``` [4](#0-3) 

**Authentication caveat that limits real-world exploitability:** `WebhooksController#verify_signature` derives the signing organization strictly from the payload's own `repository.owner.login` (or `organization.login`) field and verifies the HMAC against that organization's configured GitHub App/webhook secret:

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
``` [5](#0-4) 

This means an attacker cannot forge an arbitrary `repository` field pointing at the victim's repo — the signature must validate against the secret of the organization named in the payload. So the attacker must control (or have a legitimately signed webhook from) a GitHub organization/repo that is itself configured in `Shipit.github_teams`/`Shipit.github`, and the webhook must be a real, GitHub-signed `status` event for a commit `sha` that the attacker's own repository actually contains. The vulnerability then requires that the *same SHA string* also exists as a `Commit` row belonging to a different (victim) stack — i.e., two repositories that share literal commit objects (common in forked/mirrored/monorepo-split setups, or where a stack's `commits` table is seeded from multiple upstream sources). `StatusHandler` performs no check that the `commit.stack`'s repository matches the webhook's `repository` field, so once that SHA-collision precondition holds, the cross-stack write proceeds unguarded.

### Impact Explanation
If exploited, an attacker-controlled `status` event (state `success`, context `ci/integration`) is written into a completely different stack's commit history, potentially flipping that commit's aggregate `status` to `success` and, if the commit is otherwise `deployable?` and the victim stack has `continuous_deployment` enabled, causing `ContinuousDeliveryJob` to ship attacker-influenced code, or conversely to mark a required context as `error`/`failure` and block deploys on the victim stack. This matches the "payload for one repository mutating another's stack/commit" Critical category, since it is a write to a `Commit`/`Status` record that did not authenticate for that repository. However, this requires an actual SHA collision between the attacker's authenticated repo and the victim's stack, which the codebase does not otherwise prevent but which is not trivially attacker-controllable for arbitrary victim stacks — it depends on shared commit history/content between the two repos.

### Likelihood Explanation
Preconditions: (1) attacker must own or control a GitHub repository/organization already connected to the same Shipit instance (so `verify_signature` succeeds for a real, GitHub-signed status webhook), and (2) that repository must share a literal commit (identical SHA-1) with a target victim stack that has `continuous_deployment` enabled and requires the same status context. This is realistic in fork/mirror/monorepo topologies (e.g., a shared upstream commit merged into multiple Shipit-tracked stacks) but is not a generic "any internet attacker, any victim" primitive — it is bounded to stacks/repos that share commit objects with an attacker-controlled, Shipit-connected repository. Within that scope it is fully repeatable (attacker can call GitHub's status API on their own repo/commit as many times as desired).

### Recommendation
Scope `StatusHandler#process` (and the analogous check-run/deployment-status handlers if similarly unscoped) to the repository that authenticated the webhook, e.g. join through `Stack`/`Repository` and filter `Commit.where(sha: params.sha, stack: Stack.where(repository: repository_from_payload))` instead of a bare cross-tenant `Commit.where(sha:)`.

### Proof of Concept
minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb` conceptually):
1. Create `stack_a` (repo `owner-a/repo-a`) and `stack_b` (repo `owner-b/repo-b`, `continuous_deployment: true`, required context `ci/integration`).
2. Create two `Commit` rows with the identical `sha` value, one belonging to `stack_a`, one to `stack_b` (simulating a shared commit).
3. Assert precondition: `stack_b.commits.find_by(sha: sha).deployable?` is `false` (no successful status yet) — i.e. `commit_b.deployable? == false`.
4. Call `StatusHandler.new.process` (or post to `/webhooks` with `X-Github-Event: status`, valid signature for `owner-a`) with `params.sha = sha, context: 'ci/integration', state: 'success'`, `repository.owner.login = 'owner-a'`.
5. Assert broken binding surfaces: `commit_b.reload.deployable?` becomes `true` and/or `ContinuousDeliveryJob` is enqueued for `stack_b`, even though the webhook only authenticated `owner-a/repo-a`, demonstrating `commit_b.stack.repository.full_name != payload.repository.full_name` while the status was still applied.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/commit.rb (L11-11)
```ruby
    belongs_to :stack
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
