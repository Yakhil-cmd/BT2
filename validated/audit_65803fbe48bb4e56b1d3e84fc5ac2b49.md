### Title
Cross-repository status forgery via unscoped `Commit.where(sha:)` in `StatusHandler#process` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits by bare SHA across the entire `commits` table instead of scoping to the repository that authenticated the webhook, unlike every other handler which uses the `stacks` helper tied to `payload.dig('repository', 'full_name')`. An attacker who owns any repository wired into Shipit can send a `status` webhook (validly signed for their own repo) for a SHA that happens to collide with a commit tracked by a victim stack, and `create_status_from_github!` will write/replace status data on that victim commit.

### Finding Description
The broken binding: the invariant that should hold is `status.repository_full_name == commit.stack.repository.full_name` for every status written by `StatusHandler`. In the actual code this equality is never checked.

`Handler` defines a `stacks` helper explicitly to scope lookups to the repository that sent the webhook: [1](#0-0) 

But `StatusHandler#process` does not use it — it queries `Commit` globally by SHA: [2](#0-1) 

`Commit#create_status_from_github!` then calls `add_status`, which recomputes `status`, may emit `Hook.emit(:deployable_status, ...)`, and — critically — calls `stack.schedule_merges` when the new status is pending or successful: [3](#0-2) 

Root cause: SHA values are not repository-namespaced in git generally, and Shipit's own schema stores commits per-`stack_id`, but `StatusHandler` never joins/filters on the stack's repository. Any repository the attacker controls that is webhook-registered with Shipit lets them submit a validly-signed `status` payload (signature verification only proves *the payload came from that repo's webhook secret*, not that the `sha` belongs to that repo). If that `sha` collides with a commit already recorded against a victim's stack (e.g., shared submodule commit, cherry-picked commit, or an attacker deliberately crafting a commit with identical tree/parents/timestamps to force a matching SHA against a known target commit), the attacker's `context: deploy/production`, `state: success` status is attached to the victim's commit, potentially unblocking or triggering `schedule_merges`/continuous delivery, which (per the audit's stated configuration) executes deploy tasks as the stack's configured bot identity.

Existing guards do not stop this: `verify_signature`/`GitHubApp#verify_webhook_signature` only prove the payload came from *some* registered repository's webhook, not that its `sha` belongs to that repository's commit history; `drop_unhandled_event` and `ExplicitParameters` only validate payload shape; none of them re-derive or check `repository_name` against the target commit's stack in `StatusHandler`.

### Impact Explanation
A payload that authenticated for repository A can mutate commit/status state that belongs to repository B's stack — this is the "payload for one repository mutating another's stack/commit" category (Critical). If the victim stack has continuous deployment or merge-queue behavior gated on CI status, a forged `success`/`failure` status for `deploy/production` can trigger `stack.schedule_merges` or unblock a deploy, executed under the bot identity configured for that stack. This is repeatable against any stack whose commits share a SHA reachable by the attacker and is not limited to a single victim.

### Likelihood Explanation
Preconditions: the attacker needs (a) a Shipit-registered repository they control (to obtain a valid webhook signature), and (b) a SHA collision with a commit tracked in the victim's stack. Exact SHA-1 collisions are impractical to engineer directly, but the SHA does not need to be attacker-authored — it only needs to be *any* commit SHA already present in both the attacker's accessible repo (or fabricated payload referencing an arbitrary `sha` string, since `StatusHandler` does not validate that the SHA exists in the sender's own repository/commit history at all) and the victim's `commits` table. Since `Commit.where(sha: params.sha)` performs a exact-string match with no upstream validation that the SHA belongs to the authenticated repository, an attacker can simply supply *any* known victim commit SHA (e.g., observed publicly on the victim's GitHub repo or Shipit deploy page) in a webhook signed by their own unrelated repository. This drastically lowers the bar: no hash collision is required, only knowledge of a target SHA, making the attack practical and repeatable.

### Recommendation
Scope `StatusHandler#process` to the repository that authenticated the webhook, mirroring the `stacks` helper used elsewhere, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or joining `Commit` to `Stack`/`Repository` and filtering on `repository_name` derived from `payload.dig('repository', 'full_name')` before applying the status.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`):
1. Create `repository_a` (attacker-owned, registered with Shipit) and `repository_b`/`stack_b` (victim, `bot_login` configured via `Shipit.user`, `deploy/production` required status).
2. Create `commit_b` under `stack_b` with `sha: "deadbeef..."`.
3. Build a `status` webhook payload with `repository.full_name = repository_a.github_repo_name`, `sha: commit_b.sha`, `context: "deploy/production"`, `state: "success"`, signed with `repository_a`'s webhook secret.
4. Call `StatusHandler.call(payload)`.
5. Assert `commit_b.reload.status.success?` is now `true` and/or `stack_b.schedule_merges`/deploy was invoked — i.e. assert `commit_b.stack_id == stack_b.id` while the authenticated `repository_name` from the payload equals `repository_a.github_repo_name`, proving `payload.repository != commit.stack.repository` yet the write succeeded, violating the stated invariant.

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
