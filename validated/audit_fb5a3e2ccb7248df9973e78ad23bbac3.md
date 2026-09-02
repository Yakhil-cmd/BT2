### Title
Cross-repository `status` webhook allows attacker to flip commit status and trigger merge queue actions on a victim stack — (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves target commits with a bare, repository-unscoped query `Commit.where(sha: params.sha)`, unlike every other handler in this module which resolves the target via `stacks` (scoped through `Repository.from_github_repo_name(repository_name)`). This lets a `status` webhook validly signed for one repository mutate `Status` rows — and therefore trigger `stack.schedule_merges` / deployability — for any other stack whose `commits` table happens to contain a `Commit` with the same SHA.

### Finding Description
The broken binding: the invariant the system should enforce is `commit.stack.repository == payload['repository']['full_name']` for every `Commit` mutated by a `status` event; in `StatusHandler` this equality is never checked.

Trace:
- `Handler#stacks` (the standard, safe resolution path used by other handlers) computes `Repository.from_github_repo_name(repository_name)&.stacks` from `payload.dig('repository', 'full_name')` [1](#0-0) .
- `StatusHandler#process` ignores this scoping entirely and instead does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [2](#0-1) . The `sha` here comes only from attacker-controlled `params.sha`; `context`, `state`, `description`, `target_url` are likewise attacker-controlled fields declared in the `params` schema [3](#0-2) .
- Any `Commit` row across the entire installation whose `sha` matches will have `create_status_from_github!` called on it, replicating the attacker's status into that commit's `statuses` association regardless of which stack/repository the commit actually belongs to [4](#0-3) .
- `create_status_from_github!` → `add_status` recomputes `status`, and if the simple state changed to `success`/`pending`, unconditionally calls `stack.schedule_merges` [5](#0-4) . `deployable?` is `!locked? && (stack.ignore_ci? || (success? && !blocked?))` [6](#0-5) , meaning a forged `success` status can make an otherwise-blocked commit deployable, and on a `merge_queue_enabled` stack a green head advances/merges the queue.
- Why signature verification does not stop this: the webhook signature verifies that a request came from a repository/installation legitimately webhooked to this Shipit instance — it does **not** bind the `sha` field's target `Commit` rows to that repository. `StatusHandler` never consults `repository_name`/`stacks` at all, so the "authenticated repository" and the "repository whose commit gets mutated" can diverge whenever two stacks (e.g., a fork and its upstream, or two stacks tracking overlapping history) share a commit SHA — which is common and unforced (identical commit metadata/content/parents produce identical SHAs across any number of repositories/forks).

Attacker request: a legitimately-signed `status` webhook from a repository the attacker owns/controls (e.g., their fork, which shares ancestor commit SHAs with the victim's tracked repository) with `context: github-actions`, `state: success`, and `sha` equal to a commit SHA that also exists in the victim's `Commit` table for a `merge_queue_enabled` stack.

### Impact Explanation
A payload authenticated for repository A causes a database write (`Status` row insertion) and side effects (`stack.schedule_merges`, deployability change) against repository B's stack/commit, matching the Critical category "a payload for one repository mutating another's stack, commit, task or team" and potentially "an unauthorized deploy, rollback or merge" when combined with `merge_queue_enabled`. It is repeatable against any pair of stacks that share a commit SHA (forks, mirrored repos, shared upstream history) and requires no privileges beyond the ability to push a webhook-triggering event to a repo the attacker legitimately controls.

### Likelihood Explanation
Preconditions: (1) the attacker's own repository is webhooked into the same Shipit instance (a normal, non-privileged onboarding state, not a secret), (2) the victim stack has a `Commit` row sharing a SHA with a commit reachable/creatable by the attacker (trivially achievable via forks, shared upstream commits, or replaying an identical commit object into a different repo), and (3) `merge_queue_enabled: true` on the victim stack. Given these, the exploit is a single unauthenticated-looking (but validly signed for the attacker's own repo) HTTP POST to `/webhooks` — low cost, fully repeatable.

### Recommendation
Scope `StatusHandler#process` the same way other handlers do: resolve the target repository via `stacks` (or `Repository.from_github_repo_name(repository_name)`) and restrict the `Commit` lookup to `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`, rejecting/no-op if the SHA does not belong to a commit under the authenticated repository's stacks.

### Proof of Concept
minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`, illustrative — not present in current suite):
1. Create `repo_a` (`Repository`), `stack_a` with `merge_queue_enabled: true`, and `repo_b` (different `Repository`), `stack_b`.
2. Create `commit = stack_b.commits.create!(sha: 'deadbeef...')` — belongs only to `stack_b`.
3. Build a `status` webhook `payload` with `repository.full_name = repo_a.github_repo_name`, `sha: commit.sha`, `context: 'github-actions'`, `state: 'success'`.
4. Assert before: `commit.reload.status.success?` is false / `commit.deployable?` is false (or whatever baseline), and `commit.stack_id == stack_b.id` while `payload['repository']['full_name'] == repo_a.github_repo_name` (the two named values that should never both feed the same mutation).
5. Call `Shipit::Webhooks::Handlers::StatusHandler.call(payload)`.
6. Assert after: `commit.reload.statuses.last.state == 'success'` and `commit.deployable?`/merge-queue state on `stack_b` changed — even though the authenticated `repository.full_name` was `repo_a`, not `repo_b`/`stack_b`'s repository — proving the cross-repository write.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L6-18)
```ruby
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
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
