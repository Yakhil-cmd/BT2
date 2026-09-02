### Title
`StatusHandler#process` updates commits across all stacks by bare SHA with no repository check, allowing a `ci/integration` failure from an attacker-controlled repo to flip status on a victim stack with `merge_queue_enabled` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits solely by `Commit.where(sha: params.sha)` with no `repository`/`stack` scoping, so any repository that shares a commit SHA with a victim's stack (e.g. via a fork with identical git history) can push arbitrary `status` context/state pairs onto the victim's commit. When the victim stack has `merge_queue_enabled: true`, flipping the required `ci/integration` status changes `deployable?`/`blocked?` and triggers `stack.schedule_merges`, causing an unauthorized merge/ship or block.

### Finding Description
The broken binding: the code assumes `commit.sha == params.sha ⇒ commit.stack.github_repo_name == webhook_authenticated_repository`, but this equality is never checked.

`StatusHandler#process` is:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [1](#0-0) 

This queries the global `commits` table by bare `sha` with no `stack_id`/repository filter. Since git commit SHAs are content-addressed (tree + parents + metadata), any repository that is a fork of, or otherwise shares history with, the victim repository will produce identical SHAs for shared commits. An attacker who owns such a fork can trigger a legitimate, correctly-signed `status` webhook from their own repository (which they fully control and can authenticate for) for a SHA that also exists as a `Commit` record on the victim's stack.

`create_status_from_github!` then calls `add_status`, which calls `statuses.replicate_from_github!` and, on a state transition, `stack.schedule_merges if new_status.pending? || new_status.success?` [2](#0-1) [3](#0-2) . The victim commit's `deployable?` and `blocked?` are derived directly from `stack.required_statuses`/`blocking_statuses` matched against the `statuses` association [4](#0-3) , so writing a `failure` status for `ci/integration` on the victim's commit record — despite it never being reported by GitHub for the victim repository — directly manipulates `blocked?`/`deployable?` and, combined with `merge_queue_enabled`, the merge queue's advance/hold decision.

No existing guard prevents this: signature verification (`verify_signature`/`GitHubApp#verify_webhook_signature`) only proves the payload came from the repository that generated it (the attacker's own repo, which they legitimately own and can generate valid webhooks for) — it does not bind the payload to the specific `stack`/repository being mutated. The `ExplicitParameters` schema for `StatusHandler` only validates types (`sha`, `state`, `context`, etc.), not repository identity [5](#0-4) . `Commit.where(sha: params.sha)` performs no filtering by repository at all.

### Impact Explanation
A single unprivileged attacker who controls (or forks) any repository sharing commit history with a victim's tracked repository can, via a normal signed `status` webhook, mutate the `statuses` and thus `deployable?`/`blocked?` state of a commit belonging to a stack they do not own or administer. On a stack with `merge_queue_enabled: true`, this directly triggers `stack.schedule_merges`, causing `merge!` to fire — an unauthorized merge/ship, or conversely a forced block of a legitimate deploy. This is a cross-tenant write: a payload authenticated for one repository mutates another repository's stack/commit state, matching the Critical impact category ("a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy, rollback or merge").

### Likelihood Explanation
Preconditions: the victim stack must have a `Commit` record with a SHA that also exists in a repository the attacker controls (trivially achievable via forking, since forks share git object history for unmodified commits), and the victim stack must require/consume the `ci/integration` context with `merge_queue_enabled: true`. Attacker cost is a single unauthenticated `POST /webhooks` (or a real GitHub status event from their own fork) — no Shipit session, API token, or team membership needed. This is fully repeatable against any stack with overlapping commit history.

### Recommendation
Scope `StatusHandler#process` (and analogous handlers) to commits belonging to the repository that authenticated the webhook, e.g. join through `stack` and filter by `stack.repository_owner`/`stack.repository_name` (or `github_repo_name`) matching `payload.repository.full_name`, instead of matching on bare `sha` alone.

### Proof of Concept
minitest plan (`test/models/webhooks/handlers/status_handler_test.rb`):
1. Create two stacks, `victim_stack` (`repo_owner/repo_name = "victim/repo"`, `merge_queue_enabled: true`, `required_statuses: ["ci/integration"]`) and `attacker_stack` (`repo_owner/repo_name = "attacker/fork"`).
2. Create a `Commit` with the same `sha` "deadbeef..." under both `victim_stack` and `attacker_stack` (simulating shared git history from a fork).
3. Assert baseline: `victim_commit.deployable?` is `true` (or as configured) and `victim_stack` merge queue is not scheduled — i.e., `victim_commit.status.state == "success"` binding holds `victim_commit.stack_id != attacker_commit.stack_id` but `victim_commit.sha == attacker_commit.sha`.
4. Build `StatusHandler` params with `sha: "deadbeef..."`, `context: "ci/integration"`, `state: "failure"`, signed/authenticated as if from `attacker/fork`.
5. Invoke `StatusHandler.new(...).process`.
6. Assert `victim_commit.reload.deployable?` flipped to `false` / `blocked?` is now driven by the injected failure status, and `stack.schedule_merges` was called for `victim_stack` — demonstrating the cross-repository write and merge-queue impact despite the webhook never having been authenticated for `victim/repo`.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L7-18)
```ruby
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

**File:** app/models/shipit/commit.rb (L227-237)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end

    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
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
