### Title
`StatusHandler#process` writes commit statuses by bare SHA with no repository scoping, allowing one repository's webhook to mutate another stack's commit status - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves target commits with `Commit.where(sha: params.sha)`, which is not scoped to the repository that authenticated the webhook. Any commit row in any stack/repository sharing that SHA (e.g. shared git history between a fork and the original, mirrored repos, or cherry-picked commits) will have its status updated, which can flip `deployable?`/`blocked?` and trigger `schedule_merges`/`ContinuousDeliveryJob` for a stack the attacker never authenticated for.

### Finding Description
The broken invariant, stated as an equality that should hold but does not:
`commit.stack.repository == webhook.repository` for every `commit` mutated by `StatusHandler#process`.

Code path:
- `app/models/shipit/webhooks/handlers/status_handler.rb:20-24`:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
This query has no `stack_id`/`repository` filter — it matches every `Shipit::Commit` row across every stack in the installation whose `sha` column equals the attacker-controlled `params.sha`. [1](#0-0) 

The `commits` table is indexed on `(stack_id, sha)` rather than a globally unique `sha`, confirmed by the migration `index_commits_on_stack_id_and_sha`, meaning the schema explicitly allows the same SHA to exist in multiple stacks simultaneously. [2](#0-1) 

`create_status_from_github!` then calls `add_status`, which recomputes `status`, fires `Hook.emit(:commit_status, ...)` / `Hook.emit(:deployable_status, ...)`, and calls `stack.schedule_merges` when the new status is `pending?` or `success?` — i.e., it can directly affect deploy/merge behavior of the victim stack. [3](#0-2) [4](#0-3) 

`deployable?` and `blocked?` on `Commit` are purely a function of the commit's own status and the stack's configuration, with no re-check of which repository the incoming status payload actually came from: [5](#0-4) 

The `params` schema for `StatusHandler` never requires or validates a `repository` field, so nothing in the handler itself can distinguish "this status belongs to my repo" from "this status belongs to some other repo that happens to share the SHA": [6](#0-5) 

**Why existing guards don't stop this:** webhook signature verification (`GitHubApp#verify_webhook_signature`) only proves the payload was sent by a GitHub App/webhook the operator configured — it does not bind the payload's SHA to a specific repository inside `StatusHandler#process`, because the handler doesn't consult the payload's `repository` field at all. As long as an attacker can get a `status` event delivered with a SHA that also exists in a victim's stack (e.g., via a forked repo sharing base history, or a repository legitimately configured to send webhooks, where the attacker controls commits/refs), the handler will indiscriminately update every matching commit across every stack.

I was not able to independently verify the second half of the report's claim — a "review_stacks_enabled false provisioning precedence bug" that additionally causes stack provisioning despite the flag being disabled. The `review_stacks_enabled` logic lives in the `pull_request/labeled_handler.rb`, `pull_request/unlabeled_handler.rb`, and `pull_request/opened_handler.rb`/`reopened_handler.rb` files, which are a separate code path from `StatusHandler`, and I did not find evidence in the reviewed code that `StatusHandler` interacts with `review_stacks_enabled` or stack provisioning at all. That part of the narrative appears to conflate two unrelated subsystems and should be treated as unverified.

### Impact Explanation
An attacker who controls (or can trigger status events for) a SHA that coincidentally or deliberately also exists in a victim stack's `commits` table can flip that victim commit's status (e.g. to `failure` for `ci/coverage`), which changes `deployable?`/`blocked?` for the victim stack and can trigger or block `stack.schedule_merges` / continuous deployment for a stack the attacker never authenticated against. This is a cross-tenant write to a repository's/stack's deployment state that the attacker's webhook did not authenticate for, matching the "payload for one repository mutating another's stack/commit" Critical impact category.

### Likelihood Explanation
Exploitability depends on the attacker being able to produce a SHA collision with a real commit already present in the victim stack's `commits` table — realistic in organizations that mirror/fork repositories, use subtree merges, or otherwise share identical commit objects across multiple Shipit-tracked repositories, all of which are common setups. The attacker needs only to cause a legitimate, correctly-signed `status` webhook to be delivered (from a repository they control) referencing that shared SHA; no Shipit secrets, sessions, or team membership are required. This is repeatable against any stack sharing history with an attacker-influenced repository.

### Recommendation
Scope the commit lookup in `StatusHandler#process` (and analogously in `CheckRunHandler` if it has the same pattern) to the repository that authenticated the webhook, e.g. join through `Stack`/`Repository` and filter `Commit.joins(stack: :repository).where(sha: params.sha, shipit_repositories: { owner: ..., name: ... })` using the repository identity carried in the webhook payload, rather than a bare `sha` match across all stacks.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb` conceptually):
1. Create `repository_a` (attacker-controlled) and `repository_b` (victim) with separate `Stack` records, `stack_a` and `stack_b`.
2. Create a `Commit` with `sha: "deadbeef..."` under `stack_b` (simulating shared git history), and assert `stack_b.commits.last.deployable? == expected_before` and `stack_b.commits.last.status.state == "success"` (baseline, both sides of the binding equal).
3. Build `StatusHandler` params as if delivered by a webhook belonging to `repository_a` (`context: "ci/coverage"`, `state: "failure"`, `sha: "deadbeef..."`), and call `StatusHandler.new(delivery, params).process`.
4. Assert `stack_b.commits.last.reload.status.state == "failure"` and `stack_b.commits.last.deployable? != expected_before` — i.e., `commit.stack.repository == repository_a` is false, yet `stack_b`'s commit was mutated, proving the invariant "a `ci/coverage` status affects only the repository that authenticated it" is violated.

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

**File:** db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb (L1-1)
```ruby
class IndexCommitsOnStackIdAndSha < ActiveRecord::Migration[5.1]
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
