### Title
`StatusHandler#process` writes CI status to any commit sharing a SHA across all repositories, bypassing per-repository scoping - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits with `Commit.where(sha: params.sha)` with no repository/stack scoping, unlike `PushHandler#process` which scopes lookups through `stacks` (derived from `repository_name`) before acting [1](#0-0) [2](#0-1) . Any commit whose SHA happens to match `params.sha` — even one belonging to a completely different repository/stack that only shares commit history (e.g. a fork of the target repo) — gets `create_status_from_github!` invoked on it, feeding directly into `add_status`, which can trigger `Hook.emit(:deployable_status, ...)` and `stack.schedule_merges` [3](#0-2) [4](#0-3) .

### Finding Description
The broken binding: the code assumes `Commit.where(sha: params.sha).stack.repository.full_name == payload.dig('repository', 'full_name')` (i.e., a status webhook only touches commits belonging to the repository that sent/signed it). In fact `StatusHandler#process` never checks this — it is:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [1](#0-0) 

The base `Handler` class defines a `stacks` helper that scopes to `Repository.from_github_repo_name(repository_name)&.stacks`, and other handlers such as `PushHandler` use it before mutating any state [5](#0-4) [2](#0-1) . `StatusHandler` does not use `stacks` at all — it queries `Commit` globally by bare SHA, regardless of which repository authenticated the webhook.

Exploit flow: An attacker who owns/controls a fork (or any repository that shares commit history/objects, e.g., includes the exact same upstream commit) with the target's repository can send a legitimate, properly-signed `status` webhook from their own repository/GitHub App installation for the shared commit SHA, with `context: "review/approved"` and `state: "success"` (or `"failure"`). Because the SHA is identical (git SHAs are content-addressed and identical for the same commit object across forks), `Commit.where(sha: params.sha)` matches the row belonging to the **victim's** stack, not just the attacker's own repository. The forged status is written into `commit.statuses` on the victim's commit via `create_status_from_github!` → `add_status`, changing `status.state` and firing `Hook.emit(:deployable_status, ...)` and `stack.schedule_merges` [6](#0-5) . If the victim stack is a production environment gating merges/deploys on `review/approved`, this forged status can flip `deployable?`/`blocked?` for that commit [7](#0-6) , causing an unauthorized ship or block.

Existing guards do not prevent this: webhook signature verification (in `lib/shipit/github_app.rb` / `WebhooksController`) only proves the payload came from *some* repository/installation the attacker legitimately controls — it says nothing about which commits that payload is allowed to affect. The `ExplicitParameters` schema for `StatusHandler` only validates types of `sha`/`state`/`context`, not repository ownership of the SHA [8](#0-7) . Nothing in `Commit`, `Stack`, or `Repository` validations restricts cross-repository writes to a commit row by SHA.

### Impact Explanation
An attacker who controls any repository sharing commit history with a victim's tracked repository (trivially true for any fork, since forked commits retain identical SHAs) can inject arbitrary CI/status data (`review/approved`, or any other status context) onto the victim's commit record, without ever authenticating to or having permission on the victim's repository or Shipit instance. Because status state feeds directly into `deployable?`/`blocked?` and triggers `stack.schedule_merges`, this can cause an unauthorized deploy, rollback, or merge-blocking on a stack that did not authorize the status — squarely a "payload for one repository mutating another's stack/commit" and "unauthorized deploy/rollback/merge" impact (Critical).

### Likelihood Explanation
Preconditions: attacker needs a repository sharing at least one commit SHA with the victim's tracked repository — trivially satisfied by forking the victim's repo (a common, unprivileged GitHub action) and configuring (or already having) a webhook/GitHub App delivery for that fork pointing at the same Shipit host, which is standard for any repository onboarded to Shipit's GitHub App. No Shipit session, API token, or `webhook_secret` is needed beyond what the attacker's own repository already has. The attack is fully repeatable against any SHA shared between attacker-controlled and victim repositories.

### Recommendation
Scope `StatusHandler#process` (and any other SHA-keyed handler) to only commits belonging to stacks of the repository that authenticated the webhook, mirroring `PushHandler`'s use of the `stacks` helper, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or joining `Commit` through `Stack`/`Repository` filtered by `repository_name` before calling `create_status_from_github!`.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`):
1. Create `repository_a` (victim) and `repository_b` (attacker-controlled), each with their own `Stack`; set `stack_a.environment = 'production'` and configure a deploy spec requiring `review/approved` status.
2. Create a `Commit` under `stack_a` with a fixed `sha` (e.g., `'a' * 40`) and another `Commit` under `stack_b` with the **same** `sha`, simulating a shared/forked commit.
3. Build a webhook payload: `{ 'sha' => 'a'*40, 'state' => 'success', 'context' => 'review/approved', 'repository' => { 'full_name' => repository_b.full_name } }`.
4. Call `Shipit::Webhooks::Handlers::StatusHandler.call(payload)`.
5. Assert: `stack_a`'s commit's `status.state`/`deployable?` changed (equality broken: `commit_a.reload.status.success?` becomes true) even though the payload's `repository.full_name` equals `repository_b.full_name`, not `repository_a.full_name` — proving the binding "`status` only affects the repository that authenticated it" is violated.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```
