### Title
Cross-repository/stack CI-status forgery via unscoped `Commit.where(sha:)` in `StatusHandler#process` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits by bare SHA across the entire `commits` table with no repository/stack scoping, unlike sibling handlers (`PushHandler`, `CheckSuiteHandler`) which explicitly filter via `stacks` (derived from the payload's `repository.full_name`). Because the `commits` table only enforces `sha` uniqueness per `stack_id` (not globally), a `status` webhook whose signature is valid for *some* GitHub organization/repository can write a `Status` row onto any `Commit` record in any other stack that happens to share the same 40-char SHA (e.g., commits shared via a fork/shared history), directly affecting that victim stack's `deployable?`/`blocked?`/merge computations.

### Finding Description
The broken binding the code should enforce is: `status.commit.stack_id == webhook.repository.stack_id` (a status can only ever attach to a commit belonging to the stack that owns the repository which sent the webhook). Instead: [1](#0-0) 

`process` runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — an unscoped, table-wide lookup by SHA, with no reference to `repository_name`/`stacks` at all. Compare this to `PushHandler#process`, which restricts to `stacks.not_archived.where(branch:)` [2](#0-1) , and `CheckSuiteHandler#process`, which restricts to `stacks.where(branch: ...)` then `stack.commits.where(sha: ...)` [3](#0-2) . Both siblings derive `stacks` from `Repository.from_github_repo_name(repository_name)` in the shared base class [4](#0-3) , i.e., they scope to the repository that authenticated the webhook. `StatusHandler` uniquely omits this scoping.

The DB schema confirms SHA uniqueness is enforced only per stack, not globally: `add_index "commits", ["sha", "stack_id"], unique: true` [5](#0-4) , so it is entirely legitimate/expected for the same bare SHA to exist as separate `Commit` rows in multiple different stacks (this occurs naturally with forks/shared git history, or via the `create_from_github` shared-parent path used by `GithubSyncJob#lookup_commit`, which itself is properly scoped to `stack.commits.find_by(sha:)` [6](#0-5) ).

`Commit#create_status_from_github!` unconditionally records the status against the commit's own `stack_id`: `statuses.replicate_from_github!(stack_id, github_status)` [7](#0-6) . Once written, `Commit#deployable?` (`!locked? && (stack.ignore_ci? || (success? && !blocked?))` [8](#0-7) ) and `Commit#blocked?` (checks `stack.blocking_statuses` across undeployed commits [9](#0-8) ) are re-evaluated using this attacker-supplied status the next time the victim stack computes deploy eligibility (`Stack#next_expected_commit_to_deploy`, `UndeployedCommit#deploy_state`, merge queue `allows_merges?`).

Regarding webhook authentication: `WebhooksController#verify_signature` verifies the raw HMAC signature against the secret configured for `Shipit.github(organization: repository_owner)`, where `repository_owner` is read straight from the attacker-controlled `payload['repository']['owner']['login']` [10](#0-9) , [11](#0-10) . This only proves the webhook truly came from GitHub for *some* organization/repository that has the Shipit GitHub App/webhook installed (whichever organization the attacker controls or has push access to) — it in no way proves the SHA belongs to that organization's repository. `StatusHandler` then fails to re-check that the commit it is about to mutate actually belongs to a stack under the authenticated `repository_owner`/`repository_name`. This is exactly the guard that exists in `PushHandler`/`CheckSuiteHandler` (via `stacks`) but is missing here.

### Impact Explanation
An attacker who owns/administers any repository connected to Shipit (their own account, a fork, or any org where they can register a status context) can fire a genuine, correctly-signed `status` webhook (`context: ci/build`, `state: failure`, arbitrary `sha`) for a SHA that also exists as a `Commit` in a completely unrelated victim stack (trivial to arrange when repos share history via forks, or when the victim commit's SHA is otherwise known/guessable-length but full 40-char SHAs are effectively unguessable — the realistic vector is shared fork history). This is a payload from one repository mutating another stack's `Commit`/`Status` record — matching the stated Critical category "a payload for one repository mutating another's stack, commit, task or team." The blast radius is cross-tenant: any stack in the Shipit instance whose commit history overlaps with an attacker-controlled repo's history is affected, and the write can flip `deployable?`/`blocked?`, thereby blocking legitimate deploys or, given other conditions (e.g., stale/forged "success" states from the reverse direction), potentially unblocking deploys that should have been held. The action is repeatable per SHA per request.

### Likelihood Explanation
Preconditions: the attacker needs (a) a repository whose organization has the Shipit-configured `webhook_secret` (i.e., an org they can push to / whose signature the attacker can produce — typically their own fork/org, which is exactly the "unprivileged attacker" capability listed: "emit webhooks from a repository they own"), and (b) a target SHA that also exists as a `Commit` row in the victim stack. Shared-history forks make (b) trivial and deterministic (ancestor commits are identical SHAs across fork and upstream, and both may be tracked as separate Shipit stacks). No Shipit session, API token, or `Shipit.github_teams` membership is required — only the ability to send a validly-signed webhook from an owned/forked repository, which is within the defined unprivileged attacker capability set. This is fully reproducible with a single HTTP POST per SHA/target.

### Recommendation
Scope `StatusHandler#process` the same way as `PushHandler`/`CheckSuiteHandler`: restrict the commit lookup to commits belonging to `stacks` derived from the webhook's authenticated `repository_name`, e.g. `stacks.each { |stack| stack.commits.where(sha: params.sha).each { |c| c.create_status_from_github!(params) } }`, rather than an unscoped `Commit.where(sha: params.sha)`.

### Proof of Concept
Minitest plan (no live GitHub calls; mirrors patterns already used in `test/controllers/webhooks_controller_test.rb` and `test/models/shipit/webhooks/handlers/*`):

1. Fixtures: create two stacks in different "organizations" — `victim_stack` (repository `victim-org/app`) and `attacker_stack` (repository `attacker-org/app-fork`), each with its own `Commit` row sharing the identical `sha` value (e.g. `"deadbeef" * 5`), representing shared fork ancestry. Ensure `victim_stack` requires `ci/build` (set via `cached_deploy_spec` `ci.require: ['ci/build']` or similar) and currently has no `failure` status (i.e., `victim_commit.deployable?` is `true`/state is not `failure` before the test — assert this as the "before" side of the equality).
2. Assert the binding before the exploit: `assert_not_equal victim_stack.id, attacker_stack.id` and `assert victim_commit.deployable?` (or whatever pre-state represents "clean").
3. Stub/allow `verify_signature` (as existing tests do via `GithubHook.any_instance.stubs(:verify_signature).returns(true)` or `Shipit.github(...).stubs(:verify_webhook_signature).returns(true)`), simulating a validly-signed webhook from `attacker-org`.
4. POST to `/webhooks` with `X-Github-Event: status` and body `{ sha: shared_sha, state: 'failure', context: 'ci/build', repository: { full_name: 'attacker-org/app-fork', owner: { login: 'attacker-org' } } }`.
5. Assert the equality is now broken: `assert_equal 'failure', victim_commit.reload.state` and `refute victim_commit.deployable?`, even though the webhook's `repository.full_name` was `attacker-org/app-fork`, not the victim's repository — proving a payload authenticated for the attacker's repo mutated the victim stack's commit/deploy eligibility.
6. Optionally assert `attacker_commit.reload.state == 'failure'` too, confirming both stacks were mutated by a single request scoped to only one repository.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
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

**File:** test/dummy/db/schema.rb (L85-85)
```ruby
    t.index ["sha", "stack_id"], name: "index_commits_on_sha_and_stack_id", unique: true
```

**File:** app/jobs/shipit/github_sync_job.rb (L91-93)
```ruby
    def lookup_commit(sha)
      stack.commits.find_by(sha:)
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

**File:** app/models/shipit/commit.rb (L231-237)
```ruby
    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```
