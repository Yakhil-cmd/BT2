### Title
Status webhook handler mutates commit statuses across all stacks sharing a SHA, regardless of repository - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` looks up commits by `Commit.where(sha: params.sha)` with no repository/stack scoping, unlike sibling handlers (e.g. `CheckSuiteHandler`) which use the `stacks` helper scoped to `Repository.from_github_repo_name(repository_name)`. Any attacker who controls a repository (and can therefore send a validly-signed `status` webhook for it) can update the status of a commit belonging to a different tenant's stack, as long as that other stack contains a `Commit` row with the same SHA.

### Finding Description
The claimed binding is: `number_of_repos_the_payload_names == number_of_stacks_mutated`, both expected to be `1`. Tracing the code shows this is false in general.

- `WebhooksController#verify_signature` verifies the HMAC signature against `Shipit.github(organization: repository_owner)`, where `repository_owner` is read from `params.dig('repository','owner','login')` [1](#0-0) [2](#0-1) . This only proves the payload was legitimately signed by GitHub for the attacker's own repository/organization — it says nothing about which `Stack`/`Commit` rows should be affected.
- The base `Handler` class provides a `stacks` helper that scopes lookups to `Repository.from_github_repo_name(repository_name)&.stacks` [3](#0-2) , and other handlers such as `CheckSuiteHandler` use `stacks.` to constrain their queries to the repository named in the payload.
- `StatusHandler#process`, however, bypasses that scoping entirely: `Commit.where(sha: params.sha).each do |commit| commit.create_status_from_github!(params) end` [4](#0-3) . This is a global, unscoped query across the entire `commits` table.
- `Commit#create_status_from_github!` calls `add_status` which appends a `Status`, triggers hooks (`Hook.emit(:commit_status, ...)`, `Hook.emit(:deployable_status, ...)`), and can call `stack.schedule_merges` if the new status is pending/success [5](#0-4) [6](#0-5) .

Attacker flow: attacker owns `attacker/repo`, installs/uses the Shipit-configured GitHub App on it (a legitimate, unprivileged action any repo owner can do), pushes/cherry-picks a commit with a SHA that also exists as a `Commit` row under a victim stack `S1` for `victim/repo` (e.g., both forked from the same shared upstream commit and both projects imported that commit into their Shipit stacks), then sends (or lets GitHub send) a `status` event for that SHA. The webhook is validly signed for `attacker/repo`'s org, passes `verify_signature`, and `StatusHandler` updates every `Commit` row with that SHA — including the one belonging to `S1` — regardless of which repository actually owns it.

None of the existing guards prevent this: `verify_signature` only authenticates the sender's own org, `drop_unhandled_event`/`check_if_ping` are irrelevant, and the `ExplicitParameters` schema only validates presence/type of `sha`/`state`/etc., not repository scope.

### Impact Explanation
A single validly-signed webhook from an attacker-controlled repository can write a fabricated CI status (e.g., forcing `success`) onto a commit belonging to another tenant's stack that happens to share the same SHA. Since `Commit#deployable?` depends on `status.success?`/blocking statuses, and `add_status` can trigger `stack.schedule_merges` and `Hook.emit(:deployable_status, ...)`, this can influence whether the victim stack's commit is considered deployable/mergeable — i.e., a payload for one repository mutating another's commit/stack state, matching the "Critical" impact category (cross-tenant record mutation not authenticated by the actual owning repository). The blast radius scales with however many stacks/tenants happen to contain a `Commit` row with the same SHA (shared upstream commits, cherry-picks, monorepo forks, etc.), which is unbounded by the payload's declared repository.

### Likelihood Explanation
Preconditions: the attacker must own/control a repository already registered with the same Shipit-configured GitHub App (attacker-controlled, low cost — creating a fork or repo and installing a public GitHub App is normal, unprivileged action), and a matching SHA must exist in another stack's `commits` table (realistic for shared open-source upstreams, forks, or cherry-picks — a common occurrence). No Shipit session, API token, or GitHub secret is needed. The attack is fully repeatable: every `status` event the attacker's repository/CI emits for that SHA is unscoped and will hit all matching commits again.

### Recommendation
Scope `StatusHandler#process` to the repository named in the payload, mirroring `CheckSuiteHandler`/other handlers: iterate `stacks.flat_map { |stack| stack.commits.where(sha: params.sha) }` (or `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`) instead of the unscoped `Commit.where(sha: params.sha)`.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`):
1. Create `repository_1 = shipit_repositories(:shipit)` style fixture for `victim/repo`, `stack_1` belonging to it, and `commit_1 = stack_1.commits.create!(sha: 'deadbeef...', ...)`.
2. Create a second `repository_2` for `attacker/repo`, `stack_2` belonging to it, and `commit_2 = stack_2.commits.create!(sha: 'deadbeef...', ...)` — same SHA, different stack/repository.
3. Build a `status` webhook payload naming only `attacker/repo` (`payload['repository']['full_name'] = 'attacker/repo'`) with `sha: 'deadbeef...'`, `state: 'success'`.
4. Call `Shipit::Webhooks::Handlers::StatusHandler.call(payload)` directly (bypassing signature verification, as this test targets the handler logic).
5. Assert: `commit_2.statuses.count` increased by 1 (expected, same repo) AND `commit_1.reload.statuses.count` also increased by 1 (the bug) — i.e., assert `commit_1.statuses.count == before_count + 1` even though `payload['repository']['full_name'] != stack_1.repository.full_name`, proving `number_of_repos_named == 1` while `number_of_stacks_mutated == 2`.

### Citations

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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
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
