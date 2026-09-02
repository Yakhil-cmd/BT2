### Title
StatusHandler updates commit status/deployable_status for any stack sharing a commit sha, without scoping to the webhook's repository - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits purely `Commit.where(sha: params.sha)`, with no filter tying the result to the repository that sent the webhook. Every other handler (e.g. `PushHandler`) uses the `Handler#stacks` helper, which scopes results to `Repository.from_github_repo_name(repository_name)&.stacks` before acting. `StatusHandler` skips that scoping entirely, so a valid, signature-verified status webhook from repository B can update the status/commit records of a completely unrelated stack A if any commit row anywhere in the database happens to share that sha, driving `Commit#add_status` to emit `Hook.emit(:deployable_status, stack_A, ...)`.

### Finding Description
The binding that must hold is: for every `Commit` updated by a status webhook, `commit.stack.repository.full_name == payload.dig('repository', 'full_name')`. This is enforced in `PushHandler` via the `stacks` helper [1](#0-0) [2](#0-1) , but `StatusHandler#process` never calls `stacks` or checks `repository_name` at all: [3](#0-2) 

It simply does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`, which is a global, unscoped query across every stack in the Shipit instance. `WebhooksController#verify_signature` only proves that the webhook truly originated from GitHub for `repository_owner` (the org owning the *sending* repo); it says nothing about which stacks' commits the payload is entitled to affect [4](#0-3) . So a legitimately signed status event for repository B is dispatched straight into `StatusHandler`, which then mutates any commit row - regardless of stack/repository - whose `sha` column matches.

`Commit#create_status_from_github!` -> `add_status` then computes `previous_status`/`new_status` and, on a `simple_state` transition, emits `Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))` scoped to whatever stack owns that commit row [5](#0-4) . Because the sha lookup was never scoped to the sending repository, `stack` here can be victim stack A even though the webhook came from repo B.

Exploit flow: attacker controls (or has push access to) repository B, which has a genuine Shipit-configured webhook (signed with B's org secret - satisfying `verify_signature`). If any commit sha present in B's history also exists as a `Commit` row belonging to victim stack A (e.g. A's repository is a fork of B, shares merged history, was split from a monorepo, or otherwise contains an identical commit object - git shas are content-addressed but identical commits are routinely shared across forks/mirrors/subtree-split repos), the attacker pushes/creates a commit status for that sha in repo B. GitHub delivers a validly-signed `status` webhook for repo B to Shipit; `StatusHandler` ignores the sending repository and updates the status of stack A's commit, potentially flipping `deployable?` and firing `Hook.emit(:deployable_status, stack_A, ...)`, which is delivered to A's configured webhook subscribers (e.g. posting back to GitHub, or arbitrary third-party endpoint) as if A's own commit's CI state changed.

Existing guards do not stop this: `verify_signature` authenticates the sender org, not the affected stacks; `drop_unhandled_event` only checks the event type is registered; `ExplicitParameters` (`params do requires :sha ... end`) validates payload shape, not repository ownership; and there is no `Repository`/`stacks` scoping call anywhere in `StatusHandler`.

### Impact Explanation
A payload authenticated for repository B is used to mutate `Commit`/`Status` state belonging to stack A, and to trigger `Hook.emit(:deployable_status, stack_A, ...)` for A's registered webhooks/subscribers - this is exactly the "payload for one repository mutating another's stack, commit... " category, rated Critical. The blast radius is any stack in the Shipit instance whose commit history shares a sha with the attacker's repo (forks, mirrors, monorepo splits, cherry-picks are common in real deployments), and the attack is repeatable on demand by pushing new commits/statuses to the attacker-controlled repo.

### Likelihood Explanation
Preconditions: Shipit must have a legitimate webhook/App integration configured for the attacker's own repository B (a normal condition in multi-tenant/org-wide Shipit deployments where many repos under an org are onboarded), and stack A must have at least one commit row whose sha coincides with a commit the attacker can produce a `status` event for in repo B. Exact sha collision without shared history is computationally infeasible, but shared history (forks, template repos, monorepo extraction, cherry-picks) makes this realistically achievable for an unprivileged GitHub user who only needs push/webhook rights on their own repository - no Shipit credentials, session, or secrets are required.

### Recommendation
Scope `StatusHandler#process` to the sending repository, mirroring `PushHandler`: restrict the commit lookup to `stacks` (i.e. `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`) instead of an unscoped `Commit.where(sha: params.sha)`, so a status webhook can only affect commits that belong to stacks tied to the repository identified in `payload['repository']['full_name']`.

### Proof of Concept
Minitest plan (no live GitHub, Mocha for stubbing):
1. Create `stack_a` for repository `"victim/repo"` and `stack_b` for repository `"attacker/repo"` (both via `shipit(:stack)` fixtures/factories or `Stack.create!`).
2. Create `commit = Commit.create!(stack: stack_a, sha: "deadbeef" * 5, ...)` (a commit belonging to victim stack A).
3. Build a webhook payload with `repository: { full_name: "attacker/repo" }`, `sha: commit.sha`, `state: "success"`.
4. Assert the broken binding directly: before dispatch, `commit.stack.repository.full_name` (`"victim/repo"`) != payload's `repository.full_name` (`"attacker/repo"`).
5. Expect `Shipit::Hook.expects(:emit).with(:deployable_status, stack_a, has_entries(deployable_status: anything))` (Mocha) - i.e. assert that `stack_a`'s hook fires as a side effect of dispatching `Shipit::Webhooks::Handlers::StatusHandler.call(payload)` even though the payload's `repository.full_name` is `"attacker/repo"`.
6. Run `Shipit::Webhooks::Handlers::StatusHandler.call(payload)` and confirm the expectation is met, proving `commit.stack.repository.full_name != payload['repository']['full_name']` yet the status/hook mutation for stack A still occurred - demonstrating the missing repository-scoping check in `StatusHandler#process`.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end
```

**File:** app/models/shipit/commit.rb (L365-386)
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
