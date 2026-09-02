This confirms the vulnerability. `PushHandler#process` and `CheckSuiteHandler#process` both correctly scope their queries through the `stacks` helper, which restricts matching to `Repository.from_github_repo_name(repository_name)&.stacks` — i.e., only stacks belonging to the repository that the webhook payload claims to be for [1](#0-0) , then filters further by branch/sha within that scope [2](#0-1) [3](#0-2) .

`StatusHandler#process`, by contrast, never calls `stacks` at all. It queries `Commit.where(sha: params.sha)` globally across the entire `commits` table, with no repository/stack scoping whatsoever, and calls `create_status_from_github!` on every matching commit regardless of which repository the commit's `stack` belongs to [4](#0-3) . That method calls `Commit#add_status`, which computes `payload = { commit:, stack:, status: }` from the matched commit's *own* `stack` (not the webhook's repository) and emits `Hook.emit(:deployable_status, stack, ...)` [5](#0-4) .

### Title
Cross-tenant status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` matches incoming GitHub `status` webhook events to commits purely by SHA, with no scoping to the repository that authenticated the webhook, unlike sibling handlers (`PushHandler`, `CheckSuiteHandler`) which correctly use the `stacks` helper scoped to `Repository.from_github_repo_name(repository_name)`. Since commit SHAs are content-addressed and identical across forks/mirrors of the same Git history, an attacker who owns any repository with a legitimately-configured Shipit webhook can send a real, correctly-signed `status` event referencing a SHA shared with a victim's tracked commit (e.g., via forking the victim's public repo), causing `Commit#add_status` to fire `Hook.emit(:deployable_status, victim_stack, ...)` with the victim's own `stack` object in the payload.

### Finding Description
The broken binding: `authorized_repo_of(webhook) == stack.repository_of(matched_commit)` — this does not hold in `StatusHandler`.

Path: `WebhooksController#create` dispatches based on `X-Github-Event` header after `verify_signature` checks the payload's `repository.owner.login` against `Shipit.github(organization: repository_owner)` [6](#0-5) . This only proves the request came from a GitHub App/org configured for *that organization* — it says nothing about which specific commit SHAs should be trusted for which stack. `StatusHandler#process` then does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github! }`, with zero use of `repository_name`/`stacks` [4](#0-3) . Any `Commit` row anywhere in the database with a matching `sha` — regardless of `stack_id`/`repository` — gets a status appended, and `add_status` fires `Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))` using that commit's real `stack` [7](#0-6) .

Exploit flow: attacker forks/mirrors the victim's public GitHub repo into their own org where they legitimately control a Shipit-tracked stack and a real, correctly-configured status webhook. Shared ancestor commits keep identical SHAs. Attacker triggers (or directly POSTs, since they control CI/webhook config for their own repo) a `status` webhook with `sha` = a SHA also present in the victim stack's `commits` table and `state` chosen to flip `simple_state`. `verify_signature` passes because the request is authentically signed for the attacker's own org. `StatusHandler` then updates the status for *every* commit row with that SHA across *all* stacks, including the victim's, and `Hook.emit(:deployable_status, victim_stack, ...)` fires for the victim's Slack/chatops hook with a payload that looks fully legitimate (real victim `stack`, real victim `commit`).

Existing guards do not stop this: `verify_signature` only authenticates the organization, not the SHA-to-repository binding; `drop_unhandled_event` and the `ExplicitParameters` schema only validate shape, not tenancy; and the `stacks` scoping helper exists in the base `Handler` class and is used correctly by `PushHandler`/`CheckSuiteHandler`, but `StatusHandler` simply omits it.

### Impact Explanation
An attacker who owns/controls any repository with a legitimately registered Shipit webhook (a low bar — this is normal, sanctioned tenant onboarding, not a privilege escalation) can inject `Status`/`deployable_status` events for other tenants' commits whenever SHAs coincide (trivially achievable by forking a public repo and using shared history commits). This causes: `Shipit::Status` records being written for a stack that never authenticated that data; `Hook.emit(:deployable_status, ...)` firing for the victim's registered webhooks (Slack/chatops/deploy-gating integrations) with attacker-controlled `state`/`description`/`context`; and `stack.schedule_merges` potentially being triggered for the victim stack (`if new_status.pending? || new_status.success?`), which can affect the victim's auto-merge/deploy pipeline. This is a genuine "payload for one repository mutating another's stack/commit" case, matching the Critical impact category (cross-repository trust violation feeding deploy/notify pipelines with attacker-controlled truth).

### Likelihood Explanation
Preconditions are low-cost and realistic: the attacker needs any repository with its own legitimately configured GitHub App/webhook secret pointing at Shipit (self-service, no special privilege), and a target victim stack that tracks commits sharing history/SHAs with the attacker's repo (trivial via forking a public open-source repo tracked by Shipit). No secrets, sessions, or GitHub org membership for the victim's org are required. The attack is repeatable at will against any commit SHA the attacker can reproduce, and against any number of victim stacks that happen to share that SHA (e.g., all forks/all stacks tracking the same upstream commit history).

### Recommendation
Scope `StatusHandler#process` through the same repository-bound `stacks` helper used elsewhere: restrict the commit lookup to `stacks.flat_map(&:commits).where(sha: params.sha)` (or equivalently `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`), ensuring a `status` webhook can only affect commits belonging to stacks under the repository that authenticated the webhook.

### Proof of Concept
Add a minitest to `test/models/shipit/webhooks/handlers/status_handler_test.rb` (or extend `commits_test.rb`):
1. Create two stacks/repositories, `victim_stack` (repo `victim/app`) and `attacker_stack` (repo `attacker/app`), each with a `Commit` row sharing the identical `sha` (simulating a forked shared-history commit).
2. Register a `deployable_status` hook (or stub `Shipit::Hook.emit`) on `victim_stack`.
3. Build a `status` webhook payload whose `repository.full_name` is `attacker/app` (so it resolves via `Repository.from_github_repo_name` to only `attacker_stack`), with `sha` equal to the shared SHA and a `state` that flips `simple_state`.
4. Invoke `Shipit::Webhooks::Handlers::StatusHandler.call(payload)` directly (bypassing the need for live GitHub, since only `verify_signature`, mocked, gates dispatch).
5. Assert: `Hook.emit` is invoked with `victim_stack` as the second argument (`assert_equal victim_stack, emitted_stack` fails today because it *is* emitted — proving the binding `authorized_repo(webhook) == stack.repository` is broken) even though the webhook only authenticated `attacker/app`.
6. After the fix, assert `victim_stack`'s commit `statuses` are unchanged and no `deployable_status` hook fires for `victim_stack`, only for `attacker_stack`.

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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
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

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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
```
