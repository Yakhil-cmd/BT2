### Title
Cross-tenant Status forgery via unscoped `StatusHandler#process` — (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits globally by `sha` across **all** stacks/repositories and writes a `Status` on every match, without ever checking that the payload's `repository.full_name` matches the repository owning the matched commit's stack. By contrast, `CheckSuiteHandler` (and the shared `Handler#stacks` helper) explicitly scope all reads/writes to the repository named in the payload, so the same class of forgery fails for `check_suite`/`check_run` events.

### Finding Description
The broken binding, stated as an equality that should hold but doesn't:
`params.dig('repository','full_name')` (the attacker-controlled payload's repo) == `commit.stack.repository.full_name` (the repo actually mutated) — **false** for `StatusHandler`.

Code path:
- `WebhooksController#create` dispatches on the `X-Github-Event` header only, then calls `handler.call(params)` for every registered handler of that event type [1](#0-0) . Signature verification in `verify_signature` uses `Shipit.github(organization: repository_owner)`, i.e. it only proves the payload was signed by *some* GitHub App installation for the organization named in the payload — it says nothing about which repository's data may be mutated [2](#0-1) .
- `StatusHandler#process` does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
```
This is a global, unscoped `Commit` lookup by `sha` alone — no reference to `payload['repository']` or the `Handler#stacks` helper at all [3](#0-2) .
- `Commit#create_status_from_github!` then writes a `Status` scoped to `stack_id` — the **commit's own stack**, not any stack derived from the incoming payload [4](#0-3) .
- Compare this to `CheckSuiteHandler#process`, which uses the base `Handler#stacks` helper — `Repository.from_github_repo_name(repository_name)&.stacks`, where `repository_name` is `payload.dig('repository', 'full_name')` — to scope the lookup strictly to stacks belonging to the payload's own repository before touching any commit [5](#0-4) [6](#0-5) . `PushHandler` follows the same scoped pattern via `stacks.not_archived.where(branch:)` [7](#0-6) .

Attacker's exact request: any unprivileged GitHub user who owns/controls a repository that is tracked by *some* Shipit stack (their own) can cause a `status` webhook to be delivered for a commit sha that happens to also exist as a `Commit` record belonging to an unrelated stack/repository (e.g., shared history from a common upstream, cherry-picked/rebased commits, or a sha that a victim stack already ingested via its own sync). Because `StatusHandler` never checks `payload['repository']` against the matched commit's stack, the forged status is written onto the victim's commit/stack, potentially flipping `deployable?`, unblocking CI-gated deploys (`stack.ignore_ci? || (success? && !blocked?)`), and triggering `ProcessMergeRequestsJob`/deploy-status webhooks for a repository the attacker never authenticated against [8](#0-7) .

Existing guards do not stop this: `verify_signature` only validates that the payload is a genuine webhook for *an* organization the attacker's own installation belongs to — it does not bind the payload's repository field to the record being mutated [2](#0-1) ; `ExplicitParameters` schema on `StatusHandler` only validates types/presence of `sha`/`state`, not repository ownership [9](#0-8) .

### Impact Explanation
A single forged `status` webhook write mutates a `Status` (and via `Commit#add_status`/hooks, potentially triggers `deployable_status`/`commit_status` hook emissions and `ProcessMergeRequestsJob`) for a `Commit` belonging to a stack/repository the attacker does not control, as long as a matching `sha` exists in that victim stack. This is a payload for one repository mutating another's commit/stack data — squarely in the Critical category defined by the rules. It is repeatable against any stack whose commits share a sha with the attacker-controlled repo (forks, shared submodules/vendored history, or any coincidental sha collision from a shared merge base).

### Likelihood Explanation
Preconditions: the attacker needs a repository already tracked by a Shipit stack under the same GitHub organization/App installation (so `verify_signature` passes), and a `sha` shared with a target stack's commit history — realistic for forked/shared repos, monorepo splits, or org-wide shared history. No Shipit session, API token, or GitHub App secret is required. This matches the described attacker capability (owns a repo, can emit webhooks) exactly.

### Recommendation
Scope `StatusHandler#process` the same way `CheckSuiteHandler`/`PushHandler` do: restrict the `Commit` lookup to stacks belonging to `Repository.from_github_repo_name(payload.dig('repository','full_name'))` (i.e., use `stacks.joins(:commits).merge(Commit.where(sha: params.sha))` or equivalent) before calling `create_status_from_github!`, rather than a global `Commit.where(sha:)` scan.

### Proof of Concept
minitest plan (table-driven, no live GitHub):
1. Fixtures: `stack_a` (repo `attacker/repo`) and `stack_b` (repo `victim/repo`), each with a `Commit` sharing the identical `sha` "deadbeef...".
2. Send a `status` event with `X-Github-Event: status`, payload `repository.full_name = "attacker/repo"`, `sha` = shared sha, `state: "success"`.
   - Assert: `stack_b`'s commit now has a `Status` record from this payload (`commit_b.statuses.last.state == "success"`) — proving cross-tenant mutation succeeded despite `payload['repository'] != stack_b.repository`.
3. Send a `check_suite` event with the same forged `repository.full_name = "attacker/repo"` and `check_suite.head_sha` = shared sha.
   - Assert: no `RefreshCheckRunsJob`/`CheckRun` mutation occurs for `stack_b`'s commit, because `CheckSuiteHandler` scopes via `stacks.where(branch: ...)` restricted to `Repository.from_github_repo_name("attacker/repo").stacks`, which excludes `stack_b`.
4. This asymmetry (status mutates unrelated stack; check_suite does not) isolates `StatusHandler` as the vulnerable path.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
