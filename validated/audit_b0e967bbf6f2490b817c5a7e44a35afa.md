This confirms the vulnerability. `PushHandler` and `CheckSuiteHandler` both scope their queries through `stacks` (derived from `payload.dig('repository', 'full_name')` via `Handler#stacks`) before ever touching a `Commit`/`Stack` row, but `StatusHandler` does not.

### Title
Cross-repository commit status forgery via unscoped `Commit.where(sha:)` in `StatusHandler#process` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` mutates every `Shipit::Commit` row matching the webhook's `sha`, globally, without ever checking that the sha belongs to the repository whose signature was verified. Because signature verification in `WebhooksController#verify_signature` is scoped to the GitHub organization (`Shipit.github(organization: repository_owner)`) rather than to an individual repository, and `StatusHandler` never consults `payload.dig('repository', 'full_name')` (unlike `PushHandler`/`CheckSuiteHandler`, which both filter through `Handler#stacks`), a `status` event that is validly signed for one repository in an org can flip the CI status of a commit with a colliding/copied sha that belongs to a completely different `Stack`/`Repository`.

### Finding Description
Binding claimed as broken: `repository_that_signed(payload) == repository_owning(Commit matched by params.sha)`. This does not hold.

Trace:
- `Shipit::WebhooksController#create` (app/controllers/shipit/webhooks_controller.rb:10-15) parses `params` and dispatches to handlers for the event via `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`, with no repository check performed here either.
- `verify_signature` (app/controllers/shipit/webhooks_controller.rb:24-49) resolves `Shipit.github(organization: repository_owner)` and calls `github_app.verify_webhook_signature(signature, raw_post)`, using the HMAC computed with that org's `webhook_secret`. [1](#0-0)  This authenticates "some repo under this GitHub App/organization," not the specific repository named in `payload['repository']['full_name']`.
- `StatusHandler#process` then runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` with no `stacks` scoping and no `repository_name` check at all. [2](#0-1) 
- Contrast with `PushHandler#process`, which restricts to `stacks.not_archived.where(branch:)` where `stacks` is derived from `Repository.from_github_repo_name(repository_name)`. [3](#0-2) [4](#0-3) 
- Contrast with `CheckSuiteHandler#process`, which restricts to `stacks.where(branch: ...)` before touching `stack.commits`. [5](#0-4) 

`Commit#create_status_from_github!` unconditionally creates a `Status` row tied to `stack_id` and triggers side effects (`enable_ci_on_stack`, `schedule_continuous_delivery`, hooks) regardless of which repository the webhook actually came from. [6](#0-5) [7](#0-6) 

Exploit flow: attacker owns/controls Repository B, which is mounted in Shipit under the same GitHub App/organization as victim Stack A (Repository A). Attacker pushes an empty-tree (or otherwise sha-colliding/copied) commit to Repository B whose sha matches a sha already recorded as a `Shipit::Commit` for Stack A. GitHub emits a `status` webhook for Repository B, signed with the org's shared `webhook_secret`. `verify_signature` passes (it only checks that the signature matches *some* configured org secret, not that the sha/repo pairing is consistent). `StatusHandler#process` matches `Commit.where(sha: <the colliding sha>)`, which returns Stack A's commit row (owned by Repository A), and writes a forged `success`/`failure` status onto it — a write authorized only by Repository B's ability to emit signed events, not by any relationship to Repository A.

Existing guards do not stop this: `drop_unhandled_event` only checks the event type is registered; `ExplicitParameters` schema for `StatusHandler` only validates types of `sha`/`state`/etc., not repository ownership; there is no `force_github_authentication`, `User#authorized?`, or `stacks`/`repository_name` check anywhere in this handler.

### Impact Explanation
A payload authenticated for Repository B mutates a `Shipit::Commit`/`Status` belonging to Stack A/Repository A — this is exactly the "payload for one repository mutating another's stack, commit, task or team" Critical category. Because `Status#enable_ci_on_stack` and `schedule_continuous_delivery` fire on creation, a forged `success` status can unblock/trigger continuous deployment logic for a victim stack that the attacker has no legitimate relationship to, and a forged `failure`/`error` can block or corrupt CI signaling for a victim stack. This is repeatable against any commit sha that is shared between an attacker-reachable repository and any victim repository under the same GitHub App/org configuration in the Shipit instance (well-known shas, such as an initial empty-tree commit or a duplicated/copied commit, make sha collisions cheap and deliberate).

### Likelihood Explanation
Preconditions: the attacker must control (or be able to trigger events from) a repository that is mounted in the same Shipit instance and validated by the same GitHub App/organization's `webhook_secret` as the victim stack — this is the typical single-org Shipit deployment described in `docs/setup.md`. The attacker needs no Shipit credentials, no `ApiClient` token, and no knowledge of the `webhook_secret` itself; they only need push/webhook-triggering rights on their own repository under that org, and to craft a sha that already exists in another stack's `Commit` table (trivial for well-known empty-tree or duplicated public commits). This is low-cost and repeatable per request.

### Recommendation
In `StatusHandler#process`, scope the query to the repository the webhook actually names, mirroring `PushHandler`/`CheckSuiteHandler`: use `stacks` (backed by `Repository.from_github_repo_name(payload.dig('repository','full_name'))`) and only update commits belonging to those stacks, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` (or equivalent scoped query), instead of the unscoped `Commit.where(sha: params.sha)`.

### Proof of Concept
minitest plan (webhook integration test, no live GitHub):
1. Seed `Stack A` (Repository A, e.g. fixture `shipit_stacks(:shipit)`) with a `Shipit::Commit` fixture whose `sha` is a known/copied value (e.g. `"4b825dc642cb6eb9a060e54bf8d69288fbee4904"`, the canonical empty-tree sha).
2. Seed `Stack B` (Repository B, a different repository/org entry) with no commit sharing that sha, representing the attacker-controlled repo.
3. Stub/allow `GithubHook`/`verify_webhook_signature` to succeed (simulating a validly-signed webhook for Repository B, e.g. via `Shipit.github(organization: 'attacker-org-or-shared-org').stubs(:verify_webhook_signature).returns(true)`).
4. POST to `/webhooks` with `X-Github-Event: status`, and body `{ "sha" => "<colliding sha>", "state" => "success", "repository" => { "full_name" => "attacker/repo-b", "owner" => { "login" => "<org validated in step 3>" } } }`.
5. Assert `commit_a.reload.status.state` (the commit in Stack A) changed to `"success"`, and `commit_a.stack.enable_ci_on_stack`/`schedule_continuous_delivery` side effects fired — i.e., `assert_equal("success", commit_a.statuses.last.state)` and `assert_equal(stack_a.id, commit_a.statuses.last.stack_id)` — proving Repository B's authenticated payload mutated Stack A's data, with no relationship declared between Repository B and Stack A in the payload.

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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/status.rb (L18-33)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

    delegate :broadcast_update, to: :commit

    class << self
      def replicate_from_github!(stack_id, github_status)
        find_or_create_by!(
          stack_id:,
          state: github_status.state,
          description: github_status.description,
          target_url: github_status.target_url,
          context: github_status.context,
          created_at: github_status.created_at
        )
      end
```
