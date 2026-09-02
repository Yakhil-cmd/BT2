### Title
Cross-tenant Status forgery via SHA collision - StatusHandler#process (`app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits solely by `Commit.where(sha: params.sha)`, without any scoping to the repository/organization that authenticated the webhook. Because `WebhooksController#verify_signature` only proves that the payload was signed by *some* organization named in `repository.owner.login`, an attacker who owns Org B can push/replay a `status` event whose `sha` collides with a commit belonging to Org A's stack, and the resulting `Status` row and continuous-deployment trigger land on Org A's stack.

### Finding Description
The broken binding, stated explicitly: `organization_that_signed_the_payload (Org B, verified via Shipit.github(organization: repository.owner.login))` == `organization_owning_the_Stack/Commit_that_gets_written (Org A, selected via Commit.where(sha: params.sha))`. Tracing the code shows this equality is never enforced.

- `WebhooksController#verify_signature` derives `repository_owner` from the attacker-controlled JSON body (`params.dig('repository','owner','login')`) and calls `Shipit.github(organization: repository_owner)` to verify the HMAC signature [1](#0-0) . This only proves the payload was signed with Org B's own `webhook_secret` — it says nothing about which `Stack`/`Commit` rows in the Shipit database the payload is allowed to affect.
- `WebhooksController#create` then dispatches to `Shipit::Webhooks.for_event('status')` and calls `handler.call(params)` with the raw parsed JSON [2](#0-1) .
- `StatusHandler#process` resolves target commits purely by `sha`, with no filtering by `repository_name`/`stacks` (the base `Handler` class defines `stacks`/`repository_name` helpers scoped to the payload's repository, but `StatusHandler` never calls them) [3](#0-2) [4](#0-3) .
- `Commit#create_status_from_github!` writes a `Status` scoped to `stack_id` (the commit's own stack, i.e. Org A's stack) via `statuses.replicate_from_github!(stack_id, github_status)` [5](#0-4) , and `Status.replicate_from_github!` persists it under that `stack_id` [6](#0-5) .
- `Status#after_create` schedules `schedule_continuous_delivery` on the commit [7](#0-6) , which can flip `Commit#deployable?` and trigger `Stack#trigger_continuous_delivery` for Org A's stack — a stack the attacker never authenticated against.

Attacker's exact request: attacker (owner of Org B, which Shipit also tracks) crafts a commit whose SHA matches one already recorded under Org A's stack (shared ancestor commit, or a reproduced rebase with identical tree/parents/timestamps), then either lets GitHub emit the `status` event for repo B, or POSTs directly to `/webhooks` with header `X-Github-Event: status` and body `{"sha": "<shared sha>", "state": "success", "context": "ci", "branches": [...], "repository": {"full_name": "orgB/repoB", "owner": {"login": "OrgB"}}}`, signed with Org B's own `webhook_secret` (which the attacker legitimately possesses as the owner of Org B). `verify_signature` passes because Org B's secret is valid for Org B. `StatusHandler#process` then matches Org A's `Commit` row purely by `sha` and writes a `success` status under Org A's `stack_id`, with no cross-check that Org B is authorized for Org A's stack.

No existing guard blocks this: `verify_signature` validates only the signer, not the target stack; `drop_unhandled_event` only checks event type; the `ExplicitParameters` schema for `StatusHandler` (`sha`, `state`, `description`, `target_url`, `context`, `created_at`, `branches`) never includes/validates `repository.full_name` against the resolved commit's stack.

### Impact Explanation
An attacker who fully controls an unrelated, legitimately-tracked repository/organization (Org B) can inject a forged `success` (or any state) CI status onto a commit belonging to a different tenant's stack (Org A), by engineering a SHA collision or reusing a shared-ancestor commit SHA. If Org A's stack has `continuous_deployment: true` and no other blocking status, this results in an unauthorized `Deploy` being triggered for Org A — a cross-tenant write and unauthorized deploy trigger, matching the Critical category "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy." This is repeatable against any Org A stack/commit whose SHA the attacker can reproduce or that happens to be shared (e.g., common base commits in monorepo forks, vendored history, or squash/rebase reproducing identical trees).

### Likelihood Explanation
Preconditions: Shipit must track both organizations' stacks (a common multi-tenant Shipit deployment); a `Commit` row with a matching `sha` must already exist under Org A's stack (naturally true for shared history/forks/rebases, not requiring a true SHA-1 collision); Org A's stack must have `continuous_deployment: true` with no other blocker. The attacker only needs ownership of their own tracked Org B repo (or the ability to POST to `/webhooks` directly, which requires no secret since Org B's own secret is used) — no Shipit credentials, no GitHub App key, no cross-org secret. Reproducing an identical SHA across repos is realistic for shared git history (forked/mirrored repos, cherry-picked/rebase-preserved commits), making this feasible without needing an actual SHA-1 collision.

### Recommendation
Scope `StatusHandler#process` (and other handlers relying on raw `sha` lookups) to commits belonging to stacks resolved from the authenticated payload's repository, e.g. restrict the lookup to `stacks.flat_map(&:commits).where(sha: params.sha)` or equivalently `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`, using the `Handler#stacks`/`repository_name` helpers already defined on the base class, instead of a global unscoped `Commit.where(sha: ...)`.

### Proof of Concept
Minitest (`ActionDispatch::IntegrationTest` or `ActionController::TestCase`) plan:
1. Create `stack_a` (Org A) and `stack_b` (Org B), both `continuous_deployment: true`.
2. Create `commit_a` under `stack_a` with `sha: "deadbeef"` and no statuses (so it is currently not deployable).
3. Stub `GithubHook#verify_signature` (or `Shipit.github(organization: 'OrgB').verify_webhook_signature`) to return `true`, simulating a payload legitimately signed by Org B only.
4. POST `/webhooks` with `X-Github-Event: status` and body `{"sha": "deadbeef", "state": "success", "context": "ci", "branches": [{"name": stack_b.branch}], "repository": {"full_name": "orgB/repoB", "owner": {"login": "OrgB"}}}`.
5. Assert: before request, `commit_a.statuses.count == 0` and `stack_a.deploys.count == N`; after request, `commit_a.reload.statuses.count == 1` with `state == 'success'` and `commit_a.statuses.first.stack_id == stack_a.id`, and (with `ContinuousDeliveryJob` run inline or `assert_enqueued_with`) `stack_a.deploys.count == N + 1` — demonstrating that a payload authenticated only for Org B wrote a `Status` and triggered a deploy for Org A's stack, proving the equality `signing_org (OrgB) == owning_org (OrgA)` is false yet the write succeeded.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```

**File:** app/models/shipit/status.rb (L24-33)
```ruby
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
