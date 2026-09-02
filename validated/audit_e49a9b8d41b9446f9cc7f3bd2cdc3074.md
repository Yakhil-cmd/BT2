### Title
Cross-tenant status webhook replay fires `Hook.emit(:deployable_status, ...)` for an unrelated stack via unscoped `Commit.where(sha:)` lookup - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves the target `Commit` records purely by `sha`, with no constraint tying the lookup to the repository/organization that authenticated the webhook. Because git commit SHAs are content-addressed and are shared identically across forks and repositories with common history, an attacker who owns repository R2 (a fork of, or sharing history with, victim repository R1) can send a real, correctly-signed webhook for R2 and have it silently mutate and emit hooks for a `Commit` belonging to victim stack R1.

### Finding Description
The intended binding is: `stack_passed_to_Hook.emit == stack_named_by_authenticating_payload` (i.e., the stack that owns the repository/organization whose webhook secret validated the request). The actual code violates this.

- `WebhooksController#verify_signature` only checks that the raw payload was signed for `repository_owner` derived from the payload itself (`params.dig('repository','owner','login')`), i.e. R2: [1](#0-0) [2](#0-1) 
- `StatusHandler#process` then does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — this query is global across the entire `commits` table, not scoped to R2's repository or stack at all: [3](#0-2) 
- `Commit#create_status_from_github!` and `#add_status` then use `self.stack` / `stack_id` (the commit's own stack, which for a colliding R1 commit is R1's stack) to persist the status and to fire hooks: [4](#0-3) [5](#0-4) 

Root cause: SHA is not a tenant-scoped identifier. Two different `Stack`/`Repository` records can legitimately contain `Commit` rows with the identical `sha` value whenever their git histories overlap (most commonly: R2 is a fork of R1, or shares a common ancestor/cherry-picked commit). GitHub's webhook signature only proves the event originated from R2's installation/app config — it says nothing about which `Commit`/`Stack` rows in Shipit's database should be affected. The `StatusHandler` fails to re-derive the target stack from `params.dig('repository', 'full_name')` and cross check it against `commit.stack.repository`, so it processes every same-sha `Commit` row across all tenants.

Attack flow:
1. Attacker forks victim's repository R1 into their own R2 (or otherwise ensures a commit with an identical sha exists in both, e.g., by cherry-picking/rebasing so the tree+parent+author+committer+timestamp are bit-identical), reproducing SHA `abc123` in R1's stack's `commits` table (already created when Shipit ingested R1's push events) and R2's.
2. Attacker triggers (via GitHub) a `status` event on R2 for sha `abc123` with `state: success` — this is a completely legitimate GitHub webhook, correctly signed for R2's app/org.
3. `WebhooksController#verify_signature` passes (correctly verifies R2's own event).
4. `StatusHandler#process` runs `Commit.where(sha: 'abc123')`, which returns **both** R2's commit row and R1's commit row (different `stack_id`s, same `sha`).
5. For the R1 row, `create_status_from_github!` → `add_status` executes with `self.stack` == R1's stack, and if `previous_status.simple_state != new_status.simple_state`, `Hook.emit(:deployable_status, stack, ...)` fires with R1's stack object — even though only R2 authenticated anything.

No existing guard prevents this: `verify_signature` validates the org named in the payload (R2) but the handler never checks that the payload's `repository`/`organization` matches the `stack.repository` of the commits it mutates; `drop_unhandled_event` and the `ExplicitParameters` schema (`requires :sha`, `:state`, etc.) do not include or enforce any repository binding either: [6](#0-5) 

### Impact Explanation
An attacker fully controlling R2 (fork or shared-history repo) can cause writes (`Status` rows) and `Hook.emit(:commit_status, ...)`/`Hook.emit(:deployable_status, ...)` events to fire for R1's stack/commit, without R1 ever authenticating anything. Downstream consumers of Shipit's hooks (Slack notifications, CI gating integrations, continuous-delivery scheduling via `stack.schedule_merges`) treat this as legitimate status information from R1. Because `deployable?`/`schedule_continuous_delivery` depend on this status transition, this can also indirectly influence whether R1's commit becomes eligible for continuous deployment (`ContinuousDeliveryJob.perform_later(stack)` in `Commit#schedule_continuous_delivery`, gated on `deployable?`, which itself depends on the very statuses being forged): [7](#0-6) [8](#0-7) . This is a cross-tenant "payload for one repository mutating another's stack/commit" — matches the Critical impact category. It is fully repeatable against any pair of repos that share commit SHAs (forks are the common, low-cost case).

### Likelihood Explanation
Preconditions: R2 must contain (or be made to contain) a commit whose SHA matches one already ingested into an R1 stack's `commits` table. This is trivially achievable by forking a public/target repository (git forks preserve identical SHAs for shared history) — no secrets, no privileged role, and no TLS interception are required. The attacker only needs to be able to make GitHub emit a real `status` webhook for their own repo/fork (e.g., via a CI integration on their fork, or any service that posts commit statuses), which is squarely within an unprivileged GitHub user's capability. This is a low-cost, highly repeatable attack against any Shipit-tracked repository that has been forked.

### Recommendation
Scope the `StatusHandler` (and analogous `check_run`/other sha-keyed handlers) lookup by the repository named in the authenticated payload, not by bare SHA: join `Commit` to `Stack`/`Repository` and filter `where(stack: Stack.where(repository: Repository.from_github_repo_name(params.dig('repository','full_name'))))`, or otherwise verify `commit.stack.repository.full_name == params.dig('repository','full_name')` before calling `create_status_from_github!`, rejecting/skipping any matched `Commit` whose owning stack's repository differs from the authenticated payload's repository.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb (conceptual, minitest, no live GitHub)
test "status event for a shared sha only affects the authenticated repository's stack" do
  r1_stack = shipit_stacks(:shipit)
  r2_repository = Shipit::Repository.create!(owner: 'attacker', name: 'fork-of-r1')
  r2_stack = Shipit::Stack.create!(repository: r2_repository, environment: 'production')

  shared_sha = 'a' * 40
  r1_commit = r1_stack.commits.create!(sha: shared_sha, message: 'shared', author: shipit_users(:walrus))
  r2_commit = r2_stack.commits.create!(sha: shared_sha, message: 'shared', author: shipit_users(:walrus))

  payload = {
    sha: shared_sha,
    state: 'success',
    context: 'ci',
    repository: { full_name: r2_repository.full_name, owner: { login: 'attacker' } }
  }

  # binding under test, stated BEFORE tracing:
  # Hook.emit stack argument MUST equal r2_stack (the authenticating payload's repository's stack)
  Shipit::Hook.expects(:emit).with(:deployable_status, r2_stack, anything)
  Shipit::Hook.expects(:emit).with(:deployable_status, r1_stack, anything).never

  Shipit::Webhooks::Handlers::StatusHandler.new(delivery: SecureRandom.uuid).call(payload)
end
```
This test demonstrates that, as written, `StatusHandler#process`'s `Commit.where(sha: params.sha)` causes `Hook.emit(:deployable_status, r1_stack, ...)` to fire (violating the equality `stack_passed_to_Hook.emit == stack_of_authenticating_repository`), because both `r1_commit` and `r2_commit` share the sha and both get processed regardless of which repository authenticated the webhook.

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

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
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
