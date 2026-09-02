### Title
`StatusHandler#process` resolves commits by SHA with no repository/stack scoping, letting a status webhook from one repo flip `ignore_ci` on an unrelated stack - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits with a completely global `Commit.where(sha: params.sha)` query, unlike every other webhook handler in this engine, which resolves records through the `Handler#stacks` helper that scopes to `Repository.from_github_repo_name(repository_name)`. Any commit row anywhere in the database that shares the incoming SHA gets a `Status` created via `commit.create_status_from_github!`, which fires `Status#enable_ci_on_stack` (`app/models/shipit/status.rb:38-40`) and calls `commit.stack.enable_ci!` on whatever stack that commit belongs to - not the stack tied to the webhook's own `repository.full_name`.

### Finding Description
The broken binding, stated as an equality that should hold but doesn't:
`commit.stack.repository == Repository.from_github_repo_name(payload.dig('repository','full_name'))` (the repo that authenticated/authored the webhook) should equal the repository whose stack is mutated - but `StatusHandler#process` never checks this.

Code path:
- `WebhooksController#create` (`app/controllers/shipit/webhooks_controller.rb:10-15`) verifies the HMAC signature only against `repository_owner` (the GitHub organization, via `Shipit.github(organization: repository_owner)` at line 25), then dispatches the raw payload to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`.
- `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`):
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
This ignores `payload.dig('repository','full_name')` entirely - there is no filter by stack/repository, in contrast to the `Handler#stacks` helper (`app/models/shipit/webhooks/handlers/handler.rb:32-34`) that other handlers (`push_handler.rb`, `check_suite_handler.rb`, `membership_handler.rb`) use to scope to the authenticated repository's stacks.
- `Commit#create_status_from_github!` (`app/models/shipit/commit.rb:165-169`) creates a `Status` via `statuses.replicate_from_github!(stack_id, github_status)`.
- `Status#enable_ci_on_stack` (`app/models/shipit/status.rb:18,38-40`) runs `after_create` and unconditionally calls `commit.stack.enable_ci!`, flipping `ignore_ci` to `false` on whatever stack owns that `Commit` row, regardless of which repository's webhook triggered it.

Root cause: signature verification only authenticates the *organization* (via `repository_owner`), and even within that scope, `StatusHandler` performs a table-wide SHA lookup with no join/filter back to the repository that sent the webhook. Since Shipit routinely creates multiple `Stack` rows for the same GitHub repository (e.g., staging/production stacks, or multiple branches/environments) sharing overlapping commit history, and since the `commits` table has no unique constraint scoping SHA to a single stack, a real, validly-signed GitHub status event for one stack's commit can create a `Status` row - and thus flip `ignore_ci` - on every other `Stack` that independently ingested a `Commit` with the identical SHA (e.g., a merge base, a cherry-picked commit, or any commit shared across the org's repos/forks).

Existing guards (`verify_signature`, `drop_unhandled_event`, `ExplicitParameters` schema) validate only that the webhook is a legitimately signed status event for *some* repo in the org; none of them, nor `StatusHandler` itself, constrain the SHA lookup to the stack(s) belonging to the authenticated `repository.full_name`.

### Impact Explanation
An attacker with legitimate (unprivileged) push access to any repository within an org that has the Shipit GitHub App installed can cause GitHub to emit a validly-signed `status` webhook for a commit SHA under their control. If that SHA also exists as a `Commit` row for a different stack (a realistic occurrence given Shipit's common multi-stack-per-repo setups, forks, and shared history), the attacker silently mutates that victim stack's `ignore_ci` flag from `true` to `false` - a deployment-safety configuration explicitly set by the victim's operator - via `Stack#enable_ci!`. This directly changes `Commit#deployable?` semantics (`app/models/shipit/commit.rb:227-229`) for the victim stack, potentially enabling deploys/merges that CI gating was meant to block. This is a cross-tenant configuration mutation caused by an unauthenticated-for-that-repo payload, matching the Critical category ("a payload for one repository mutating another's stack").

### Likelihood Explanation
Preconditions: attacker needs push/webhook-triggering access to at least one repo in an org with the Shipit GitHub App installed (a low bar, and explicitly within the stated attacker capabilities), plus a SHA collision with a commit belonging to the victim stack. True cryptographic SHA collision is infeasible, but shared commit history across multiple stacks tracking the same repository (or forks/mirrors) is a normal, common Shipit deployment pattern, making a "collision" via legitimately shared commits realistic and repeatable at will by an attacker who identifies such overlapping stacks.

### Recommendation
Scope `StatusHandler#process` to the authenticated repository, mirroring the `Handler#stacks` pattern used elsewhere, e.g. resolve `stack_ids = stacks.pluck(:id)` from `Repository.from_github_repo_name(repository_name)` and constrain the commit lookup: `Commit.where(sha: params.sha, stack_id: stack_ids)`. Additionally, consider making `Status#enable_ci_on_stack` idempotent/no-op when `ignore_ci` was already explicitly set by an operator, or require an explicit operator action rather than an implicit side effect of any inbound status.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb (add case)
test "status webhook for one repo's commit flips ignore_ci on an unrelated victim stack sharing the same commit sha" do
  victim_stack = shipit_stacks(:shipit)
  victim_stack.update!(ignore_ci: true)

  attacker_stack = shipit_stacks(:cyclimse) # different repository/full_name fixture
  shared_sha = "a" * 40

  victim_commit = victim_stack.commits.create!(sha: shared_sha, message: "victim commit")
  attacker_commit = attacker_stack.commits.create!(sha: shared_sha, message: "attacker commit")

  payload = {
    'sha' => shared_sha,
    'state' => 'success',
    'context' => 'ci',
    'repository' => { 'full_name' => attacker_stack.repository.full_name,
                       'owner' => { 'login' => attacker_stack.repository.owner } }
  }

  assert victim_stack.reload.ignore_ci?, "precondition: victim ignore_ci should start true"

  Shipit::Webhooks::Handlers::StatusHandler.call(ExplicitParameters::Parameters.new(payload))

  assert_equal attacker_stack, attacker_commit.reload.stack
  refute victim_stack.reload.ignore_ci?, "victim stack's ignore_ci flipped to false due to attacker's webhook for a different repo/stack"
end
```
This asserts the equality that should hold (`victim_stack.ignore_ci` unaffected by `attacker_stack`'s webhook) fails after the call, demonstrating the cross-stack mutation. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** app/models/shipit/status.rb (L18-40)
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
    end

    private

    def enable_ci_on_stack
      commit.stack.enable_ci!
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

**File:** app/controllers/shipit/webhooks_controller.rb (L24-31)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

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
