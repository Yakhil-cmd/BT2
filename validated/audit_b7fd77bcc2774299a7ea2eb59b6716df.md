### Title
Cross-tenant unhandled exception in `StatusHandler#process` turns HTTP 500 vs 200 into an existence/state oracle for other tenants' commits - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` iterates `Commit.where(sha: params.sha)` with no scoping to the repository that sent the webhook, and any exception raised while creating a `Status` for one matched commit aborts the `.each` loop and propagates unhandled through `WebhooksController#create`, producing an HTTP 500 instead of the normal 200. Because the query matches commits by `sha` alone across all stacks/tenants, and because per-record processing inside `Commit#add_status` depends on the *target stack's own state* (e.g. `deployed?` calling `stack.last_deployed_commit.id`), the resulting status code can depend on data belonging to a stack the sender does not own.

### Finding Description
The binding under test: response_status_to_sender == f(sender's own repository state) only. This is broken because the query and the loop are not scoped to the sender's repository.

- `StatusHandler#process` matches on raw `sha` with no stack/repository filter: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`. [1](#0-0) 
- `WebhooksController#create` invokes the handler with no exception handling: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` then `head(:ok)`. [2](#0-1) 
- `Commit#create_status_from_github!` → `add_status` calls `deployed?`, which dereferences `stack.last_deployed_commit.id`; if that stack (which may belong to an entirely different tenant sharing the same commit sha, e.g. a fork of the same upstream repo) has no deployed commit yet, `last_deployed_commit` returns `nil` and `.id` raises `NoMethodError` for *that* commit's processing, independent of the sender's own commit/state. [3](#0-2) [4](#0-3) 

Attack flow: the attacker owns/controls a GitHub repository that is legitimately onboarded to Shipit (satisfying `verify_signature`, which only checks that the payload was signed by GitHub for `repository_owner`, i.e. the attacker's own org). Because git commits are content-addressed, a commit shared between the attacker's fork and a victim tenant's repository (e.g. a shared open-source ancestor commit) has an identical `sha` in both. The attacker sets a GitHub commit status on that shared commit in their own repo (using ordinary, unprivileged status-creation rights on their own repository/CI), causing GitHub to deliver a validly-signed `status` webhook to Shipit. `Commit.where(sha:)` then matches *both* the attacker's own commit row and the victim tenant's commit row with the same sha, and `.each` processes them in id order. If the victim stack happens to be in a state (e.g., "no deploy has ever completed on this stack") that makes `add_status` raise, the loop aborts and the whole request either short-circuits before or after the attacker's own commit is processed, yielding HTTP 500 instead of 200 - purely as a function of the victim tenant's internal state, not the attacker's own repository.

None of the existing guards prevent this: `verify_signature` only authenticates that the payload came from GitHub for the attacker's own org, it says nothing about which `Commit` rows get touched; the `ExplicitParameters` schema on `StatusHandler` only validates presence/type of `sha`/`state`, not ownership; there is no `stacks`/repository scoping in the query at all, and no `rescue` around `handler.call` in the controller.

### Impact Explanation
The attacker (unauthenticated w.r.t. any other tenant) can learn, per request, one bit of internal state about a stack they do not own and cannot otherwise query: whether the response is 200 (processing succeeded for all matching commits, including the other tenant's) or 500 (processing raised while touching some other tenant's commit). Combined with the unscoped `sha` match, this also means the webhook write path itself (`Status.find_or_create_by!`) is executed against records belonging to other tenants' commits without any authorization check tied to the sender's repository - the oracle is a side effect of a broader missing-scoping defect. This matches "High: unauthenticated read of stack state," since it discloses derived state (e.g., deploy history existence) of stacks belonging to other repositories/tenants. It is repeatable against any sha shared across tenants (most practically: forks/mirrors of the same upstream project, a common Shipit review-stack pattern).

### Likelihood Explanation
Exploitation requires: (1) the attacker's repository being an already-onboarded Shipit tenant able to produce genuinely GitHub-signed webhooks (satisfies `verify_signature`); (2) a commit sha that coincidentally/deliberately matches a commit tracked under a different tenant's stack, which is realistic for forked/mirrored repositories sharing history; (3) the victim stack being in a state that causes a raise during `add_status` (e.g. zero deploys yet, a very common condition for young or low-traffic stacks). Given these are not exotic preconditions in multi-tenant Shipit deployments with review-stack/fork patterns, the attack is feasible and repeatable, though it depends on which particular shas overlap and which stack-specific error conditions exist - this makes it a somewhat noisy, best-effort oracle rather than a deterministic one.

### Recommendation
Scope `StatusHandler#process` to only the commits belonging to the sending repository's stacks (e.g. `stacks.commits.where(sha: params.sha)` using the same `Repository.from_github_repo_name` lookup already used by `Handler#stacks`), and wrap each per-commit `create_status_from_github!` call in its own `rescue` so a failure for one matched commit does not abort processing of, or leak information about, unrelated commits/stacks. Additionally, `WebhooksController#create` should not allow unhandled model/validation exceptions from handlers to propagate as differentiated HTTP status codes; failures should be logged and a generic `200`/`422` returned uniformly.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb (conceptual)
test "raising while processing one tenant's commit prevents processing of another tenant's commit with the same sha and surfaces as an unhandled exception" do
  shared_sha = "deadbeef" * 5

  victim_stack  = shipit_stacks(:shipit)                     # tenant B, e.g. no deploys yet
  attacker_stack = create_stack(repository: "attacker/fork") # tenant A, attacker-owned

  victim_commit   = victim_stack.commits.create!(sha: shared_sha, message: "shared ancestor")
  attacker_commit = attacker_stack.commits.create!(sha: shared_sha, message: "shared ancestor")

  # Force the victim stack into the state that makes `deployed?` raise:
  victim_stack.stubs(:last_deployed_commit).returns(nil)

  params = ExplicitParameters::Parameters.define { }.parse!(
    { "sha" => shared_sha, "state" => "success", "context" => "ci" }
  )

  assert_raises(NoMethodError) do
    Shipit::Webhooks::Handlers::StatusHandler.new(
      { "sha" => shared_sha, "state" => "success", "context" => "ci" }
    ).process
  end

  # Binding check: attacker's own repository state alone would have produced success (200),
  # but the response is instead determined by victim_stack's unrelated internal state.
  assert_not attacker_commit.reload.statuses.exists?, "attacker's own commit was never reached because the loop aborted on the victim's commit first"
end
```
This demonstrates that a per-tenant condition unrelated to the sender's own repository (`victim_stack.last_deployed_commit == nil`) changes the outcome (raise vs. no raise) of processing a webhook whose `sha` is shared across tenants, which via `WebhooksController#create`'s lack of rescue would manifest to the unauthenticated sender as HTTP 500 instead of 200 - violating the stated binding.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/models/shipit/commit.rb (L308-310)
```ruby
    def deployed?
      stack.last_deployed_commit.id >= id
    end
```

**File:** app/models/shipit/commit.rb (L365-378)
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

```
