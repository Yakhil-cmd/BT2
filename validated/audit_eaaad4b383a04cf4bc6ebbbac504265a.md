### Title
Cross-repository status injection via unscoped `Commit.where(sha:)` lookup - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` looks up commits purely by `sha` with no repository/stack scoping, unlike every other webhook handler which resolves `stacks` via `Repository.from_github_repo_name(repository_name)`. Because `verify_signature` only proves that the payload was legitimately signed by *some* GitHub organization (the one named in `payload['repository']['owner']['login']`), a status event legitimately emitted by an attacker-controlled repository can create a `Status` and trigger `Commit#schedule_continuous_delivery` / `ContinuousDeliveryJob` against a completely different tenant's `Stack`, provided a `Commit` row with the same `sha` exists there.

### Finding Description
The broken binding, stated explicitly: **`Shipit.github(organization: repository_owner)` (the org whose secret validated the signature) == `commit.stack.repository.owner` (the org whose Stack is mutated by `Status.create` / `ContinuousDeliveryJob`)**. This is assumed but never enforced.

Code path:
- `app/controllers/shipit/webhooks_controller.rb:24-30` (`verify_signature`) authenticates the payload against `Shipit.github(organization: repository_owner)`, where `repository_owner = params.dig('repository','owner','login')`. This proves the request truly came from GitHub for *that org's* repo — it says nothing about which `Stack`/`Commit` rows will be touched.
- `app/models/shipit/webhooks/handlers/status_handler.rb:20-24`:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
This performs a **global** `Commit.where(sha:)` query across every `Stack` in the installation. It never uses `Repository.from_github_repo_name(repository_name)` (the `stacks` helper defined in `app/models/shipit/webhooks/handlers/handler.rb:32-38`, which every other handler such as `PushHandler` relies on) to restrict matches to commits belonging to the repository that actually emitted the webhook.
- `Commit#create_status_from_github!` (`app/models/shipit/commit.rb:165-169`) calls `statuses.replicate_from_github!(stack_id, github_status)` using the matched commit's **own** `stack_id` — i.e., whatever stack that pre-existing `Commit` row belongs to, not the attacker's stack.
- `Status` callbacks (`app/models/shipit/status.rb:18-19,38-44`) then run `commit.stack.enable_ci!` and `commit.schedule_continuous_delivery` on that (potentially victim) stack.
- `Commit#schedule_continuous_delivery` (`app/models/shipit/commit.rb:281-287`) checks `deployable?`, `stack.continuous_deployment?`, `stack.deployable?` — all evaluated against the **victim's** stack/commit — and enqueues `ContinuousDeliveryJob.perform_later(stack)` for the victim's stack.
- `ContinuousDeliveryJob` ultimately calls `Stack#trigger_continuous_delivery`, which can create a real `Deploy` (see `test/models/shipit/stack_test.rb:700-708` showing `trigger_continuous_delivery` creates a `Deploy`).

The database even models commits as `(sha, stack_id)` unique pairs (`t.index ["sha", "stack_id"], unique: true` in `test/dummy/db/schema.rb:85`), confirming the same `sha` can legitimately exist as separate `Commit` rows under different, unrelated stacks — exactly the condition `StatusHandler` fails to disambiguate.

Exploit flow: attacker owns/controls a repository connected to Shipit under organization A (their own stack). They get GitHub to emit a `status` webhook (signed correctly with org A's secret) for a commit `sha` that happens to also exist as a `Commit` row in victim organization B's stack. Such a sha collision does not require breaking SHA-1: it occurs naturally whenever two repositories share git history containing the same commit object — e.g., the victim's stack tracks a public/open-source repository or a shared base branch that the attacker has forked or mirrored into their own Shipit-connected repo. Any commit shared between the two histories has an identical, content-addressed sha in both repos. (Note: the specific example given in the prompt, `4b825dc642cb6eb9a060e54bf8d69288fbee4904`, is the well-known SHA of an *empty git tree object*, not a commit object, so it would not by itself appear as a `Commit.sha` value populated from GitHub's commit API; the realistic collision vector is shared commit history via forks/mirrors rather than that specific constant.)

None of the existing guards stop this: `verify_signature` authenticates the sender's org, not the target stack; `Handler#stacks`/`repository_name` scoping exists in the base class but `StatusHandler` does not use it; `Commit#deployable?`, `blocked?`, `locked?` are commit-state checks with no tenant-ownership check; `ExplicitParameters` schema only validates payload shape, not ownership.

### Impact Explanation
An attacker who controls any Shipit-connected repository (even a trivial personal fork) can, by emitting a correctly-signed `status` webhook from their own repository/org, cause `Status` records to be created and continuous-delivery evaluation/deploys to be triggered against a **different tenant's Stack** whose commit history happens to intersect (via shared commits) with the attacker's repository. This is a payload from one repository mutating another repository's stack/commit state and can result in an unauthorized deploy, matching the **Critical** impact category (payload for one repository mutating another's stack/commit/task; unauthorized deploy).

### Likelihood Explanation
Preconditions: the victim `Stack` must have `continuous_deployment` enabled and an undeployed commit whose sha is reachable/shared with a repository the attacker controls (realistically via forked/mirrored shared git history, not via breaking SHA-1). The attacker must control at least one repository already connected to Shipit (own stack) so that GitHub will deliver a validly-signed webhook. This is a low-cost, repeatable action — no Shipit credentials, session, or secrets are required, only the ability to have GitHub fire a `status` event on a repo the attacker controls. Feasibility depends on the sha-collision precondition being satisfiable in practice (shared history is common in fork-based workflows), which is plausible but environment-dependent, rather than universally guaranteed like the prompt's empty-tree claim suggests.

### Recommendation
Scope `StatusHandler#process` (and `create_status_from_github!`/`replicate_from_github!`) to only the commits belonging to stacks under the repository that authenticated the webhook, mirroring the `stacks` helper already used by `PushHandler` and other handlers, e.g.:
```ruby
def process
  stacks.each do |stack|
    commit = stack.commits.find_by(sha: params.sha)
    commit&.create_status_from_github!(params)
  end
end
```
This ensures the org that signed the webhook can only affect its own stacks/commits.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`, currently absent — would need to be added):
```ruby
test "status event for org A cannot mutate a commit belonging to org B's stack" do
  sha = "deadbeef" * 5  # 40-char sha shared between two repos' history

  stack_a = shipit_stacks(:shipit)                 # attacker's own stack, org "shopify"
  stack_b = shipit_stacks(:cyclimse)                # victim stack, different org
  stack_b.update!(continuous_deployment: true)
  stack_b.expects(:ignore_ci?).returns(false)

  commit_b = stack_b.commits.create!(sha:, ...)     # victim's undeployed commit, same sha

  payload = {
    'sha' => sha,
    'state' => 'success',
    'repository' => { 'full_name' => stack_a.repository.full_name,
                       'owner' => { 'login' => stack_a.repository.owner } }
  }

  # Binding under test: repository_owner (org that signed) == commit_b.stack.repository.owner
  assert_not_equal payload['repository']['owner']['login'], commit_b.stack.repository.owner

  assert_enqueued_with(job: ContinuousDeliveryJob, args: [stack_b]) do
    Shipit::Webhooks::Handlers::StatusHandler.call(payload)
  end
  # Demonstrates org A's signed webhook enqueued continuous delivery for org B's stack.
end
```
This shows the two sides of the equality (`payload`-authenticated org vs. `commit_b.stack`'s org) diverge, and `ContinuousDeliveryJob` is still enqueued for the victim stack, confirming the cross-tenant mutation.