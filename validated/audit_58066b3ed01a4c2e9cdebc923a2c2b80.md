### Title
`StatusHandler#process` applies GitHub `status` webhooks to commits across *any* stack without scoping to the sending repository - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` looks up commits purely `by sha` (`Commit.where(sha: params.sha)`), unlike `CheckSuiteHandler` and other handlers which scope through `stacks` (which is derived from `payload.dig('repository','full_name')`). Because Shipit's `Commit#sha` is not scoped to a single repository/stack at the model level, a webhook signed for repository A can flip the CI status of a commit that belongs to a different stack B, as long as both stacks happen to contain a `Commit` row with the same sha (e.g. a fork sharing history with the upstream, or two Shipit stacks tracking the same repo/mirror).

### Finding Description
The binding that must hold for correctness is: `payload.dig('repository','full_name') == stack.repository.full_name` for every `Commit` whose status is mutated by a given webhook. Tracing the code:

- `WebhooksController#verify_signature` (app/controllers/shipit/webhooks_controller.rb:24-38) verifies the HMAC signature using `Shipit.github(organization: repository_owner)`, i.e. it authenticates that the payload was genuinely sent by GitHub *for the organization named in the payload*. It does **not** verify that the `repository.full_name` in the payload corresponds to the stack(s) that end up being mutated.
- `WebhooksController#create` (app/controllers/shipit/webhooks_controller.rb:10-15) dispatches the parsed JSON to every registered handler for the `status` event, calling `StatusHandler.call(params)`.
- `StatusHandler#process` (app/models/shipit/webhooks/handlers/status_handler.rb:20-24):
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
This queries `Commit` globally by `sha`, with **no join/filter on `stack.repository` or `payload['repository']['full_name']`**. Contrast with `CheckSuiteHandler#process` (app/models/shipit/webhooks/handlers/check_suite_handler.rb:13-17), which correctly scopes via `stacks.where(branch: ...)` — `stacks` being `Repository.from_github_repo_name(repository_name)&.stacks` (app/models/shipit/webhooks/handlers/handler.rb:32-38), i.e. explicitly bound to the sending repository.

Root cause: `Commit#sha` has no uniqueness/repository-scoping validation in `app/models/shipit/commit.rb`, and `StatusHandler` never consults `repository_name`/`stacks` before applying the status. `Commit#create_status_from_github!` → `Status.replicate_from_github!` (app/models/shipit/commit.rb:165-169) writes a `Status` record with `state: 'success'` regardless of which repository actually produced it, feeding directly into `Commit#deployable?` (app/models/shipit/commit.rb:227-229: `!locked? && (stack.ignore_ci? || (success? && !blocked?))`), then `Stack#next_commit_to_deploy` (app/models/shipit/stack.rb:235-243) and `Stack#trigger_continuous_delivery` (app/models/shipit/stack.rb:210-229), which calls `trigger_deploy(commit, Shipit.user, ...)`.

Exploit flow: attacker needs a `Commit` row to exist in the victim stack with a sha that also exists as a commit in a repository the attacker controls (e.g., a fork of the victim's repo before divergence, or another Shipit-tracked mirror the attacker owns/administers). The attacker pushes/generates a genuine GitHub `status` event from their own controlled repository for that shared sha with `state: success`, signed with their own org's legitimate webhook secret (which passes `verify_signature` because the check only validates the org named in *that* payload, not that the org matches every stack whose commits get touched). `StatusHandler` then updates the `Status` for **every** `Commit` row across the installation sharing that sha — including the victim stack's commit — flipping it to `success?` true, making it `deployable?`, and enabling `trigger_continuous_delivery`/`ContinuousDeliveryJob` to deploy it via `Shipit.user`.

Existing guards do not stop this: `verify_signature` only authenticates the org of the *payload's own* repository, not a match against the affected stacks' repositories; `drop_unhandled_event` and the `ExplicitParameters` schema only validate the shape of `sha`/`state`, not repository binding; there is no `Repository`/`stack` scoping inside `StatusHandler#process` itself.

### Impact Explanation
A cross-repository payload can flip a victim stack's `Commit#success?` to true without the victim repository's own CI ever reporting success, enabling an unauthorized continuous deployment (`Deploy` record created, task enqueued, potentially run against production infrastructure with `Shipit.user`). This matches the "Critical" category: "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy." The blast radius is bounded by whether a matching `sha` exists across repositories/stacks (this requires shared git history, e.g. forks/mirrors that haven't diverged at the relevant commit, or an attacker able to engineer identical commit content/metadata to produce a sha collision with a target commit) — it is not a universal cross-tenant primitive against arbitrary unrelated stacks, but is real and repeatable wherever such sha overlap exists (a common scenario for forks tracked as separate Shipit stacks, or mirrored repositories).

### Likelihood Explanation
Preconditions: victim stack must have `continuous_deployment: true`, a `cached_deploy_spec`, be unlocked, have no active task, and — critically — must contain a `Commit` row whose `sha` coincides with a commit the attacker's own repository/org can legitimately emit a signed `status` webhook for (fork-of-same-history scenario is the realistic vector). The attacker's cost is low (own a GitHub repo/fork, run CI, or directly POST a webhook if they can get GitHub to sign it for their org — no Shipit secrets required). This is fully repeatable per matching sha and does not require any Shipit-side credentials, matching the described unprivileged attacker capabilities.

### Recommendation
Scope `StatusHandler#process` (and any other sha-only lookups) to the sending repository, mirroring `CheckSuiteHandler`:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
using the inherited `stacks`/`repository_name` helper (`Repository.from_github_repo_name(payload.dig('repository','full_name'))&.stacks`) so that only commits belonging to stacks whose repository matches the webhook's `repository.full_name` are updated.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb` or similar):
```ruby
test "status webhook from repository A does not affect commit sharing a sha in repository B's stack" do
  victim_stack = shipit_stacks(:shipit) # repository.full_name == "shopify/shipit-engine"
  victim_commit = victim_stack.commits.create!(sha: "deadbeef" * 5, ...) # no status yet
  refute_predicate victim_commit, :deployable?

  attacker_payload = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'repository' => { 'full_name' => 'attacker/other-repo' }
  }

  assert_no_difference -> { victim_commit.statuses.count } do
    Shipit::Webhooks::Handlers::StatusHandler.call(attacker_payload)
  end

  refute_predicate victim_commit.reload, :deployable?
  assert_no_difference -> { Deploy.count } do
    victim_stack.trigger_continuous_delivery
  end
end
```
Before the fix, `Commit.where(sha: params.sha)` matches `victim_commit` regardless of `attacker_payload['repository']`, the status is created, `deployable?` becomes true, and `trigger_continuous_delivery` produces a `Deploy` — demonstrating `Deploy.count` incrementing on the victim stack from a cross-repository webhook alone.