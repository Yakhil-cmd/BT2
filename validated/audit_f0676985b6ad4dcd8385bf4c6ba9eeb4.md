### Title
`StatusHandler` applies GitHub status webhooks to any commit sharing a SHA, regardless of repository, letting Repo B trigger `stack.schedule_merges` on tenant A's stack - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits by `Commit.where(sha: params.sha)` with **no repository/stack scoping**, then calls `commit.create_status_from_github!(params)`, which reaches `Commit#add_status` and, on a `pending`/`success` transition, calls `stack.schedule_merges` on `commit.stack` — the commit's own (real) stack, not the stack tied to the webhook payload's `repository` field. Because the webhook signature check (`WebhooksController#verify_signature`) only authenticates the *organization* of the payload's `repository.owner.login`, not the specific repository, any repo within a Shipit-integrated organization (or any fork sharing commit SHAs with the tracked repo) can emit a legitimately-signed `status` webhook for a SHA belonging to a different stack and force `stack.schedule_merges` on it.

### Finding Description
The claimed binding is: `stack.schedule_merges` should only run when `webhook.repository.full_name == commit.stack.repository.full_name` (i.e., the payload's authenticated repository equals the commit's real owning repository). Tracing the code shows this binding is **not enforced**:

- `WebhooksController#verify_signature` (app/controllers/shipit/webhooks_controller.rb:24-30) validates the HMAC signature using `Shipit.github(organization: repository_owner)` — scoped only to the **organization**, derived from `params.dig('repository','owner','login')`. It never checks that the specific `repository.full_name` in the payload is the one whose commit is about to be mutated.
- `StatusHandler#process` (app/models/shipit/webhooks/handlers/status_handler.rb:20-24):
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
This queries **all** `Commit` rows across the entire database matching the SHA — it never joins/filters by `stack_id` or `repository`, even though the base `Handler` class already exposes a repository-scoped `stacks` helper (`app/models/shipit/webhooks/handlers/handler.rb:32-34`) that other handlers (e.g. `CheckSuiteHandler`) correctly use to scope by `repository_name`. `StatusHandler` uniquely omits this scoping.
- `Commit#create_status_from_github!` → `add_status` (app/models/shipit/commit.rb:165-169, 366-386) operates on `self.stack` — the commit's real, originally-created stack — and calls `stack.schedule_merges if new_status.pending? || new_status.success?` (line 383).

**Exploit flow**: An attacker who owns/controls a repository B within the same GitHub organization Shipit is configured for (or a fork of the target repository A, which shares identical, content-addressed commit SHAs with A) sends a `status` webhook (self-triggered via GitHub, e.g. by setting a commit status on their own repo/fork) with `state: success` and a `sha` equal to a real SHA that exists as a `Commit` row belonging to tenant A's stack. GitHub signs this webhook validly (organization-level secret), so `verify_signature` passes. `StatusHandler` then finds Commit A's row purely by SHA match and calls `add_status`, which invokes `stack.schedule_merges` for **stack A**, even though the payload's `repository` field names repo B.

Existing guards fail because: (1) `verify_signature` authenticates only the org, not the specific repo; (2) `drop_unhandled_event`/`ExplicitParameters` schema for `StatusHandler` only require `sha`/`state`, with no repository/stack cross-check; (3) `StatusHandler` does not use the `stacks` scoping helper that other handlers use.

### Impact Explanation
This lets a payload for one repository (B) mutate/trigger behavior tied to another repository's stack (A) — matching the Critical category "a payload for one repository mutating another's stack, commit, task or team." Concretely it forces an unauthorized evaluation/trigger of stack A's merge queue (`ProcessMergeRequestsJob` via `Stack#schedule_merges`), which can cause premature or unwanted merges to be evaluated/executed for tenant A, without tenant A's repository having authenticated that specific request. This is repeatable against any commit SHA the attacker can learn (trivial for public repos/forks) and any stack whose commit rows share that SHA, so blast radius extends to all stacks within the same GitHub organization (or any stack tracking a commit that is also reachable/duplicated in an attacker-controlled repo).

### Likelihood Explanation
Preconditions: Shipit must be configured for at least one GitHub organization containing multiple repositories/stacks, and the attacker needs a repository (their own, a fork, or any repo in the same org) capable of emitting a genuinely GitHub-signed `status` webhook, plus knowledge of a target commit SHA (public information for public repos, or discoverable via forks which retain identical SHAs). No Shipit secrets, sessions, or tokens are required — only the ability to create a status event on a repository the attacker controls within a Shipit-monitored org, or on a fork of the target repo. This is low-cost and repeatable at will.

### Recommendation
Scope `StatusHandler#process` to the repository named in the (already organization-authenticated) payload, mirroring `CheckSuiteHandler`'s use of the `stacks` helper, e.g. iterate `stacks.flat_map(&:commits).where(sha: params.sha)` or equivalently restrict to `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`, ensuring `commit.stack.repository.full_name == repository_name` before calling `create_status_from_github!`.

### Proof of Concept
```ruby
# test/models/webhooks/handlers/status_handler_test.rb (conceptual)
test "status webhook for repo B does not schedule merges for stack A's commit sharing the same sha" do
  stack_a = shipit_stacks(:shipit) # repository "shopify/shipit-engine"
  commit_a = shipit_commits(:cyclimse_first) # belongs to stack_a, sha = SHARED_SHA
  commit_a.update!(sha: "deadbeefcafefeed0000000000000000000000")

  payload = {
    'sha' => commit_a.sha,
    'state' => 'success',
    'context' => 'ci/travis',
    'repository' => { 'full_name' => 'attacker/forked-repo', 'owner' => { 'login' => 'attacker' } }
  }

  Shipit::Stack.any_instance.expects(:schedule_merges).never # binding: only commit.stack (A) — must not fire for B's payload

  Shipit::Webhooks::Handlers::StatusHandler.call(payload)
end
```
Given the current code, `Commit.where(sha: params.sha)` finds `commit_a` regardless of `payload['repository']`, and `add_status` invokes `stack_a.schedule_merges` — so `schedule_merges.never` would fail, demonstrating the broken binding `commit.stack.repository == payload.repository`.