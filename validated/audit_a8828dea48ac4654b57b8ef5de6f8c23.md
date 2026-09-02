### Title
`StatusHandler#process` writes GitHub status updates to commits by SHA alone, with no scoping to the repository that authenticated the webhook - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves the target commits with `Commit.where(sha: params.sha)`, a global query across the entire `commits` table, and then calls `create_status_from_github!` on every match, regardless of which repository the incoming webhook was authenticated for. Because git commit SHAs are content-addressed, the exact same SHA can legitimately exist as a `Commit` row in two different stacks (e.g. a victim stack and an attacker-owned fork of the same upstream history), letting an attacker who legitimately owns a registered repository/fork forge a `status` event that mutates a commit's status for a stack they do not control.

### Finding Description
The broken binding: the handler assumes `commit.stack_id == stack_id(repository_name_from_authenticated_payload)` for every `commit` matched by `Commit.where(sha: params.sha)`, but nothing in the code enforces that equality.

- `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) only proves the payload was signed by GitHub for `repository_owner = params.dig('repository','owner','login')` — i.e. it authenticates that the event genuinely came from *some* GitHub org/repo the attacker controls, not that it applies to any specific victim commit.
- The base `Handler` class exposes a `stacks` helper that scopes lookups to `Repository.from_github_repo_name(repository_name)` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`), and other handlers (e.g. `check_suite_handler.rb`) use this `stacks` scoping to constrain which records they touch.
- `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) does **not** use `stacks`/`repository_name` at all — it queries `Commit.where(sha: params.sha)` unconditionally across all stacks/repositories, then calls `commit.create_status_from_github!(params)` for every match.
- `Commit#create_status_from_github!` → `statuses.replicate_from_github!(stack_id, github_status)` (`app/models/shipit/commit.rb:165-169`) writes the status using the **commit's own** `stack_id`, so if a victim's `Commit` row shares a SHA with the attacker's authenticated payload, the victim's stack gets a new status record for a context/state the attacker chose.

Exploit flow:
1. Attacker forks (or otherwise obtains) a repository whose history shares a commit SHA with the victim's tracked repository (git commit hashes are content-addressed and identical across forks for unchanged history).
2. Attacker registers/owns that repo under a GitHub org already known to Shipit (so `Shipit.github(organization: repository_owner)` resolves and `verify_webhook_signature` succeeds — this is a legitimate signature for the attacker's own repo).
3. Attacker triggers (or has GitHub send) a `status` event for that shared SHA with `context: "ci/smoke"`, `state: "success"`.
4. `StatusHandler#process` matches the victim's `Commit` row purely by SHA and calls `create_status_from_github!`, writing a `success` status attributed to `ci/smoke` onto the victim's stack's commit.
5. If `ci/smoke` is part of the victim stack's `ci.require`, `Commit#status`/`deployable?` flips, potentially unblocking a merge or continuous deployment (`Commit#schedule_continuous_delivery`, `app/models/shipit/commit.rb:281-287`).

Existing guards (`verify_signature`, `ExplicitParameters` schema, `drop_unhandled_event`) only validate the payload shape and that it was actually sent by GitHub for the attacker's own org — none of them validate that the target `Commit` belongs to that same repository, which is the actual missing check.

### Impact Explanation
This is a cross-tenant write: a webhook authenticated for repository A (attacker-controlled) causes a status/commit-state mutation on repository B's (victim's) stack, potentially flipping `deployable?`/merge eligibility and triggering continuous deployment or merge-request auto-merge for attacker-influenced code. This matches the "a payload for one repository mutating another's stack/commit" Critical category. It is repeatable against any stack whose tracked repository shares any historical commit SHA with a repository the attacker can register with Shipit (forks of public repos are the common case).

### Likelihood Explanation
Preconditions: the attacker needs a GitHub repository/org already registered with the Shipit instance's GitHub App (so `verify_signature` succeeds for their org), and needs a SHA collision with a real commit tracked by the victim's stack — trivially achieved by forking a public repository and reusing an existing, unmodified commit from its history (the SHA is identical in the fork). No Shipit credentials, sessions, or GitHub secrets are required beyond the attacker's own legitimate webhook signature for their own repo. This is a low-cost, deterministic, and repeatable attack for any target that fits this fork/shared-history pattern.

### Recommendation
Scope `StatusHandler#process` (and confirm all other SHA-keyed handlers) to only touch commits belonging to stacks resolved from the authenticated `repository_name`, e.g. `stacks.joins(:commits).where(shipit_commits: { sha: params.sha }).each { |stack| stack.commits.find_by(sha: params.sha)&.create_status_from_github!(params) }`, using the `stacks` helper already defined on `Handler`, instead of the unscoped `Commit.where(sha: ...)`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "process does not update commits belonging to a different repository sharing the same sha" do
  victim_stack = shipit_stacks(:shipit) # tracks e.g. "shopify/shipit-engine"
  victim_stack.update!(cached_deploy_spec: { ci: { require: [['ci/smoke']] } })
  shared_sha = "a" * 40
  victim_commit = victim_stack.commits.create!(sha: shared_sha, author: shipit_users(:walrus),
    committer: shipit_users(:walrus), authored_at: Time.now, committed_at: Time.now, message: "shared")

  attacker_repo = Repository.create!(owner: "attacker", name: "fork") # repo the attacker legitimately owns/authenticates as

  payload = {
    'repository' => { 'full_name' => attacker_repo.github_repo_name, 'owner' => { 'login' => 'attacker' } },
    'sha' => shared_sha, 'state' => 'success', 'context' => 'ci/smoke'
  }

  before = victim_commit.reload.deployable?
  Shipit::Webhooks::Handlers::StatusHandler.call(payload)
  after = victim_commit.reload.deployable?

  assert_equal before, after, "victim commit's deployable? must not change from an event authenticated for a different repository"
  refute victim_commit.statuses.exists?(context: 'ci/smoke'), "no status should have been written to the victim stack's commit"
end
```
Both sides of the equality `commit.stack.repository == authenticated_repository` must hold before writing a status; with the current implementation this assertion fails, confirming the vulnerability.