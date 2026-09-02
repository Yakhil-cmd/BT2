### Title
Cross-repository commit status forgery via unscoped `Commit.where(sha:)` lookup - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves the target commit(s) for an incoming `status` webhook with `Commit.where(sha: params.sha)`, a query that is **not** scoped to the repository/stack that authenticated the webhook. Because Git SHA‑1 commit IDs are pure content hashes with no repository identity component, an attacker can make a commit with an identical SHA exist under their own, unrelated Shipit stack (by forking/copying a public commit's exact tree/parents/author/committer/dates, no SHA‑1 collision attack required), then trigger a genuinely GitHub‑signed `status` event on their own repository that gets applied to the victim's commit in a completely different stack.

### Finding Description
The binding this design should enforce is:
`params.repository.full_name (the repo that produced/authenticated the payload) == commit.stack.repository.full_name (the repo owning the mutated Commit record)`.

Tracing the code:
- `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) only verifies the HMAC over the raw body using the `webhook_secret` selected via `repository_owner` (the *organization*, not the specific repo) taken straight out of the attacker‑controlled JSON body. It never checks that the `sha`/commit referenced in the payload belongs to that org/repo.
- `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`):
```
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
This is a **global, unscoped** query across every `Commit` row in the database, regardless of which `Stack`/`Repository` it belongs to. Contrast this with `CheckSuiteHandler` (`app/models/shipit/webhooks/handlers/check_suite_handler.rb:13-17`), which correctly scopes through `stacks.where(branch: ...)` before touching `stack.commits.where(sha: ...)`. `StatusHandler` is the outlier that omits any stack/repository scoping.
- `Commit#sha` is only unique per `(sha, stack_id)` (`db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb`), confirming the schema itself anticipates the same SHA existing under multiple, unrelated stacks — but the status handler doesn't respect that boundary.

Exploit flow:
1. Attacker forks/clones a public victim repository and copies the exact Git commit object (identical tree, parent(s), author, committer, timestamps, message) that produces a target victim commit's SHA — this is not a SHA‑1 brute‑force attack, it is simply re‑using identical content, which is trivially possible for any publicly readable commit.
2. Attacker pushes that object into a repository/branch they control that is tracked as its own Shipit `Stack` (their own org/repo). `GithubSyncJob` (`app/jobs/shipit/github_sync_job.rb`) ingests it, creating a `Commit` row with `sha` equal to the victim's commit SHA but under the attacker's `stack_id`.
3. Attacker triggers (or has GitHub deliver) a genuine, correctly‑signed `status` webhook for that commit on their own repository (e.g., their own CI reports `success`/`failure`).
4. `WebhooksController#verify_signature` validates the signature successfully — it's a real signature for the attacker's own org/repo.
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, which matches **both** the attacker's own commit row and the victim's unrelated commit row (different stack, different repository, potentially different organization), and calls `create_status_from_github!` on all of them, writing a forged status onto the victim's commit.

No `verify_signature`, `drop_unhandled_event`, `ExplicitParameters` schema, or model validation checks the payload's `repository.full_name` against the commit's owning stack/repository, so the divergence is not caught anywhere in the pipeline.

### Impact Explanation
A forged `Status` record is written onto a commit belonging to a repository/stack the attacker never authenticated for. Since `Status`/`Commit#state` feeds `deployable_status`, required/blocking status checks, and merge‑queue and deploy gating logic, this can mark a victim's commit as `success` to unblock a deploy/merge, or as `failure`/`error` to block one — a payload for one repository mutating another repository's commit/task state, matching the Critical category ("a payload for one repository mutating another's stack, commit, task or team"). It is repeatable against any Shipit instance where `StatusHandler`'s unscoped query can be reached, and against any target commit whose exact Git object content the attacker can reproduce (any public commit, or any commit whose metadata the attacker can otherwise learn).

### Likelihood Explanation
Preconditions: attacker needs their own Shipit‑tracked stack/repo (self‑service or already onboarded), the ability to push arbitrary Git objects to it (trivial, they own it), and the ability to trigger one legitimately GitHub‑signed `status` webhook on that repo (trivial via any commit status API call or CI integration on their own repo). No secrets, sessions, or privileged roles are required — reproducing an existing public commit's exact Git object is not a cryptographic attack, just data reuse. This is highly feasible and repeatable against any known target commit SHA.

### Recommendation
Scope the status lookup to the repository that authenticated the webhook, e.g.:
```ruby
def process
  Repository.find_by(name: params.repository... , owner: ...)&.stacks&.each do |stack|
    stack.commits.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }
  end
end
```
or otherwise join `Commit` through `Stack -> Repository` and filter on the payload's `repository.full_name`/owner before mutating any record, mirroring the pattern already used in `CheckSuiteHandler`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "status handler forges status onto a commit from an unrelated repository/stack" do
  repo_a = Shipit::Repository.create!(owner: 'victim-org', name: 'victim-repo')
  stack_a = Shipit::Stack.create!(repository: repo_a, environment: 'production')
  repo_b = Shipit::Repository.create!(owner: 'attacker-org', name: 'attacker-repo')
  stack_b = Shipit::Stack.create!(repository: repo_b, environment: 'production')

  colliding_sha = 'a' * 40 # simulates attacker reproducing victim's exact git object
  victim_commit = stack_a.commits.create!(sha: colliding_sha, message: 'victim', authored_at: Time.now, committed_at: Time.now)
  attacker_commit = stack_b.commits.create!(sha: colliding_sha, message: 'attacker copy', authored_at: Time.now, committed_at: Time.now)

  # Binding under test: only attacker_commit's repository authenticated this payload
  assert_equal repo_b.full_name, 'attacker-org/attacker-repo'
  refute_equal repo_a.full_name, repo_b.full_name

  payload = { 'sha' => colliding_sha, 'state' => 'success', 'context' => 'ci', 'branches' => [] }
  handler = Shipit::Webhooks::Handlers::StatusHandler.new(payload)

  assert_difference -> { victim_commit.reload.statuses.count }, 1 do
    handler.process
  end
  # Demonstrates: a payload only genuinely tied to repo_b mutated repo_a's commit -> binding violated
end
```
This mirrors the existing controller-level integration test `test/controllers/webhooks_controller_test.rb:42-59` but explicitly proves the cross-repository/cross-stack write.