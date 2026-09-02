### Title
`StatusHandler#process` applies GitHub status webhooks to any `Commit` matching a sha, without scoping to the payload's repository, enabling cross-tenant merges - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
Every other webhook handler (`PushHandler`, `CheckSuiteHandler`, `PullRequest::OpenedHandler`) resolves target stacks through `Handler#stacks`, which scopes to `Repository.from_github_repo_name(payload['repository']['full_name'])` before acting. `StatusHandler#process` does not: it looks up commits globally by `Commit.where(sha: params.sha)` and calls `commit.create_status_from_github!(params)` on every match, regardless of which repository the verified webhook belongs to. This breaks the intended 1:1 binding between a verified webhook's repository and the stack(s) it may mutate.

### Finding Description
The intended binding is: `payload['repository']['full_name'] == commit.stack.repository.full_name` for any commit the webhook is allowed to mutate. `StatusHandler` never establishes this binding.

Path: `WebhooksController#create` (`app/controllers/shipit/webhooks_controller.rb:10-15`) verifies the HMAC signature using `Shipit.github(organization: repository_owner)` from the *payload's* repository owner — this only proves the payload was sent by an org Shipit trusts, it says nothing about which `Commit` rows the event may touch. It then dispatches to `StatusHandler.call(params)`.

`StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`):
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
This is a global, cross-tenant query with no `repository`/`full_name` filter — contrast with `CheckSuiteHandler#process` (`app/models/shipit/webhooks/handlers/check_suite_handler.rb:13-16`), which restricts via `stacks.where(branch: ...)` where `stacks` is derived from `Repository.from_github_repo_name(repository_name)` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`). `StatusHandler`'s param schema doesn't even declare `repository` as required.

`create_status_from_github!` → `Status.replicate_from_github!` creates a `Status` row scoped to `commit.stack_id` (the *victim* stack, not the attacker's), which fires `after_commit :schedule_continuous_delivery` (`app/models/shipit/status.rb:19,42-44`) → `Commit#schedule_continuous_delivery` enqueues `ProcessMergeRequestsJob.perform_later(stack)` for the victim's stack. `ProcessMergeRequestsJob#perform` (`app/jobs/shipit/process_merge_requests_job.rb:10-32`) then calls `merge_request.refresh!` and `merge_request.all_status_checks_passed?` for every pending `MergeRequest` in that victim stack whose `head.sha` matches, and calls `merge!` if satisfied — merging a pull request in a repository that never sent or authenticated the webhook.

Exploit precondition: two `Commit` rows in different stacks/tenants sharing the same `sha`. This is not a cryptographic SHA-1-collision requirement — Git commit shas are content-addressed and repositories that share history (forks, or repos template-forked without divergence) naturally have identical commit objects/shas for shared history. If an attacker owns/controls a repository (or a fork) whose webhook is registered with Shipit under a trusted org (satisfying `verify_signature`), and any other tenant stack tracks a repository sharing a commit sha with the attacker's repo (e.g., an un-diverged fork, or an unrelated repo that independently produced a bit-identical commit, e.g. an automated dependency-bump commit with reproducible tree/parent/timestamp), the attacker's single forged `status` POST creates a `Status` on the victim stack's `Commit` too, and `ProcessMergeRequestsJob` will merge the victim's PR.

`verify_signature`, `drop_unhandled_event`, and the `ExplicitParameters` schema (`requires :sha`, `:state`) do not close this gap — they validate the sender's identity and payload shape, not which `Commit`/`Stack` the sha may affect. There is no `Repository`/`Stack` scoping guard anywhere else in `StatusHandler`.

### Impact Explanation
A single forged/legitimate `status` webhook from one attacker-controlled, Shipit-trusted repository can create `Status` rows on, and trigger `ProcessMergeRequestsJob` → `MergeRequest#merge!` for, unrelated tenants' stacks whose commits happen to share a sha — resulting in unauthorized `merge_pull_request` GitHub API calls (`app/models/shipit/merge_request.rb:169-176`) against repositories that never authenticated the webhook. This matches the Critical category: "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy, rollback or merge." The blast radius spans every stack/tenant sharing commit history or sha-colliding commits with the attacker's repo, not just one.

### Likelihood Explanation
The attacker needs: (1) a repository whose webhook is verified by Shipit (an org they legitimately push webhooks from, satisfying `verify_signature`), and (2) a commit sha shared with a victim stack's pending `MergeRequest.head`. Condition (2) is realistic for forked/templated repositories (shared git history and thus identical shas for unmodified commits) and is explicitly given as a proof idea in the question (identical dependency-bump commit cherry-picked across repos with deterministic tree/parent/dates). No Shipit secrets, sessions, or privileged roles are required — only ability to send an authenticated-for-their-own-repo `status` webhook, which is well within the stated attacker capabilities.

### Recommendation
Scope `StatusHandler#process` to the payload's repository the same way every other handler does: require `repository.full_name` in the params schema, resolve `Repository.from_github_repo_name(params.repository.full_name)`, and restrict the `Commit` lookup to that repository's stacks (e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or a `commit.stack.repository == repository` filter) before calling `create_status_from_github!`.

### Proof of Concept
```ruby
# test/models/webhooks/handlers/status_handler_test.rb (conceptual)
test "status webhook does not create a Status for a commit belonging to a different repository" do
  shared_sha = "a" * 40

  repo_a = shipit_stacks(:shipit) # repository "shopify/shipit-engine"
  repo_b = shipit_stacks(:cyclimse) # unrelated repository/tenant, e.g. "other-org/other-repo"

  commit_a = repo_a.commits.create!(sha: shared_sha, ...)
  commit_b = repo_b.commits.create!(sha: shared_sha, ...) # sha collision across tenants

  payload = {
    'sha' => shared_sha,
    'state' => 'success',
    'context' => 'ci/travis',
    'branches' => [{ 'name' => repo_a.branch }],
    'repository' => { 'full_name' => repo_a.github_repo_name } # only repo_a authenticated this event
  }

  Shipit::Webhooks::Handlers::StatusHandler.call(payload)

  assert_equal 1, commit_a.reload.statuses.count   # correct: repo_a's own commit is updated
  assert_equal 0, commit_b.reload.statuses.count   # currently FAILS: commit_b also gets a Status
end

# Follow-on: prove downstream merge fan-out
test "a single status webhook can trigger merges across two unrelated stacks sharing a head sha" do
  # set up merge_request_a on repo_a and merge_request_b on repo_b, both with head.sha == shared_sha,
  # both pending and passing required checks.
  # post the status webhook once with repository = repo_a only.
  # assert ProcessMergeRequestsJob is enqueued for BOTH repo_a and repo_b's stacks,
  # and that stack.github_api.merge_pull_request is invoked for both github_repo_names.
end
```