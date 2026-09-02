### Title
Cross-repository Status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` allows unauthorized merge - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits to attach a GitHub `status` webhook to purely `Commit.where(sha: params.sha)`, with no scoping to the repository that actually sent/authenticated the webhook. Since `Commit` uniqueness is only enforced per `(sha, stack_id)` (not globally), an attacker who controls any second repository/stack can post a forged "success" status for a commit SHA they authored, causing Shipit to attach that success `Status` to the identical-SHA commit sitting on a completely unrelated stack, defeating the merge-queue's CI gate.

### Finding Description
The broken binding: `webhook.payload['repository']['full_name'] == commit.stack.repository.full_name` should hold for every `Status` row created from a webhook, but it does not.

`WebhooksController#verify_signature` only proves the webhook truly came from GitHub for `repository_owner` (`app/controllers/shipit/webhooks_controller.rb:24-38`); it never constrains which `Commit`/`Stack` rows the payload is allowed to mutate. Every other stateful handler re-derives that scope explicitly, e.g. `PullRequest::OpenedHandler#repository` uses `Shipit::Repository.from_github_repo_name(params.repository.full_name)` before touching any model (`app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb:50-54`), and the base `Handler#stacks` helper exists for exactly this purpose (`app/models/shipit/webhooks/handlers/handler.rb:32-38`).

`StatusHandler#process` ignores that pattern entirely:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
(`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`)

This is a global lookup by `sha` alone. `Commit` has a unique index on `(sha, stack_id)`, not `sha` alone (`db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb:3`), so the same SHA can legitimately exist as separate `Commit` rows on multiple stacks. Since a git commit's SHA is fully determined by its content (tree, parents, author/committer, timestamps, message), the attacker — who authors the exact commit they push as the head of their pull request against Stack A — can push that identical commit object into a second repository they control (Repo B, tracked by their own Stack B). Both repos now have a `Commit` row with the same `sha`.

The attacker then posts a real commit status against Repo B (via GitHub's Statuses API, or their own CI on Repo B) with a `context` string copied from Stack A's real required check (e.g. `"ci/circle"`), `state: success`, and a `created_at` timestamp newer than any real status. GitHub, having genuinely delivered this event for Repo B, sends a correctly-signed `status` webhook — `verify_signature` passes because it only checks that Repo B's owner/app credentials are valid, not that Repo B relates to Stack A. `StatusHandler#process` then finds **both** the Repo B commit and the Stack A commit sharing that `sha` and calls `create_status_from_github!` on each, writing the forged success `Status` onto Stack A's commit too.

`Status.replicate_from_github!` only ever creates rows (`find_or_create_by!`), it never invalidates or removes prior statuses (`app/models/shipit/status.rb:24-33`), and `Status::Group#select_significant_status` picks the most-recent row per `context` (`statuses.to_a.uniq(&:context)` ordered by `created_at DESC`, `app/models/shipit/status/group.rb:27,71-83`). Because the attacker controls `context` and `created_at`, the forged row (state `success`) becomes the "significant" status for that context, masking the real `ci_failing`/`ci_missing` status.

`MergeRequest#all_status_checks_passed?` (`app/models/shipit/merge_request.rb:193-197`) delegates to `StatusChecker#success?`, which now returns `true`. `ProcessMergeRequestsJob#perform` (`app/jobs/shipit/process_merge_requests_job.rb:10-32`) calls `merge_request.refresh!` (which re-fetches Stack A's *own* real GitHub statuses via `stack.github_api.statuses(...)`, but only *adds* additional rows without deleting the forged one), then `reject_unless_mergeable!` (no longer rejects on `any_status_checks_failed?` because the significant status per context is masked), then `all_status_checks_passed?` returns true and `merge_request.merge!` is invoked, calling `stack.github_api.merge_pull_request(...)` and merging the attacker's PR into Stack A's protected branch.

None of the existing guards (`verify_signature`, `drop_unhandled_event`, the `ExplicitParameters` schema on `StatusHandler`, model validations) check that the commit being updated belongs to the repository that authenticated the webhook — that check simply does not exist in this handler.

### Impact Explanation
A payload authenticated for Repository B is used to write a `Status` row onto a `Commit` belonging to Stack A/Repository A, which never authenticated it. This lets an attacker's own pull request bypass CI/status gating and get merged into another repository's protected branch via `merge_request.merge!` → `stack.github_api.merge_pull_request`. This is an unauthorized merge triggered by cross-tenant data mutation — matching the Critical category "a payload for one repository mutating another's stack, commit... or an unauthorized deploy, rollback or merge." The blast radius spans any pair of stacks/repositories sharing the same Shipit deployment/GitHub App installation; it is repeatable against any stack for which the attacker can get an identical commit object registered under a second stack they control.

### Likelihood Explanation
Preconditions: the attacker must have (1) a pull request open against the target Stack A (already given), and (2) at least one other repository they fully control that is also registered as a Shipit stack (Stack B) under the same Shipit/GitHub App deployment, so they can push the identical commit object there and post a status against it. Pushing an identical commit object into a second repo is trivial (`git push` the same object; no SHA collision attack needed since the attacker authors the original commit). No Shipit secrets, sessions, or elevated GitHub roles are required — only standard push/status-posting rights on repos the attacker owns, and a real GitHub-delivered webhook with a legitimately valid signature for Repo B. This is fully repeatable and requires no timing race beyond ordering the forged status's `created_at`/delivery after any earlier legitimate ones.

### Recommendation
Scope `StatusHandler#process` to the repository that authenticated the webhook, mirroring the pattern used by `PullRequest` handlers: resolve `stacks` via `Repository.from_github_repo_name(payload.dig('repository','full_name'))` and only update commits belonging to those stacks, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` instead of the global `Commit.where(sha: params.sha)`.

### Proof of Concept
Minitest (model/handler level, no live GitHub):
```ruby
test "StatusHandler does not write a status onto a commit belonging to a different repository/stack" do
  stack_a = shipit_stacks(:shipit)          # Repository A
  stack_b = shipit_stacks(:cyclimse)        # Repository B, attacker-controlled

  shared_sha = 'deadbeef' * 5

  commit_a = stack_a.commits.create!(sha: shared_sha, message: 'pr head', author: shipit_users(:walrus), committer: shipit_users(:walrus))
  commit_a.statuses.create!(stack: stack_a, state: 'failure', context: 'ci/circle')

  commit_b = stack_b.commits.create!(sha: shared_sha, message: 'pr head', author: shipit_users(:walrus), committer: shipit_users(:walrus))

  # binding under test: repo that authenticated the webhook == repo owning the commit
  assert_equal stack_b.repo_owner, "cyclimse".downcase, "sanity: payload repo is Repo B, not Repo A"

  payload = {
    'sha' => shared_sha,
    'state' => 'success',
    'context' => 'ci/circle',              # copies Stack A's required context
    'created_at' => 1.minute.from_now.utc.iso8601,
    'repository' => { 'full_name' => stack_b.github_repo_name, 'owner' => { 'login' => stack_b.repo_owner } },
    'branches' => [{ 'name' => stack_b.branch }]
  }

  assert_difference -> { commit_a.statuses.count }, 1 do
    Shipit::Webhooks::Handlers::StatusHandler.call(payload)
  end

  refute_equal commit_a.stack, commit_b.stack, "commits belong to different stacks/repositories"
  assert commit_a.statuses.reload.exists?(state: 'success', context: 'ci/circle'),
    "Repo B's webhook wrote a success status onto Repo A's commit"

  merge_request = shipit_merge_requests(:shipit_pending)
  merge_request.update!(head: commit_a)

  assert_predicate merge_request, :all_status_checks_passed?,
    "forged cross-repo status flips all_status_checks_passed? to true despite real ci_failing status on Repo A"
end
```
This demonstrates the equality violation directly: the `payload['repository']` used to authenticate the webhook (`stack_b`/Repository B) differs from `commit_a.stack` (Repository A), yet `StatusHandler.call` still writes the success `Status` onto `commit_a`, and `MergeRequest#all_status_checks_passed?` flips to `true`.