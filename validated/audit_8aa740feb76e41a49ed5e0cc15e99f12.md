### Title
`StatusHandler` updates commit statuses by SHA alone, ignoring `payload['repository']`, allowing a status webhook for one repository to mutate another repository's commit rows - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits with `Commit.where(sha: params.sha)` and calls `create_status_from_github!` on every match, without ever scoping the query to the repository named in `payload['repository']['full_name']`, unlike `PullRequest::ClosedHandler`, which resolves `Shipit::Repository.from_github_repo_name(params.repository.full_name)` before acting. Because Shipit's `Commit` table has no uniqueness constraint tying a SHA to a single stack/repository, and identical SHAs legitimately occur across forks/mirrors sharing git history, a validly-signed `status` webhook from a repository/org the attacker controls can flip commit status/state for a commit row that actually belongs to a different, unrelated stack.

### Finding Description
The claimed binding is: `payload.dig('repository','full_name')` (the repository whose GitHub status event is being processed) **==** the repository owning the `Commit` row mutated by `create_status_from_github!`. In `StatusHandler` this equality is never checked.

- `Handler#stacks` / `Handler#repository_name` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`) exist precisely to scope operations to the repository named in the payload, and other handlers like `PullRequest::ClosedHandler#repository` (`app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb:49-53`) use `Repository.from_github_repo_name(params.repository.full_name)` before mutating anything.
- `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) does: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — it parses `:repository` nowhere in its `params` schema and never calls `stacks`/`repository_name`.
- `Commit#create_status_from_github!` (`app/models/shipit/commit.rb:165-169`) unconditionally records the new status/state, triggers `Hook.emit(:commit_status, ...)`, and can flip `deployable_status`, potentially triggering `stack.schedule_merges` (`app/models/shipit/commit.rb:379-384`) — i.e., it can affect downstream deploy/merge decisions for whichever stack owns that `Commit` row.
- The webhook signature check (`WebhooksController#verify_signature`, `app/controllers/shipit/webhooks_controller.rb:24-49`) verifies the payload was sent by GitHub for `repository_owner` (`params.dig('repository','owner','login')` or `organization.login`) — it authenticates *who sent it*, not that the `sha` inside actually belongs to that repository. Once a webhook is validly signed for any org/repo known to Shipit (e.g. an attacker's own repo/fork within an org that has Shipit's GitHub App installed), `StatusHandler` will happily update any `Commit` row anywhere with a matching SHA, including commits belonging to a completely different tracked stack.

Exploit flow: attacker owns or can push to a repository/fork that shares commit history (hence identical SHAs) with a repository Shipit tracks, or otherwise causes a commit with a colliding SHA to exist in their own repo. They set a commit status via the GitHub UI/API on that SHA in their own repo (which they are authorized to do). GitHub sends a validly-signed `status` webhook to Shipit for their own repository. `StatusHandler` matches the SHA against `Commit` rows globally and updates the tracked stack's commit's status, potentially unblocking or blocking deploy/merge logic for a repository the attacker does not control.

### Impact Explanation
An attacker can write a `Status`/`state` for a `Commit` belonging to a stack/repository they do not own, since lookup is `Commit.where(sha: ...)` with no repository scoping. This can influence `deployable?`/`blocked?` and trigger `stack.schedule_merges` for that foreign stack (`app/models/shipit/commit.rb:227-237`, `379-384`), i.e., a payload for one repository mutating another repository's commit/stack state — matching the "Critical: a payload for one repository mutating another's stack, commit, task or team" category. It is repeatable for any SHA collision the attacker can produce or find, and the blast radius spans all stacks whose commits share that SHA.

### Likelihood Explanation
Requires the attacker to get a validly-signed `status` webhook accepted by `verify_signature`, meaning their own repository/org must already be recognized by `Shipit.github(organization: repository_owner)`; this is realistic when an attacker has push access to a fork within the same GitHub org/installation that Shipit already trusts, and shared/forked history commonly yields identical SHAs across repos. No Shipit secrets, sessions, or maintainer privileges are needed — only ordinary GitHub write access to a repo under an org the GitHub App is installed on.

### Recommendation
In `StatusHandler`, require `:repository { requires :full_name, String }` in the params schema, resolve `Repository.from_github_repo_name(params.repository.full_name)` (mirroring `Handler#stacks`), and scope the `Commit` lookup to `stacks.flat_map(&:commits).where(sha: params.sha)` (or `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`) instead of the unscoped `Commit.where(sha: params.sha)`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "process does not scope commit lookup to the payload's repository" do
  foreign_stack = shipit_stacks(:shipit)
  other_stack   = shipit_stacks(:cyclimse) # different repository
  colliding_sha = "a" * 40

  foreign_stack.commits.create!(sha: colliding_sha, message: "foreign commit")
  other_commit = other_stack.commits.create!(sha: colliding_sha, message: "other repo commit, same sha")

  payload = {
    'sha' => colliding_sha,
    'state' => 'success',
    'repository' => { 'full_name' => other_stack.github_repo_name }, # attacker's own repo
  }

  Shipit::Webhooks::Handlers::Handler.any_instance.expects(:stacks).never

  Shipit::Webhooks::Handlers::StatusHandler.call(payload)

  other_commit.reload
  assert_predicate other_commit.status, :success? # attacker's own repo, expected
  # BUG: foreign_stack's commit with the same sha was also mutated, despite
  # payload['repository'] naming a different repository:
  assert_predicate foreign_stack.commits.find_by(sha: colliding_sha).status, :success?
end
```
This demonstrates `stacks`/`repository_name` are never invoked by `StatusHandler`, and that a `status` payload naming `other_stack`'s repository nonetheless mutates `foreign_stack`'s commit row purely via SHA collision.