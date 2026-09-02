### Title
StatusHandler#process resolves commits by SHA alone, mutating statuses for commits belonging to a different repository's stack - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`PushHandler`, `CheckSuiteHandler`, and every other stack-mutating handler scope their writes through `stacks` (derived from `Repository.from_github_repo_name(repository_name)`), so `repository_name == commit.stack.github_repo_name` always holds before a mutation happens. `StatusHandler#process` is the sole exception: it looks up commits with a bare `Commit.where(sha: params.sha)` and calls `commit.create_status_from_github!(params)` on every match, with no comparison to `repository_name` at all, so a verified webhook for repository A can write a `Status` (and trigger `deployable_status`/`ProcessMergeRequestsJob` side effects) on a commit that actually belongs to repository B's stack whenever the two repos happen to share a commit SHA (e.g., via a fork sharing history).

### Finding Description
Binding claimed: `repository_name` (from `payload.dig('repository','full_name')`, verified by `WebhooksController#verify_signature` via the organization's `webhook_secret`) should equal `commit.stack.github_repo_name` for every commit whose `Status` is created. 

- `Handler#stacks` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`) enforces this binding via `Repository.from_github_repo_name(repository_name)&.stacks`, and `PushHandler#process` (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`) and `CheckSuiteHandler#process` (`app/models/shipit/webhooks/handlers/check_suite_handler.rb:13-17`) both mutate only through that `stacks` scope, so the binding holds.
- `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) does not call `stacks` at all:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
This performs a global, cross-tenant lookup of `Commit` by `sha` only, with no `repository_name` vs. `commit.stack.github_repo_name` comparison anywhere in the handler or in `Commit#create_status_from_github!` (`app/models/shipit/commit.rb:165-169`), which just calls `add_status`/`statuses.replicate_from_github!(stack_id, ...)` unconditionally for whatever commit was matched.

Root cause: git commit SHA1s are not globally unique across repositories — identical SHAs commonly exist across a repository and any fork/clone that shares history. `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-30`) authenticates that a `status` event genuinely originated from the claimed organization/repo owner (`repository_owner`), but it never re-validates that `payload['repository']['full_name']` matches the repository of the `Commit` row(s) that end up being mutated — that check exists only in `PushHandler`/`CheckSuiteHandler` via the `stacks` scope, and is absent in `StatusHandler`.

Exploit flow: an attacker who owns/forks a repository sharing commit history with a Shipit-tracked repository (both under an org where the GitHub App/webhook is configured) sends (or causes GitHub to send) a genuine, correctly-signed `status` webhook for a shared SHA with attacker-controlled `state`, `description`, `target_url`, and `context`. `StatusHandler` finds every `Commit` row across all stacks with that SHA — including the one belonging to the victim's stack — and writes/overwrites its status, potentially flipping `deployable?` (`success? && !blocked?`, `app/models/shipit/commit.rb:227-229`) and triggering `ProcessMergeRequestsJob`/deploy-eligibility side effects for a stack the attacker never authenticated against.

### Impact Explanation
A payload legitimately authenticated only for the attacker's own repository can create/overwrite a `Status` on a commit belonging to an unrelated tenant's `Stack`, directly matching the listed Critical category "a payload for one repository mutating another's stack, commit ... " If that status flips a commit to `success`, it can make an otherwise-blocked commit `deployable?`, enabling an unauthorized deploy/merge of another team's stack — this is repeatable for any shared-history repo pair and is not limited to a single victim.

### Likelihood Explanation
Requires: (1) two repositories tracked/traceable through the same signed webhook path that share commit history (fork of a tracked repo, or repo split/renamed under the same org), (2) the attacker able to trigger a `status` event for the shared SHA from their side (e.g. via their own CI/GitHub Status API call on their fork, or by pushing a commit whose SHA collides), and (3) the webhook actually reaching Shipit's endpoint with a signature the org's `webhook_secret` validates. No Shipit secrets, sessions, or API tokens are needed — only ordinary GitHub repository ownership/fork rights, matching the declared unprivileged attacker profile. This is feasible without brute force whenever forks exist, which is common for open-source or internally-forked repos.

### Recommendation
Scope `StatusHandler#process` through `stacks`/`repository_name` exactly like `PushHandler` and `CheckSuiteHandler`, e.g. resolve commits via `stacks.flat_map { |stack| stack.commits.where(sha: params.sha) }` (or add an explicit `commit.stack.github_repo_name == repository_name` guard) before calling `create_status_from_github!`.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`, and a source-inspection test in `test/models/shipit/webhooks/handlers_test.rb`):
1. Behavioral test: create `stack_a` (repo `"owner/repo-a"`) and `stack_b` (repo `"owner/repo-b"`) each with a `Commit` sharing the identical `sha` (`"deadbeef" * 5`). Build a `status` payload with `repository.full_name = "owner/repo-a"` and `sha` set to the shared SHA, `state: "success"`.
2. Assert equality-before: `commit_a.stack.github_repo_name == payload['repository']['full_name']` (true) and `commit_b.stack.github_repo_name == payload['repository']['full_name']` (false).
3. Call `Shipit::Webhooks::Handlers::StatusHandler.call(payload)`.
4. Assert equality-after / impact: `commit_b.reload.statuses.last.state == "success"` even though `commit_b.stack.github_repo_name != repository_name` — proving the write crossed the repository boundary. Compare with `PushHandler`/`CheckSuiteHandler`, where an equivalent cross-repo payload produces zero mutation on `stack_b`.
5. Source-inspection test enumerating `Shipit::Webhooks::Handlers.constants`, asserting each handler's `#process` source (`instance_method(:process).source_location`) references `stacks` or compares `repository_name`/`github_repo_name`, and asserting this is false only for `StatusHandler`.