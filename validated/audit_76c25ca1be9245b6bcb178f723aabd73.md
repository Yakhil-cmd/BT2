### Title
`StatusHandler#process` matches commits by SHA across all repositories, letting an attacker's own repo status webhook mark another stack's commit deployable - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` looks up commits with `Commit.where(sha: params.sha)` with no repository scoping, unlike every other handler (`PushHandler`, `CheckSuiteHandler`, etc.) which restrict to `stacks` derived from `payload.dig('repository', 'full_name')`. Because git SHAs are content-addressed and not bound to a specific repository, an attacker who controls Repository B can create a commit whose SHA collides with (i.e., is literally copied from) a commit that also exists in Stack A's Repository A, then have their own repo's CI post `state: success` for that SHA; the resulting genuine, correctly-signed webhook from Repository B will attach a `success` `Status` to Commit A's row in Shipit and can trigger `Commit#schedule_continuous_delivery` → `ContinuousDeliveryJob.perform_later(stack)` for Stack A.

### Finding Description
The broken binding: the webhook's authenticated origin repository, `payload.dig('repository', 'full_name')` (Repository B), should equal the repository that owns the `Commit` row being mutated (Repository A, owner of Stack A). `StatusHandler` never enforces this equality.

- `app/models/shipit/webhooks/handlers/handler.rb` exposes a `stacks` helper that scopes to `Repository.from_github_repo_name(repository_name)&.stacks`, and `PushHandler#process` (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`) and `CheckSuiteHandler` use it correctly.
- `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) instead does:
  ```ruby
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
  ```
  This ignores `repository_name`/`stacks` entirely and matches any `Commit` row in the entire Shipit database sharing that SHA, regardless of which repository/stack it belongs to.
- `Commit#create_status_from_github!` → `add_status` → `statuses.replicate_from_github!(stack_id, github_status)` (`app/models/shipit/commit.rb:165-169`, `app/models/shipit/status.rb:24-33`) creates a `Status` scoped to `commit.stack_id` (Stack A), not to the webhook's originating repository.
- `Status#schedule_continuous_delivery` (`app/models/shipit/status.rb:42-44`) calls `commit.schedule_continuous_delivery`, which in `Commit#schedule_continuous_delivery` (`app/models/shipit/commit.rb:281-287`) checks `deployable? && stack.continuous_deployment? && stack.deployable?` and, if true, enqueues `ContinuousDeliveryJob.perform_later(stack)` for Stack A - a stack the attacker never touched.
- `Commit#deployable?` (`app/models/shipit/commit.rb:227-229`) is `!locked? && (stack.ignore_ci? || (success? && !blocked?))`; a fresh `success` status from Repository B's CI is exactly what flips this from false to true for Commit A#1 given `ignore_ci?: false`.

Regarding guards: `verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) only proves the webhook genuinely originates from GitHub for the organization named in the payload (Repository B's owner) - it authenticates *that a request came from GitHub for Repository B*, but does nothing to bind the SHA in the payload to Repository B's actual commit graph, nor to prevent it from being applied to an unrelated `Commit` row belonging to Repository A/Stack A. `ExplicitParameters` only validates the shape of `sha`/`state`/etc., not repository ownership. No model validation ties `Status#stack_id`/`Commit` lookup to `payload['repository']['full_name']` in this handler. Thus signature verification and schema validation do not close this gap - only the (missing) repository-scoping in `StatusHandler#process` would.

Exploit flow: attacker forks/creates Repository B, cherry-picks or otherwise reproduces a commit with the exact same SHA as pending Commit A#1 in Stack A (trivial via `git cherry-pick`/`git format-patch`+`git am`, or simply pushing the same tree/parent/author/committer/timestamp), pushes it to Repository B, and lets any CI integration on Repository B (which the attacker fully controls) post a `success` status for that SHA. GitHub signs and delivers this as a normal `status` webhook for Repository B. `WebhooksController#create` dispatches to `StatusHandler`, which finds the row via `Commit.where(sha: ...)` without checking which repository it belongs to, and writes a `success` `Status` under Stack A's `stack_id`.

### Impact Explanation
This lets an attacker who has no relationship to Stack A/Repository A cause a `Status` row to be written for Stack A's commit and, if `continuous_deployment: true` and the commit is otherwise deployable, trigger `ContinuousDeliveryJob.perform_later(stack)`, i.e. an unauthorized deployment/rollback trigger for Stack A driven by a webhook the attacker legitimately caused only for Repository B. This matches the Critical category "a payload for one repository mutating another's stack/commit... or an unauthorized deploy." The attack is repeatable against any target stack for which the attacker can predict/reproduce a pending commit's SHA (which is often the case in practice, e.g., forks of the same upstream repo/branch share identical SHAs by construction) - one request per fabricated status.

### Likelihood Explanation
Preconditions: Stack A must have `continuous_deployment: true`, `ignore_ci?: false`, and an existing pending/failing `Commit` whose SHA the attacker can reproduce in a repository they control (trivial for forks of the same upstream, or any repo where the attacker knows/controls the exact commit object). The attacker needs only a GitHub account, a repo they own, and a CI integration on that repo - no Shipit credentials, no privileged GitHub team membership, and no bypass of `verify_webhook_signature`, since the webhook is a completely legitimate GitHub delivery for Repository B. This is highly feasible whenever attacker-controlled forks share commit history with the tracked repository, which is common.

### Recommendation
Scope `StatusHandler#process` to the originating repository the same way `PushHandler`/`CheckSuiteHandler` do: restrict the commit lookup to `stacks` (derived from `Repository.from_github_repo_name(payload.dig('repository','full_name'))`) rather than a bare `Commit.where(sha: ...)` across all stacks, e.g. `Commit.where(sha: params.sha, stack_id: stacks.select(:id))` or by joining through `stacks.commits.where(sha: params.sha)`.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`, not out-of-scope since it demonstrates the model-level defect via the handler):
1. Create `stack_a` with `continuous_deployment: true`, `ignore_ci: false`, and `repository` pointing to `"org/repo-a"`.
2. Create `commit_a1` under `stack_a` with a known `sha`, and give it a `pending` status so `commit_a1.deployable?` is `false`.
3. Build a webhook payload: `{ "sha" => commit_a1.sha, "state" => "success", "repository" => { "full_name" => "attacker/repo-b" } }` (Repository B, unrelated to `stack_a`).
4. Assert the binding is broken:
   - Before: `payload.dig('repository','full_name') == "attacker/repo-b"` while `commit_a1.stack.repository.full_name == "org/repo-a"` (not equal).
   - Call `Shipit::Webhooks::Handlers::StatusHandler.call(payload)`.
   - After: `assert commit_a1.reload.deployable?` is now `true`, and `assert_enqueued_with(job: Shipit::ContinuousDeliveryJob, args: [stack_a])` inside the invocation, proving Stack A's continuous delivery was triggered purely by a payload whose declared repository was Repository B - confirming the two sides of the equality (originating repo vs. mutated stack's repo) never matched, yet the mutation and job enqueue still occurred.