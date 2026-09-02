### Title
`StatusHandler#process` writes a `Status` to any `Commit` matching a SHA regardless of which repository's webhook produced it - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits purely by `sha` and never restricts the query to the repository named in the signed payload, unlike `PushHandler` which explicitly scopes through `stacks` (repository-derived). If a `Commit` row with the same `sha` exists under a different stack than the one that authenticated the webhook, that unrelated commit gets a `Status` written to it.

### Finding Description
The binding that should hold is: `repository.full_name` in the verified payload == the repository that owns every `Commit` row mutated by `create_status_from_github!`. Tracing the code shows this binding is never established.

- `WebhooksController#create` (`app/controllers/shipit/webhooks_controller.rb:10-15`) verifies the signature using `repository_owner` (derived from the payload) via `verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`), then dispatches raw `params` to `Shipit::Webhooks.for_event(event)` handlers.
- `Handler#initialize`/`.call` (`app/models/shipit/webhooks/handlers/handler.rb:15-24`) only parses fields declared in the handler's `params` schema and provides an optional `stacks` helper scoped by `Repository.from_github_repo_name(repository_name)` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`).
- `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
```
It never calls `stacks`, never reads `params.dig('repository', 'full_name')`, and its own `params do ... end` schema (`status_handler.rb:7-18`) doesn't even require a `repository` key. Contrast with `PushHandler#process` (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`), which correctly restricts to `stacks.not_archived.where(branch:)`.
- `Commit.where(sha: ...)` is a global lookup with no `stack_id` filter (`app/models/shipit/commit.rb`), and `Status.replicate_from_github!` (`app/models/shipit/status.rb:24-33`) is invoked via `commit.create_status_from_github!` (`app/models/shipit/commit.rb:165-169`), writing directly using `commit.stack_id`, i.e. whatever stack the matched `Commit` row belongs to — not the stack that authenticated the request.
- Signature verification (`verify_signature`) only proves that *some* repository's webhook secret produced the request; it does not, and cannot, prove that the `sha` inside the body belongs to that same repository. Because git commit SHAs are content-addressed hashes independent of the hosting repository, two different repositories tracked by the same Shipit instance (e.g. a fork or mirrored history) can contain `Commit` rows with an identical `sha` under different `stack_id`s. `StatusHandler` will happily attach a `Status` to all of them.

None of the existing guards (`drop_unhandled_event`, `verify_signature`, `ExplicitParameters` schema, model validations on `Repository`/`Stack`) close this gap — they validate *that* a webhook is authentic for *some* tracked org/repo, not *which* repository's commit is being mutated.

### Impact Explanation
An attacker who legitimately controls a repository/org tracked by the same Shipit instance (a normal tenant in a multi-team/self-hosted deployment) can cause a `Status` (`success`/`failure`/etc.) to be written against a `Commit` belonging to a completely different, unrelated stack, as long as a `Commit` row with a matching `sha` exists there. This is a cross-repository/cross-tenant write: `Status.replicate_from_github!` can flip a victim commit's CI state (`Commit#deployable?`, `blocked?`, `active?` all key off `status`/`state`), potentially unblocking or blocking deploys, and it also triggers `enable_ci_on_stack`, `schedule_continuous_delivery`, and `ProcessMergeRequestsJob` side effects on the victim's stack (`app/models/shipit/status.rb:18-19`, `app/models/shipit/commit_deployment_status.rb`... and referenced job scheduling in `commits_test.rb:763-777`). This matches the Critical category "a payload for one repository mutating another's stack, commit, task or team."

### Likelihood Explanation
This requires: (1) Shipit tracking two (or more) repositories that can independently produce webhooks with valid signatures for their own org/repo, and (2) a `Commit` row with an identical `sha` existing under a different stack — realistic via forks, mirrors, or repository renames/re-homing that are commonly tracked side-by-side in a shared Shipit instance, since git SHAs are content hashes shared across any repo holding the same commit object. The attacker needs no Shipit credentials, no maintainer status on the victim repo, and no knowledge of the victim's webhook secret — only the ability to trigger a `status` webhook from their own legitimately-configured repository. This is a code-level flaw independent of any specific hosting arrangement; the exploitability depends on the operator's topology (whether SHA collisions across tracked stacks actually occur), but the missing repository check is a genuine gap that push/pull_request handlers already close.

### Recommendation
Scope `StatusHandler#process` to the repository named in the signed payload, mirroring `PushHandler`/`Handler#stacks`, e.g.:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
and require `repository.full_name` in the `params` schema so a repository-less payload cannot bypass the check.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb` style, no live GitHub):
1. Load two stack fixtures from different repositories, e.g. `shipit_stacks(:shipit)` (repo A) and another fixture stack for repo B (`shipit_stacks(:cyclimse)` or similar distinct fixture).
2. Create a `Commit` under stack B with a specific `sha` (e.g. `"deadbeef" * 5`).
3. Create a second `Commit` with the *same* `sha` under stack A (simulating a shared/forked commit).
4. Stub `GithubHook#verify_signature` (or `GithubApp#verify_webhook_signature`) to return `true`, simulating a legitimately signed webhook from repo A's org.
5. POST `/webhooks` with `X-Github-Event: status`, body `{sha: <shared sha>, state: 'success', repository: {full_name: 'org-a/repo-a'}}`.
6. Assertions:
   - Binding before: `Commit under stack A` belongs to `repository.full_name == 'org-a/repo-a'`, matches payload.
   - Binding after: assert that `Commit under stack B` (belonging to `'org-b/repo-b'`, which never authenticated this request) also gained a `Status` row (`assert_difference('commit_b.statuses.count', 1)`), proving the payload's repository binding does not hold for all mutated commits.