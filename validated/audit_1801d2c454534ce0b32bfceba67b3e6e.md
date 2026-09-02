### Title
StatusHandler matches commits by SHA alone across all repositories/stacks, breaking the webhook-signature-to-stack binding - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` only proves that a `status` webhook was authentically sent by the GitHub App installed for the *sending* repository's organization (`repository_owner`, per `app/controllers/shipit/webhooks_controller.rb` lines 24-49); it never checks which repository/stack the payload is entitled to mutate. `StatusHandler#process` (lines 20-24) then looks up commits purely `Commit.where(sha: params.sha)`, with no filter against the requesting repository, so a validly-signed status event from repo R2 can flip the CI status of a `Commit` belonging to a completely different stack/repo R1, as long as a `Commit` row with the same SHA exists in both.

### Finding Description
The binding that should hold is:

`app_installation_repo(R2) == commit_owning_stack_repo(R1)`

Trace:
1. `WebhooksController#create` (`app/controllers/shipit/webhooks_controller.rb` lines 10-15) parses the raw JSON and dispatches to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`. The only authentication gate is `verify_signature`, which calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)` — this validates the HMAC using the `webhook_secret` configured for the *organization that owns the sending repository* (`repository_owner`, derived from `params.dig('repository','owner','login')`). It says nothing about which specific repo's `Stack`/`Commit` records the event is allowed to touch.
2. `Handler#initialize` (`app/models/shipit/webhooks/handlers/handler.rb` lines 21-24) parses the payload through the `ExplicitParameters` schema defined in `StatusHandler.params` (lines 7-18). That schema only extracts `sha`, `state`, `description`, `target_url`, `context`, `created_at`, `branches` — it deliberately does **not** carry `repository`/`repository_owner` into `params`, even though `Handler` itself defines `#repository_name` (`payload.dig('repository', 'full_name')`, line 36-38) and `#stacks` (line 32-34) precisely for this purpose.
3. `StatusHandler#process` (lines 20-24) never calls `repository_name` or `stacks`. It does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — a **global**, cross-tenant lookup by SHA over the entire `commits` table, not scoped to the sending repository's `Stack`.
4. `Commit#create_status_from_github!` (`app/models/shipit/commit.rb` lines 165-169) unconditionally writes a `Status` row and re-evaluates `deployable?`/`schedule_continuous_delivery`/Hook emission for whatever `Commit` matched, regardless of which stack/repo it belongs to.

Contrast with other handlers (e.g. `PushHandler`, `CheckSuiteHandler`, `MembershipHandler` under the same directory) which are expected to consult `Handler#stacks`/`#repository_name` to scope their side effects to the repository that actually signed the request. `StatusHandler` omits this scoping entirely.

Root cause: `git` commit SHAs are content-addressed and repository-agnostic. Any attacker who forks a target repository (or otherwise produces byte-identical commits — same tree, parents, author/committer, timestamps, message) and pushes those commits to their own GitHub repository, then sets up any application (their own fork, or any repo where a Shipit-configured GitHub App is installed) that can trigger a `status` webhook for that SHA (e.g. via GitHub Actions/any CI integration posting a commit status on their own repo, or by using an arbitrary webhook-emitting integration on a repo they control), will produce a genuinely-signed webhook whose `sha` collides with a `Commit` row already tracked under an unrelated stack (R1). `verify_signature` passes because the signature is valid for R2's organization. `StatusHandler` then finds and mutates the R1 commit's status because it never checks that the request's repository matches R1's owning stack.

Existing guards do not stop this:
- `verify_signature` authenticates the *sender's own* org/app, not the target stack — it establishes no repo-scoping by itself; the docstring intent (transitively binding installation repo to stack repo) is never actually implemented in the handler.
- `drop_unhandled_event` and `ExplicitParameters` only validate event type/shape, not repo ownership.
- `Handler#stacks`/`#repository_name` exist but are simply not invoked by `StatusHandler`.
- No `Repository`/`Stack` validation exists at the `Commit` lookup layer; `Commit.where(sha:)` is a bare, unscoped query.

### Impact Explanation
An attacker who controls any repository with an active status-emitting integration (their own fork, or any repo where a Shipit-recognized GitHub App is installed) can inject a forged/attacker-controlled CI status (`success`, `failure`, `error`, `pending`, with attacker-chosen `context`, `description`, `target_url`) onto a `Commit` belonging to a **different tenant's stack** (R1), as long as they can get a `Commit` row with a matching SHA into existence in both places (trivially achievable by forking/mirroring the exact same commit history). This can:
- Mark a blocking/required status as `success`, defeating `Commit#blocked?`/`Commit#deployable?` checks and enabling `stack.schedule_merges`/`ContinuousDeliveryJob` to fire for R1, i.e. an unauthorized deploy or merge trigger for a repository the attacker never authenticated against.
- Overwrite `target_url`/`description` shown to R1's maintainers (misleading status link), a limited spoof.

This matches the "payload for one repository mutating another's stack/commit" Critical impact category, and is repeatable against any stack whose commit history the attacker can reproduce/fork.

### Likelihood Explanation
Preconditions: the attacker needs (a) a GitHub repository under their control with any status-emitting integration and a genuinely-configured Shipit `GithubApp`/webhook secret for that repo's org (which is normal for any public-repo fork of an app already on Shipit, or any org they control that installs the Shipit app), and (b) a `Commit` row in Shipit's DB for a SHA identical to one they can reproduce (straightforward via fork/mirror of the target repo's exact commit). No Shipit session, API token, or GitHub secret of the victim is required — only a legitimately-signed webhook for the attacker's own repo. This is feasible and repeatable per matching SHA.

### Recommendation
In `StatusHandler#process`, scope the commit lookup to the stacks associated with the requesting repository, e.g.:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
using the existing `Handler#stacks`/`#repository_name` helpers, so a status is only ever applied to commits that belong to the stack backed by the repository that actually signed the webhook.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "status event for repo B does not mutate a commit belonging to repo A's stack" do
  stack_a = shipit_stacks(:shipit)          # belongs to repo "shopify/shipit-engine" e.g.
  stack_b = create_stack(repository: "attacker/malicious-fork")

  shared_sha = "a" * 40
  commit_a = stack_a.commits.create!(sha: shared_sha, message: "victim commit")

  # simulate a status payload that a genuinely-signed webhook from repo B would carry
  payload = {
    "sha" => shared_sha,
    "state" => "success",
    "context" => "ci/attacker",
    "repository" => { "full_name" => stack_b.github_repo_name, "owner" => { "login" => "attacker" } }
  }

  assert_no_changes -> { commit_a.reload.status.state } do
    Shipit::Webhooks::Handlers::StatusHandler.call(payload)
  end
end
```
Both sides of the equality must be asserted: `payload.dig('repository','full_name') == stack_b.github_repo_name` (the authenticated side) vs. `commit_a.stack.github_repo_name == stack_a.github_repo_name` (the mutated side) — currently these differ yet the mutation proceeds, demonstrating the broken binding described.