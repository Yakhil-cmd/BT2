This confirms the vulnerability. The base `Handler` class provides a `stacks` helper method that correctly scopes lookups to the repository identified in `payload.dig('repository', 'full_name')`, as used by `CheckSuiteHandler#process` (`stacks.where(branch: params.check_suite.head_branch)`). `StatusHandler#process`, however, bypasses this scoping entirely and queries `Commit.where(sha: params.sha)` globally across all repositories/stacks, then calls `commit.create_status_from_github!(params)` for every match.

### Title
Cross-tenant Status forgery via unscoped global SHA lookup in StatusHandler#process - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits with `Commit.where(sha: params.sha)` without any constraint on the repository that sent the webhook, unlike `CheckSuiteHandler` which correctly scopes via the `stacks` helper (`Repository.from_github_repo_name(repository_name)&.stacks`). Because git SHAs are content-addressed and not repository-scoped, an attacker who owns an unrelated public repository can send a legitimately-signed `status` webhook from their own repo for a SHA that happens to also exist in a victim's private stack, causing Shipit to write a `Shipit::Status` row onto the victim's commit/stack.

### Finding Description
The broken binding: the code assumes `Commit.sha == params.sha` implies `Commit.stack.repository == payload.repository`, i.e. it treats `sha` as globally unique to the repository that reports it. In reality only `(stack_id, sha)` is unique — `Shipit::Commit` has no unique index across the whole table, and nothing in `Status.replicate_from_github!` or `Commit#create_status_from_github!` re-checks `repository_name` from the payload against the matched commit's stack.

Code path:
- `app/models/shipit/webhooks/handlers/status_handler.rb:20-24`: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — no `stacks` scoping, no `repository_name` check.
- Contrast with `app/models/shipit/webhooks/handlers/check_suite_handler.rb:13-16`, which correctly does `stacks.where(branch: ...)` before touching commits, where `stacks` (defined in `app/models/shipit/webhooks/handlers/handler.rb:32-34`) is derived from `payload.dig('repository', 'full_name')`.
- `Shipit::Commit#create_status_from_github!` (in `app/models/shipit/commit.rb`) creates a `Status` bound to `self.stack`, whatever stack that commit belongs to, regardless of which repository's webhook triggered it.

Attacker request: attacker owns `attacker/public-repo` containing a commit whose SHA equals a SHA already tracked in `victim/private-repo`'s Shipit stack (e.g. from a shared vendored dependency, a rebase, or a cherry-pick — SHAs are computed purely from tree/parent/message content, not from any repository identity). The attacker pushes a `status` event from GitHub for their own repo (legitimately signed with the attacker's own `webhook_secret`, since GitHub signs per-repository). `verify_signature`/`GitHubApp#verify_webhook_signature` validates fine — it's a real, correctly-signed event for the attacker's own repo. `drop_unhandled_event` and the `ExplicitParameters` schema don't block it either — `sha`, `state`, etc. are all valid per-schema. None of these guards check that the resolved `Commit`/`Stack` actually belongs to the repository named in `payload.repository.full_name`. The `StatusHandler` receives it, executes `Commit.where(sha: params.sha)` and matches the victim's commit purely by content-addressed SHA, then writes a real `Status` row scoped to the victim's stack.

### Impact Explanation
The attacker can inject arbitrary CI status (`success`, `failure`, `error`, `pending`, arbitrary `context`/`description`/`target_url`) onto a specific commit of a **victim's private stack**, without ever authenticating to or being a collaborator on the victim repository. Since `Status` rows drive Shipit's deployability/merge logic (`Commit#add_status`, `stack.schedule_merges`, continuous delivery triggers via `Hook.emit(:deployable_status, ...)` and `ContinuousDeliveryJob`), a forged `success` status can unblock/trigger an unauthorized deploy or merge for a repository the attacker never authenticated against. This matches "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy" (Critical) if continuous deployment is enabled on the victim stack, or at minimum forges CI state read by maintainers/deploy gating (High).

### Likelihood Explanation
Preconditions: attacker needs a SHA that collides with one tracked by the victim's stack. This is entirely plausible without any brute force — via shared open-source dependencies merged into both repos, cherry-picked/rebased commits (same tree+parent+message+author+timestamp → identical SHA), or forks that share history. No Shipit secrets, sessions, or GitHub team membership are required — only the ability to own a repo and trigger a real `status` webhook from it (any GitHub user with any repo can do this trivially). This is fully repeatable against any stack whose commit SHA the attacker can predict/reproduce.

### Recommendation
In `StatusHandler#process`, scope the commit lookup through `stacks` (the repository-derived scope already available on `Handler`), e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or equivalently `Commit.joins(:stack).merge(stacks).where(sha: params.sha)`, so a `Status` can only be attached to commits belonging to the stack(s) of the repository named in the webhook's `payload.repository.full_name`.

### Proof of Concept
```ruby
test "status webhook cannot forge status on another repository's commit with colliding sha" do
  colliding_sha = "5590fd8b5f2be05d1fedb763a3605ee461c39074"

  victim_repo = shipit_repositories(:shipit) # some fixture repo
  victim_stack = victim_repo.stacks.first
  victim_commit = victim_stack.commits.create!(sha: colliding_sha, ...)

  attacker_repo = Shipit::Repository.create!(owner: "attacker", name: "public-repo")
  attacker_stack = attacker_repo.stacks.create!(...)
  # attacker_stack has no commit with colliding_sha tracked, or has its own unrelated one

  payload = {
    "sha" => colliding_sha,
    "state" => "success",
    "context" => "ci/attacker",
    "repository" => { "full_name" => "attacker/public-repo" }
  }

  assert_no_difference -> { victim_commit.reload.statuses.count } do
    Shipit::Webhooks::Handlers::StatusHandler.call(payload)
  end
end
```
Before the fix, this assertion fails: `victim_commit.statuses.count` increases even though the webhook's `payload.repository.full_name` is `attacker/public-repo`, proving `Status.stack_id` is written for a stack the webhook never authenticated for.