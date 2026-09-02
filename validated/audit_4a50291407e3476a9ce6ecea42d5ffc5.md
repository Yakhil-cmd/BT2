### Title
Cross-stack Status forgery via unscoped `Commit.where(sha:)` lookup enables victim stack CI-toggle mutation - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` resolves the target `Commit` records purely by `sha`, with no filter on the repository named in the verified webhook payload, unlike sibling handlers (`PushHandler`, `CheckSuiteHandler`) which scope through `stacks` (derived from `repository_name`). Because git commit SHAs are content-addressed and are frequently shared across forks of the same repository (all pre-fork history is identical), an attacker who can emit a validly signed `status` webhook for a repository they own can cause `Status` rows — and their `after_create :enable_ci_on_stack` side effect — to be created against an unrelated, victim `Stack` whose `Commit` table happens to contain the same SHA.

### Finding Description
The claimed binding is: `Stack acted upon by enable_ci_on_stack == Stack owning repository named in payload["repository"]["full_name"]`.

Tracing the code:
- `StatusHandler#process` (app/models/shipit/webhooks/handlers/status_handler.rb:20-24):
```
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
This queries the global `commits` table by `sha` only — it never restricts to `stacks` derived from `repository_name`, unlike `PushHandler#process` (`stacks.not_archived.where(branch:)...`) and `CheckSuiteHandler#process` (`stacks.where(branch: ...)`), both of which use the base `Handler#stacks` method (app/models/shipit/webhooks/handlers/handler.rb:32-38) that resolves `Repository.from_github_repo_name(repository_name)`.
- `Commit#create_status_from_github!` (app/models/shipit/commit.rb:165-169) calls `statuses.replicate_from_github!(stack_id, github_status)`, where `stack_id` is the matched `Commit`'s own `stack_id` — i.e., whatever stack that commit actually belongs to, not the attacker's stack.
- `Status` (app/models/shipit/status.rb:18,38-40) has `after_create :enable_ci_on_stack`, which calls `commit.stack.enable_ci!` — again resolving to the matched commit's actual stack.
- `Stack#enable_ci!` (app/models/shipit/stack.rb:579-581) writes `true` to the stack's CI-enabled cache key, which downstream (`Commit#deployable?`, `_banners.html.erb`) affects whether CI is required/considered for deploys.

The equality does **not** hold: the stack whose `enable_ci!` fires is determined by SHA-collision across the entire `commits` table, not by the repository the verified payload claims to be from. Since git SHAs are deterministic hashes of tree/parent/author/committer/timestamp/message, a fork of a victim repository shares identical SHAs for all commits made before the fork diverged. An attacker who owns/forks a repository that shares history with a victim's tracked repository — and who can trigger (or is authorized to send, per the threat model) a signed `status` webhook naming their own repository — will cause `Commit.where(sha: ...)` to match commits belonging to the **victim's** stack as well as (or instead of) their own, since the query has no repository/stack scoping at all.

None of the listed guards prevent this: `verify_signature`/`GitHubApp#verify_webhook_signature` only authenticate that GitHub sent the payload for the named repository — they say nothing about which `Commit`/`Stack` rows the handler is allowed to touch. `drop_unhandled_event` and the `ExplicitParameters` schema only validate the shape of `sha`/`state`/etc., not repository ownership of the affected commit. There is no `require_permission!`/`stacks` scoping call in `StatusHandler` at all.

### Impact Explanation
This is a payload for one repository mutating another stack's state — the impact category explicitly listed as Critical. The concrete mutation is `Stack#enable_ci!`, which flips the CI-enabled cache flag for the victim stack. If the victim currently relies on `ignore_ci: true` because it is genuinely not wired to a CI provider, `ci_enabled?` becoming true changes UI banners and, more importantly, changes `Commit#deployable?` logic (`!locked? && (stack.ignore_ci? || (success? && !blocked?))` at app/models/shipit/commit.rb:227-229) and blocking-status evaluation for future commits, altering deploy gating behavior on a stack the attacker does not control. It is repeatable for any repository whose commit history overlaps (forks, mirrors, or repos that share commit ancestry) with a tracked victim stack, and requires no privilege on the victim stack.

### Likelihood Explanation
Preconditions: the victim `Stack` must have a `Commit` row for a SHA that also exists in a repository the attacker can send a signed `status` event for (realistic via GitHub forks, since shared history commits keep identical SHAs). The attacker needs the ability to emit a validly signed `status` webhook for their own repository, per the stated threat model. No Shipit session, API token, or secret is needed beyond that. The victim stack's tracked commits need to have been synced (normal operation). This is feasible and repeatable as long as SHA overlap exists, which is common for forked/mirrored repositories.

### Recommendation
Scope `StatusHandler#process` (and any other handler resolving records purely by SHA) to the stacks belonging to the repository named in the verified payload, mirroring `PushHandler`/`CheckSuiteHandler`:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
This ensures a `Status` (and its `enable_ci_on_stack` side effect) can only be created against commits belonging to a stack whose repository matches the authenticated webhook's `repository.full_name`.

### Proof of Concept
Add to `test/models/shipit/webhooks/handlers/status_handler_test.rb` (or an equivalent handler test file):
```ruby
test "status webhook does not enable CI on an unrelated stack sharing the same commit sha" do
  attacker_repo = shipit_repositories(:shipit) # repository named in the payload
  victim_stack = shipit_stacks(:cyclimse)      # unrelated stack, currently ignore_ci: true
  victim_stack.update!(ignore_ci: true)
  Rails.cache.delete(victim_stack.send(:ci_enabled_cache_key))

  shared_sha = "deadbeef"
  # Simulate SHA collision from a forked repo: same sha exists on victim's commit table,
  # but NOT under the repository named in the payload.
  victim_commit = victim_stack.commits.create!(sha: shared_sha, ...)

  payload = {
    "sha" => shared_sha,
    "state" => "success",
    "repository" => { "full_name" => attacker_repo.full_name } # attacker's own repo
  }

  refute victim_stack.ci_enabled?

  Shipit::Webhooks::Handlers::StatusHandler.call(payload)

  # Binding under test: victim_stack.ci_enabled? must only flip if
  # payload["repository"]["full_name"] == victim_stack.repository.full_name
  assert_not_equal attacker_repo.full_name, victim_stack.repository.full_name
  refute victim_stack.reload.ci_enabled?, "victim stack's CI flag flipped from an unrelated repository's webhook"
end
```
Currently this assertion fails (`ci_enabled?` becomes true) because `Commit.where(sha:)` in `StatusHandler#process` is not scoped by `stacks`/`repository_name`; after applying the recommended fix, the assertion passes.