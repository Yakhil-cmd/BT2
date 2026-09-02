### Title
StatusHandler creates/updates Status rows on commits belonging to any stack sharing a sha, without checking `repository.full_name` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` never calls `Handler#stacks` / `Repository.from_github_repo_name`, unlike every other handler (`ClosedHandler`, `LabeledHandler`, `OpenedHandler`, `ReopenedHandler`). It instead runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` with no repository scoping at all, so a validly-signed webhook for repository A will mutate `Status` records for any commit with a matching sha regardless of which stack/repository it actually belongs to.

### Finding Description
The broken binding: for every other `Handler` subclass, `payload.dig('repository','full_name')` (verified as `repository.full_name`) equals the repository whose `stacks`/commits are touched, because `Handler#stacks` does `Repository.from_github_repo_name(repository_name)&.stacks` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`). For `StatusHandler` this equality is never established: `process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) queries `Commit.where(sha: params.sha)` globally across the entire `commits` table with no `stack_id`/repository filter, then calls `commit.create_status_from_github!(params)` for every match found (`app/models/shipit/commit.rb:165-169`), which writes a new `Status` row via `statuses.replicate_from_github!` and re-evaluates `status`/`deployable?` state for that commit's stack.

`WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) only authenticates that the HTTP request was signed by the org identified by `repository_owner` (i.e. `payload.dig('repository','owner','login')`); it never asserts that `repository.full_name` corresponds to the stack(s) whose commits get updated. The `ExplicitParameters` schema for `StatusHandler` (`sha`, `state`, `description`, `target_url`, `context`, `created_at`, `branches`) also carries no repository constraint.

Attack flow: attacker pushes a commit to a repository they control that lives in a GitHub organization on which the Shipit GitHub App/webhook is installed (so a legitimately-signed `status` webhook is emitted by GitHub itself). If that commit's sha happens to also exist as a `Commit` row tied to an unrelated stack/repository B (realistic for shared history, empty/no-op commits, or forks of common upstream), the webhook — legitimately signed for the attacker's own repo A — will create/overwrite a `Status` on stack B's commit, changing its computed `state`/`deployable?` outcome, with no verification that A == B.

### Impact Explanation
A webhook that is authentically signed for repository/organization A can write `Status` rows (and therefore alter `Commit#status`, `#deployable?`, and downstream `schedule_continuous_delivery`/merge-queue behavior) on commits belonging to a completely different stack/repository B. This is a cross-repository/cross-tenant write to another team's `Commit`/`Status` state, matching the Critical category "a payload for one repository mutating another's stack, commit, task or team." Because `Commit.where(sha:)` is unscoped, this is repeatable against any shared sha and any number of stacks simultaneously (a single sha collision fans out to every stack containing that commit).

### Likelihood Explanation
The attacker needs (a) push access to some repository within an organization where Shipit's GitHub App/webhook is already installed (unprivileged, self-controlled), and (b) a sha collision with a commit tracked by a different stack. Sha collisions are realistic without any cryptographic attack: repos forked from a shared upstream, empty/no-op initial commits, vendored boilerplate, or license-file-only commits routinely produce identical shas across unrelated Shipit-tracked repositories. No secrets are required beyond what GitHub itself provides when the attacker legitimately pushes to their own repo, since GitHub — not the attacker — computes the HMAC signature.

### Recommendation
Make `StatusHandler` scope to the repository named in the payload, mirroring the other handlers: resolve `Repository.from_github_repo_name(repository_name)` and restrict the commit lookup to `commit.stack.repository == repository` (or `stacks.joins(:commits).where(commits: { sha: params.sha })`) before calling `create_status_from_github!`, discarding matches for commits belonging to other repositories.

### Proof of Concept
```ruby
test "StatusHandler does not scope by repository and can mutate an unrelated stack's commit" do
  stack_a = shipit_stacks(:shipit)
  stack_b = shipit_stacks(:cyclimse) # different repository/stack
  colliding_sha = 'deadbeef' * 5
  commit_a = stack_a.commits.create!(sha: colliding_sha, message: 'shared')
  commit_b = stack_b.commits.create!(sha: colliding_sha, message: 'shared')

  Shipit::Repository.expects(:from_github_repo_name).never

  payload = {
    'repository' => { 'full_name' => 'attacker/repo' }, # unrelated to stack_a/stack_b repos
    'sha' => colliding_sha,
    'state' => 'success',
    'context' => 'ci'
  }

  Shipit::Webhooks::Handlers::StatusHandler.call(payload)

  # binding check: payload.repository.full_name != stack_b.repository.full_name,
  # yet commit_b (belonging to stack_b) still received the status.
  assert_not_equal 'attacker/repo', stack_b.repository.full_name
  commit_b.reload
  assert commit_b.statuses.exists?(context: 'ci', state: 'success')
end
```