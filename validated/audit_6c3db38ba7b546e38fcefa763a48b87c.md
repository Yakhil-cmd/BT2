### Title
Cross-tenant status forgery via unscoped SHA lookup unblocks victim stacks - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` resolves the target commit purely by `Commit.where(sha: params.sha)`, with no filter on `payload.dig('repository', 'full_name')`, unlike `PushHandler` and `CheckSuiteHandler` which both scope through the `stacks` helper (`Repository.from_github_repo_name(repository_name)`). Since GitHub webhook signature verification (`verify_signature`) only proves the payload came from *some* organization the attacker controls, not that the `sha` belongs to that organization's repository, an attacker who mirrors/reproduces a victim's public commit sha into their own repository can post a validly-signed status webhook that mutates the victim's `Commit` row.

### Finding Description
The broken binding is: the code implicitly assumes `Commit.where(sha: params.sha).stack.repository.full_name == payload.dig('repository', 'full_name')`, but nothing enforces this equality.

Path:
1. `WebhooksController#create` (`app/controllers/shipit/webhooks_controller.rb:10-15`) dispatches by event type to `Shipit::Webhooks.for_event('status')`, after `verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) checks the HMAC signature against `Shipit.github(organization: repository_owner)` — i.e., it authenticates that the payload came from the org named in `payload['repository']['owner']['login']`, nothing about the `sha` field.
2. `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`):
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
This queries `Commit` globally by `sha` across **all stacks/repositories** in the Shipit instance — it never calls the `stacks` helper (`app/models/shipit/webhooks/handlers/handler.rb:32-38`) that both `PushHandler` (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`) and `CheckSuiteHandler` (`app/models/shipit/webhooks/handlers/check_suite_handler.rb:13-17`) use to scope by `repository_name`.
3. `Commit#create_status_from_github!` → `#add_status` (`app/models/shipit/commit.rb:165-169`, `:366-386`) creates a `Status` row and recomputes `status`.
4. `Commit#blocked?` (`app/models/shipit/commit.rb:231-237`) computes `stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)`; `blocking?` is delegated to `status.blocking?` (`app/models/shipit/commit.rb:219`). Flipping C1's status to `success` removes it from the blocking set, so `blocked?` for every later commit C2 flips from `true` to `false`, and `Commit#deployable?` (`app/models/shipit/commit.rb:227-229`) becomes `true`.

Attacker's exact request: a `status` webhook POST to `/webhooks`, signed with the attacker's own organization's app secret (which they legitimately possess for their own org/repo), containing `{"sha": "<C1's sha>", "state": "success", "repository": {"full_name": "attacker/repoA", "owner": {"login": "attacker-org"}}}`. The signature check passes because it is genuinely signed by GitHub for `attacker-org`. Git commit shas are deterministic content hashes, so an attacker can trivially reproduce the exact same sha as a public commit on victim stack V by mirroring/cherry-picking the identical commit (same parent, author, timestamps, tree, message) into their own repo A, which they fully control.

Existing guards fail because: `verify_signature` only authenticates the org, not the commit; the `stacks`/`repository_name` scoping helper exists in the codebase but is simply not used by `StatusHandler`; `ExplicitParameters` schema for `StatusHandler` validates types only, not repository ownership of the sha.

### Impact Explanation
An attacker can silently clear a legitimate CI failure/pending block on an arbitrary victim stack V they do not control, causing later undeployed commits to become `deployable?` and eligible for continuous deployment/merge-queue processing (`add_status` also calls `stack.schedule_merges` on success/pending transitions, and `Commit#deployable?` feeds `Stack#next_commit_to_deploy`/`next_expected_commit_to_deploy`). This is a cross-tenant integrity violation: a payload authenticated for repository A mutates state (`Status`) belonging to unrelated stack/repository V, producing an unauthorized deploy/merge trigger for a party that never authenticated as V. This matches "a payload for one repository mutating another's stack, commit" — Critical severity.

### Likelihood Explanation
Preconditions: the attacker needs (a) a repository that Shipit's GitHub App/webhook integration is configured for (their own org, which they can set up themselves as they own it), and (b) the ability to make a commit whose sha exactly matches the victim's blocking commit — achievable by copying a public commit verbatim (same tree/parents/author/committer timestamps/message) since sha1 is fully deterministic from that content. No Shipit credentials, sessions, or GitHub App private key are required; the attacker only uses their own legitimately-issued webhook signature. This is repeatable against any stack/commit whose sha the attacker can reproduce, and the cost is low (git object crafting only, no collision needed — exact byte-for-byte copies of public commits share sha1 trivially).

### Recommendation
Scope `StatusHandler#process` the same way `PushHandler`/`CheckSuiteHandler` do: restrict the commit lookup to `stacks` derived from `payload.dig('repository', 'full_name')`, e.g. `stacks.flat_map(&:commits).select { |c| c.sha == params.sha }` or `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`, ensuring a status webhook can only mutate commits belonging to stacks whose repository matches the payload's `repository.full_name`.

### Proof of Concept
```ruby
# test/models/webhooks/handlers/status_handler_test.rb (conceptual)
test "status webhook cannot mutate a commit belonging to a different repository" do
  victim_stack = shipit_stacks(:shipit) # repository "shopify/shipit-engine"
  c1 = victim_stack.commits.create!(sha: "deadbeef" * 5, ...) # blocking commit
  c1.statuses.create!(stack: victim_stack, state: "failure")
  c2 = victim_stack.commits.create!(sha: "cafebabe" * 5, ...) # commit after c1

  assert c2.blocked?

  forged_payload = {
    "sha" => c1.sha,
    "state" => "success",
    "repository" => { "full_name" => "attacker/repoA", "owner" => { "login" => "attacker-org" } }
  }

  Shipit::Webhooks::Handlers::StatusHandler.call(forged_payload)

  refute c2.reload.blocked?
  assert c2.deployable?
end
```
This demonstrates: before, `c2.blocked?` is `true` because `c1.blocking?` is `true`; after processing a `status` webhook whose `repository.full_name` names an unrelated repo, `c2.blocked?` becomes `false` and `c2.deployable?` becomes `true`, proving the cross-tenant mutation.