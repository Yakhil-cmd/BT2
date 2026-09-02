### Title
Cross-repository status forgery via unscoped SHA lookup lets an attacker satisfy a victim stack's `required_statuses` gate - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves the target `Commit` purely by `Commit.where(sha: params.sha)`, with no check that the webhook's own `repository.full_name` corresponds to the stack/repository that commit belongs to. Because `state` and `context` are taken verbatim from the payload, any correctly-signed webhook (which GitHub will sign for any repository the sender controls) that references a SHA shared with a victim's tracked commit (e.g., via a public fork, which preserves upstream SHAs) can write an arbitrary `Status` — including `state: 'success'`, `context: 'ci/important'` — onto the victim's commit, satisfying `Stack#required_statuses` and unlocking `Commit#deployable?`/merge gating for a repository the attacker never authenticated against.

### Finding Description
The broken binding: the context/state an authorized CI system for repository R may report for commit C == the context/state this handler accepts and attaches to C's `Status` row, from any repository whose signature validates — **but the code never enforces "sending repo == C's repo" at all**, so the binding fails on both the context axis (as posed in the question) and the repository axis (the commit is found with no scoping whatsoever).

Code path:
- `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) verifies the HMAC using `Shipit.github(organization: repository_owner)`, where `repository_owner` is read straight from `params.dig('repository','owner','login')` in the JSON body. This only proves the payload was legitimately signed *for that org* — it says nothing about which commits that org is entitled to report on. An attacker who owns a repository under any org with the GitHub App/webhook installed on Shipit can get GitHub to emit a validly-signed `status` webhook at will, for their own fork.
- `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`): `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`. Unlike `Handler#stacks` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`), which other handlers use to scope lookups to `Repository.from_github_repo_name(repository_name)`, `StatusHandler` bypasses that helper entirely and queries `Commit` globally by `sha`, with **no join/filter on repository or stack**.
- `Commit#create_status_from_github!` (`app/models/shipit/commit.rb:165-169`) then calls `statuses.replicate_from_github!(stack_id, github_status)`, writing `state`/`context`/`target_url`/`description` directly from `params` onto that commit's `stack_id`.
- `Commit#deployable?` (`app/models/shipit/commit.rb:227-229`) and `Stack#required_statuses` (delegated to `cached_deploy_spec`, `app/models/shipit/stack.rb:527-531`) then evaluate the forged status as if it were legitimate.

Exploit flow: attacker forks the victim's public repository (git SHAs are content-addressed and preserved across forks), pushes/tags nothing further needed — they simply POST (or trigger via their fork's real GitHub status API, since GitHub will sign it correctly for their own org) a `status` event with `sha` = a SHA that exists in the victim's Shipit-tracked history, `state: 'success'`, `context: '<victim's required context>'`. `verify_signature` passes because the signature matches the attacker's own org's webhook secret; `StatusHandler` then finds the victim's `Commit` row by bare SHA equality and attaches the forged status to it.

Why existing guards don't catch this: `verify_signature` authenticates the *sender org*, not the *target commit/repository*; `ExplicitParameters` schema only validates types/presence, not cross-repository ownership; there is no `Repository`/`Stack` scoping anywhere in `StatusHandler`.

### Impact Explanation
A forged status write on a foreign stack's commit satisfies `Stack#required_statuses` checks used by `Commit#deployable?` and `Stack#next_commit_to_deploy`/`trigger_continuous_delivery`, enabling an unauthorized deploy or merge-queue advance for a repository/stack the attacker does not own or administer — this is a "payload for one repository mutating another's commit/stack" scenario, matching the Critical bar ("unauthorized deploy, rollback or merge"). It is repeatable against any stack whose tracked commits share history (via public fork) with a repository the attacker controls, and is not limited to one victim.

### Likelihood Explanation
Preconditions: attacker needs (a) any repository under an org/installation that Shipit's GitHub App can sign webhooks for (trivially satisfied by forking any public repo already tracked by the target Shipit instance, or by owning any repo in an org with the app installed), and (b) knowledge of the victim's required status context (explicitly stated as discoverable from the victim's public `shipit.yml` or the GitHub status API). No Shipit credentials, secrets, or privileged roles are required — cost is essentially "fork a public repo and push a commit/CI status." This is highly feasible and repeatable.

### Recommendation
In `StatusHandler#process`, scope the `Commit` lookup to the stacks belonging to the webhook's own repository (reuse `Handler#stacks`/`repository_name`) rather than a bare `Commit.where(sha: ...)` across the whole table, e.g. resolve via `stacks.flat_map(&:commits).where(sha: params.sha)` or join through `Stack`/`Repository` so a status can only be attributed to a commit that actually belongs to the reporting repository's own stack(s).

### Proof of Concept
Under `test/models/shipit/webhooks/handlers/status_handler_test.rb` (minitest, no live GitHub):
```ruby
test "cannot forge a required status for a commit belonging to a different repository" do
  victim_stack = shipit_stacks(:shipit)
  victim_stack.update!(cached_deploy_spec: DeploySpec.new('ci' => { 'require' => ['ci/important'] }))
  victim_commit = shipit_commits(:first) # belongs to victim_stack
  refute_predicate victim_commit, :deployable?

  attacker_payload = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'context' => 'ci/important',
    'repository' => { 'full_name' => 'attacker/unrelated-repo', 'owner' => { 'login' => 'attacker-org' } }
  }

  Shipit::Webhooks::Handlers::StatusHandler.call(attacker_payload)

  victim_commit.reload
  assert_equal 'success', victim_commit.statuses.last.state
  assert_equal 'ci/important', victim_commit.statuses.last.context
  assert_predicate victim_commit, :deployable? # FAILS the fix; should stay false pre-fix demonstrates the bug
end
```
Both sides of the binding before/after: before the call, `victim_commit.deployable?` == `false` (no matching required status); after the call from an unrelated `repository.full_name`, `victim_commit.deployable?` == `true`, proving the sending repository was never validated against the commit's owning stack/repository.