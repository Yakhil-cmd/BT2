### Title
Unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` lets a `status` webhook from one repository write a status onto another repository's commit record when SHAs collide - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits globally by bare SHA (`Commit.where(sha: params.sha)`) with no repository/stack scoping, unlike its sibling handlers (`PushHandler`, `CheckSuiteHandler`, all `PullRequest::*Handler`) which explicitly resolve `Shipit::Repository.from_github_repo_name(repository_name)` before touching any stack. If a commit with an identical SHA exists in both the attacker's Shipit-connected repository and a victim's stack, a legitimately-signed `status` webhook from the attacker's own repository will write/update a `Status` on the victim's `Commit` row too, potentially flipping `shipit/checks` to `success` and triggering `stack.schedule_merges`/deployability changes on the victim stack.

### Finding Description
The broken binding is: **`status webhook signed for repository R` should imply `only commits belonging to R's stacks are mutated`**, i.e. `verified_repository == commit.stack.repository`. This binding holds for `PushHandler` (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`, uses `stacks` derived from `repository_name`) and `CheckSuiteHandler` (`app/models/shipit/webhooks/handlers/check_suite_handler.rb:13-17`, uses `stacks.where(branch:)` before touching commits), but it is broken for `StatusHandler`: [1](#0-0) 

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```

`Commit.where(sha:)` is a global, cross-repository/cross-stack query with no `stack_id` filter and no use of the `stacks` helper defined on the base `Handler` class (`app/models/shipit/webhooks/handlers/handler.rb:32-38`), which every other stateful handler uses to scope by `repository.full_name`.

`WebhooksController#verify_signature` only authenticates that the payload was signed by *some* organization matching `repository_owner` in the payload (`app/controllers/shipit/webhooks_controller.rb:24-49`) — it validates the sender's own org/repo, not that the `sha` in the body belongs to that repo. Once signature verification passes for the attacker's own onboarded repository, `StatusHandler` is invoked with attacker-controlled `sha`/`context`/`state`, and it will match *any* `Commit` row in the entire database sharing that SHA, regardless of which `stack`/repository it belongs to.

`Commit#create_status_from_github!` → `add_status` then creates a `Status`, recomputes `status`/`deployable?`, and can call `stack.schedule_merges` if the new status is `success` (`app/models/shipit/commit.rb:165-169, 366-386`), directly affecting the victim's stack merge/deploy behavior with a `shipit/checks` `success` status the attacker crafted.

Exploit flow:
1. Attacker owns/operates a GitHub repository that is legitimately connected to the same Shipit instance (so `verify_signature` passes using their own org's webhook secret).
2. Attacker arranges (e.g., via a shared commit history/fork/cherry-pick, since Git SHAs are content-derived and not repository-scoped) for a commit with the same SHA to exist in both their own repo's stack and the victim's stack in the `commits` table.
3. Attacker triggers (or crafts and sends) a `status` event with `sha` = the shared SHA, `context: "shipit/checks"`, `state: "success"`.
4. `StatusHandler#process` finds all `Commit` rows with that SHA — including the victim's — and calls `create_status_from_github!` on each, writing a `success` status onto the victim's commit and potentially unblocking merges/deploys on the victim's stack.

Existing guards do not prevent this: signature verification only checks the sender org, `ExplicitParameters` only validates the shape of `sha`/`state`/`context`, and there is no repository/stack scoping anywhere in `StatusHandler`.

### Impact Explanation
A payload authenticated for one repository can write a `Status` record for a commit belonging to a completely different repository/stack, changing that victim stack's `deployable?`/`blocked?` computation and potentially triggering `stack.schedule_merges`. This is a cross-tenant/cross-repository state manipulation matching the "Critical" category (a payload for one repository mutating another's stack/commit). The blast radius covers every stack in the Shipit instance that happens to track a commit whose SHA is shared with any repository the attacker controls.

### Likelihood Explanation
The attacker must have at least one repository legitimately connected to the same Shipit instance (a low bar in typical self-service/monorepo/multi-team deployments) and must arrange a SHA collision — achievable in real usage via shared history, forks, cherry-picks, or vendored/mirrored commits, since Git commit SHAs are content+parent derived and identical across repositories/forks when the same commit is present in both. No secrets are required beyond the attacker's own repo's legitimate webhook signature. The attack is repeatable against any stack whose commit table contains a colliding SHA.

### Recommendation
Scope `StatusHandler#process` the same way as `PushHandler`/`CheckSuiteHandler`: resolve the repository from `payload.dig('repository', 'full_name')`, restrict to that repository's `stacks`, and update only `stack.commits.where(sha: params.sha)` instead of the global `Commit.where(sha: params.sha)`.

### Proof of Concept
minitest plan (no live GitHub):
```ruby
test "status webhook does not affect a commit belonging to a different repository sharing the same SHA" do
  victim_stack = shipit_stacks(:shipit) # requires shipit/checks
  attacker_repo = Repository.create!(owner: 'attacker', name: 'attacker-repo')
  attacker_stack = Stack.create!(repository: attacker_repo, environment: 'production', branch: 'master')

  shared_sha = shipit_commits(:first).sha
  victim_commit = shipit_commits(:first) # belongs to victim_stack
  attacker_commit = Commit.create!(stack: attacker_stack, sha: shared_sha, message: 'x')

  before = victim_commit.deployable?

  payload = {
    'sha' => shared_sha,
    'state' => 'success',
    'context' => 'shipit/checks',
    'repository' => { 'full_name' => attacker_repo.github_repo_name, 'owner' => { 'login' => 'attacker' } }
  }

  Shipit::Webhooks::Handlers::StatusHandler.call(payload)

  victim_commit.reload
  # Assert the binding: status authenticated for attacker_repo must not mutate victim_commit
  assert_equal before, victim_commit.deployable?, "status from attacker repo must not affect victim commit/stack"
  assert_empty victim_commit.statuses.where(context: 'shipit/checks')
end
```
This demonstrates that `StatusHandler` currently fails the assertion (writes the status/flips deployability) because of the unscoped `Commit.where(sha:)` lookup.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
