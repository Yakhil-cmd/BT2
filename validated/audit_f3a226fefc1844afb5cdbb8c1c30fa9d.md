### Title
Cross-repository status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves commits purely by `sha`, with no scoping to the repository that authenticated the webhook, unlike `Handler#stacks`/`repository_name` which every other handler uses. Because `Commit#add_status` calls `stack.schedule_merges` whenever a status transitions to `pending`/`success` [1](#0-0) , a status event authenticated for one repository can flip CI state and trigger merge-queue advancement for any other stack whose `commits` table happens to contain a row with the same `sha`.

### Finding Description
The broken binding is: `commit.stack.repository.full_name` (the stack that owns the mutated commit) should equal `payload['repository']['full_name']` (the repository whose webhook signature was verified). In `StatusHandler#process` this equality is never checked:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [2](#0-1) 

Contrast with the base `Handler` class, which provides a repo-scoping helper (`stacks`) built from `payload.dig('repository', 'full_name')` [3](#0-2)  that `StatusHandler` simply does not use.

`WebhooksController#verify_signature` verifies the signature using `Shipit.github(organization: repository_owner)`, i.e. keyed by the *organization/App installation*, not the specific repository named in the payload [4](#0-3) . This authenticates "a webhook from some repo under this org/installation," not "a webhook from repo X about a commit belonging to stack Y." Any repository under an organization where the Shipit GitHub App/token is installed (including a fork of the victim repository, which shares SHAs with the upstream) can emit a signed `status` event naming an arbitrary `sha` and `context`.

Once `StatusHandler` matches any `Commit` row across all stacks with that `sha`, `create_status_from_github!` → `add_status` runs: it recomputes `status`/`checks`, and if the simple state changes to `pending` or `success`, unconditionally calls `stack.schedule_merges` [1](#0-0) . If that stack has `merge_queue_enabled` true and is waiting on a required status named `codecov/project`, the forged green status makes the head of the queue appear deployable and the merge queue advances, potentially firing `merge!`/deploy for attacker-uncontrolled but attacker-triggered code.

None of the existing guards stop this: `verify_signature` only proves the sender controls *some* repo/org with the app installed, not the specific repo tied to the target stack; `ExplicitParameters` only validates the shape of `sha`/`context`/`state`, not repository ownership; and no `Stack`/`Repository` scoping is applied in `StatusHandler#process`.

### Impact Explanation
An attacker who controls (or forks) any repository sharing SHAs with a victim's tracked repository, and has (or can obtain) a webhook endpoint authenticated for their own org/installation, can write arbitrary CI status rows (`context: codecov/project`, `state: success`) onto commits belonging to a victim's stack. If that stack has `merge_queue_enabled` and requires `codecov/project`, this forged status can unblock/advance the merge queue and trigger `merge!`, i.e. an unauthorized merge/deploy driven by a payload that never authenticated against the victim's repository. This is a cross-tenant record write with a downstream deploy/merge effect, matching the Critical category ("a payload for one repository mutating another's stack, commit ... or an unauthorized deploy/rollback/merge").

### Likelihood Explanation
Preconditions: (1) victim stack has `merge_queue_enabled: true` and requires a `codecov/project` status; (2) attacker needs some repository under an organization/App installation known to `Shipit.github`, and a commit SHA also present in the victim's `commits` table (trivially achievable via a fork, since forks retain full upstream git history and SHAs). No Shipit session, API token, or GitHub team membership is required — only the ability to have a repo wired to send webhooks to the Shipit instance (which is the normal, low-privilege GitHub App installation flow for any repo the attacker owns). The attack is repeatable indefinitely against any repo sharing history with a tracked stack.

### Recommendation
Scope `StatusHandler#process` (and verify all other handlers) to only update commits/statuses belonging to stacks whose repository matches the webhook's authenticated `repository.full_name`, e.g. reuse `Handler#stacks`/`repository_name` to filter: `Commit.where(sha: params.sha, stack_id: stacks.select(:id))` (or equivalent join through `Stack#repository`) before calling `create_status_from_github!`.

### Proof of Concept
Minitest plan (`test/models/webhooks/status_handler_test.rb`, illustrative — file itself is out-of-scope for editing but describes the validation):
```ruby
test "status for unrelated repository must not affect victim stack merge queue" do
  victim_stack = shipit_stacks(:shipit) # merge_queue_enabled: true, requires 'codecov/project'
  attacker_repo_payload = { 'repository' => { 'full_name' => 'attacker/other-repo' } }
  shared_sha = victim_stack.commits.last.sha # e.g. from a fork sharing history

  # Precondition: no status yet for codecov/project on victim's commit
  assert_not victim_stack.commits.last.statuses.exists?(context: 'codecov/project')

  Shipit::Webhooks::Handlers::StatusHandler.call(
    'sha' => shared_sha,
    'state' => 'success',
    'context' => 'codecov/project',
    'repository' => { 'full_name' => 'attacker/other-repo' } # NOT victim's repo
  )

  commit = victim_stack.commits.reload.last
  # Broken binding check: commit.stack.repository.full_name should equal payload repository, but it doesn't
  assert_not_equal 'attacker/other-repo', commit.stack.repository.full_name
  assert commit.statuses.exists?(context: 'codecov/project', state: 'success'), "status written despite repo mismatch"
  # And confirm merge queue was advanced as a result
  assert_enqueued_with(job: Shipit::MergeSchedulingJob) # or equivalent schedule_merges effect
end
```

### Citations

**File:** app/models/shipit/commit.rb (L379-384)
```ruby
      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
```
