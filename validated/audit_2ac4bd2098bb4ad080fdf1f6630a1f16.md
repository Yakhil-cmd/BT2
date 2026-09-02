### Title
Cross-repository `Status` forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` looks up the target commit(s) by SHA alone, across the entire database, instead of scoping the lookup to the repository that authenticated the webhook (as `PushHandler` and `CheckSuiteHandler` do via `stacks`). Any org/repo that has a legitimately configured, signature-verified webhook can therefore forge a `Status` row (and its side effects) for a commit belonging to a completely different stack/repository, simply by sending a `status` event whose `sha` collides with a commit tracked by another stack. This write occurs unconditionally, regardless of `Stack#deployable?` or `Stack#continuous_deployment?`, confirming it is a standalone Critical bug independent of whether `ContinuousDeliveryJob` is subsequently enqueued.

### Finding Description
The broken binding is: the handler assumes `repository_name_from_signed_payload == repository_that_owns(commit_with_matching_sha)`, but no code enforces this equality.

- `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) only checks the HMAC signature against `Shipit.github(organization: repository_owner)`, where `repository_owner` is read directly from the attacker-controlled payload (`params.dig('repository','owner','login')`). This proves the request came from *some* GitHub org that Shipit trusts (the attacker's own org/repo, per the threat model), but proves nothing about which *commit* the payload's `sha` should be allowed to touch.
- The base `Handler` class defines a `stacks` helper (`app/models/shipit/webhooks/handlers/handler.rb:32-38`) that scopes lookups to `Repository.from_github_repo_name(repository_name)&.stacks`, and both `PushHandler#process` (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`) and `CheckSuiteHandler#process` (`app/models/shipit/webhooks/handlers/check_suite_handler.rb:13-17`) correctly use `stacks.where(...)` to restrict effects to the authenticated repository.
- `StatusHandler#process` does not use `stacks` at all: [1](#0-0) 
  It runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — a global, unscoped query across every stack/repository in the Shipit instance.

Exploit flow: an attacker who owns a repository/org with a valid Shipit webhook configured (satisfying `verify_signature` legitimately, since GitHub itself signs the request for their org) sends a `status` webhook whose `repository.full_name` is their own repo, but whose `sha` is chosen/engineered to match a commit SHA that exists in a *different* tracked stack (e.g., a shared upstream commit, a forked history, or any known SHA of a target repo's commit — SHA1 is a public, non-secret identifier so an attacker can trivially learn or predict a target's commit SHAs from the target's public GitHub history). Because `StatusHandler#process` matches purely on `sha` with no repository/stack scoping, `Commit#create_status_from_github!` is invoked on the victim stack's commit, creating a forged `Status` record attributed to the attacker's arbitrary `state`/`context`/`description`/`target_url` values.

This corrupts `Commit#blocked?` (`app/models/shipit/commit.rb:231-237`) and `Commit#deployable?` (`app/models/shipit/commit.rb:227-229`) evaluation for the victim stack, and triggers downstream effects tied to `Status` creation (`after_create :enable_ci_on_stack`, `after_commit :schedule_continuous_delivery, :broadcast_update`, hook emissions) — all attributable to a repository that never authenticated for the victim stack.

Existing guards do not stop this: `verify_signature` authenticates the *sender's own org*, not the *target commit's owning repo*; `drop_unhandled_event` and the `ExplicitParameters` schema only validate shape, not ownership; there is no `Repository`/stack membership check anywhere in `StatusHandler`.

Per the question's specific framing: even if stack A additionally requires `stack.deployable?` (no lock, no active task) before `Commit#schedule_continuous_delivery` proceeds to enqueue `ContinuousDeliveryJob` (`app/models/shipit/commit.rb:281-287`, `app/models/shipit/stack.rb:376-378`), that gate only affects the *deploy trigger* side effect. The `Status` row write, the `blocked?`/`deployable?` state corruption, and any hook emitted on `Status` creation happen inside `create_status_from_github!` **before** and **independent of** the `stack.deployable?` check in `schedule_continuous_delivery`. Locking stack A does not prevent the forged write; it only prevents the subsequent auto-deploy from firing. This isolates the status forgery as a standalone, unconditional Critical finding.

### Impact Explanation
An unprivileged attacker who controls any repository with a valid Shipit webhook installation can write fabricated `Status` rows for commits belonging to unrelated repositories/stacks they do not own or authenticate for. This corrupts CI-gating logic (`blocked?`, `deployable?`) for the victim stack, can force a victim's continuous-delivery evaluation to consider the commit "green" (fabricated `success` status) or block a legitimate deploy (fabricated `failure`/`error` status), and fires any registered hooks tied to status changes with attacker-controlled data attributed to the victim repository. This is a cross-repository write where a payload for one repository mutates another's commit/stack state — matching the Critical impact category ("a payload for one repository mutating another's stack, commit ... or an unauthorized deploy"). The finding is repeatable against any commit SHA the attacker can enumerate from any tracked repository's public GitHub history, and does not require any Shipit credential beyond a legitimately webhook-linked repo of the attacker's own.

### Likelihood Explanation
Preconditions: Shipit must have at least one org/repo the attacker controls with the GitHub App/webhook installed (satisfying `verify_signature` legitimately — this is an ordinary, low-cost Shipit onboarding scenario, not a secret bypass), and a target stack tracking a commit whose SHA the attacker can learn (public GitHub SHAs are not secret). Attacker cost is a single crafted HTTP POST to `/webhooks` with a `status` event body containing the victim's SHA. It is fully repeatable and scriptable against arbitrary target stacks/commits.

### Recommendation
Scope `StatusHandler#process` to the authenticated repository the same way `PushHandler`/`CheckSuiteHandler` do, e.g., restrict the commit lookup to commits belonging to `stacks` (repository-scoped) rather than a global `Commit.where(sha:)`:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```

### Proof of Concept
Minitest plan (`test/models/webhooks/handlers/status_handler_test.rb`, illustrative — actual file may already exist under `test/`):
```ruby
test "status handler forges a Status for a commit on a different, locked stack" do
  victim_stack = shipit_stacks(:shipit) # e.g. locked, deployable? == false
  victim_stack.update!(lock_reason: 'locked for testing')
  assert_not victim_stack.deployable?

  victim_commit = shipit_commits(:first) # belongs to victim_stack

  attacker_payload = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'context' => 'attacker-forged',
    'repository' => { 'full_name' => 'attacker-org/attacker-repo', 'owner' => { 'login' => 'attacker-org' } }
  }

  assert_difference -> { victim_commit.statuses.count }, 1 do
    assert_no_enqueued_jobs only: ContinuousDeliveryJob do
      Shipit::Webhooks::Handlers::StatusHandler.call(attacker_payload)
    end
  end

  status = victim_commit.statuses.last
  assert_equal 'attacker-forged', status.context
  assert_equal 'success', status.state
  # Write occurred despite stack A being locked/undeployable -> proves
  # the forgery write is unconditional and independent of the deploy trigger.
end
```
This demonstrates the `Status` row is written (and any `after_create`/`after_commit` hooks on `Status` fire) for `victim_commit` even though the payload's `repository` is the attacker's own and `victim_stack.deployable?` is `false`, while `ContinuousDeliveryJob` is correctly not enqueued — isolating the unscoped `Commit.where(sha:)` lookup as the standalone Critical defect.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
