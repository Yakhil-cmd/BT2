### Title
`security/scan` status webhook flips required-context state on any commit sharing the same SHA across unrelated repositories/stacks - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` looks up commits purely by SHA (`Commit.where(sha: params.sha)`) and never scopes the query to the repository that authenticated the webhook, unlike sibling handlers such as `CheckSuiteHandler` which use the `stacks` helper (repository-scoped via `Repository.from_github_repo_name(repository_name)`). Because `verify_signature` in `Shipit::WebhooksController` only checks that the payload's `repository.owner.login` matches a configured GitHub org/app and not that the specific commit belongs to that repository, any commit row that happens to share a SHA with the attacker-controlled payload gets its status updated, regardless of which repository authenticated the request.

### Finding Description
The broken binding is: **the equality "webhook's authenticated `repository.full_name` == `commit.stack.repository.full_name` for every `Commit` mutated by this request" is assumed but never enforced.**

Trace:
- `Shipit::WebhooksController#create` (app/controllers/shipit/webhooks_controller.rb:10-15) parses JSON and dispatches to handlers for the event type. `verify_signature` (lines 24-49) only validates the HMAC signature against `Shipit.github(organization: repository_owner)`, i.e. it proves the payload was signed by *some* GitHub org's webhook secret, not that the commit SHA inside it belongs to that org's repository. [1](#0-0) 
- `Shipit::Webhooks::Handlers::Handler` provides a repository-scoping helper `stacks`, built from `payload.dig('repository', 'full_name')`, that other handlers (e.g. `CheckSuiteHandler`) use to constrain writes to stacks belonging to the authenticating repository. [2](#0-1) [3](#0-2) 
- `StatusHandler#process`, however, ignores `stacks`/`repository_name` entirely and queries `Commit.where(sha: params.sha)` — a bare, unscoped, table-wide lookup — then calls `commit.create_status_from_github!(params)` for every match, however many different stacks/repositories they belong to. [4](#0-3) 
- `Commit#create_status_from_github!` records the status and, via `add_status`, can trigger `stack.schedule_merges` when the new status is `success`/`pending`. [5](#0-4) [6](#0-5) 
- Separately, on `after_create`, every commit schedules `schedule_continuous_delivery`, which enqueues `ContinuousDeliveryJob` if `deployable? && stack.continuous_deployment? && stack.deployable?`. `deployable?` requires `success? && !blocked?` (or `ignore_ci?`), which is exactly the condition a forged `security/scan`/`success` status flips. [7](#0-6) [8](#0-7) 

Exploit flow: an attacker owns/controls repo `attacker/evil` (or any repo whose webhook secret they can trigger, e.g. their own fork with webhooks enabled) that legitimately shares a commit SHA with the victim's tracked repository — SHA is a pure content hash of tree+parents+metadata, so any commit cherry-picked, rebased identically, or historically shared between repos (common upstream ancestor, mirrored release commit, or a crafted commit with identical tree/parents/authored dates/message reproduced in the attacker's own repo) will have an identical SHA regardless of which GitHub repo hosts it. The attacker fires (or GitHub fires on their behalf) a `status` event: `{state: "success", context: "security/scan", sha: "<shared sha>", repository: {full_name: "attacker/evil", owner: {login: "attacker"}}}`. This request is legitimately signed by the attacker's own repo's webhook secret, so `verify_signature` passes. `StatusHandler#process` then finds the `Commit` row in the victim's stack matching that SHA (even though it belongs to a completely different `repository.full_name`) and writes the `security/scan: success` status onto it. If the victim stack requires `security/scan` as a blocking/required status and has `continuous_deployment` enabled, this write can flip `deployable?` to true and trigger `ContinuousDeliveryJob`, producing an unauthorized deploy of a commit the victim's own CI/security pipeline never actually scanned as safe (or, conversely, an attacker could send `state: failure` to block a legitimate deploy on the victim stack).

Existing guards do not stop this: `verify_signature` authenticates only the org owning the payload's `repository` field, not the commit's true owner; `drop_unhandled_event` and `ExplicitParameters` schema only validate shape/presence of fields, not tenant scoping; there is no `require_permission!`/`stacks`-scoping call inside `StatusHandler#process` as there is in `CheckSuiteHandler`.

### Impact Explanation
A payload that is authenticated for one repository (`attacker/evil`) mutates commit/status state belonging to a different repository/stack (the victim's), directly matching the Critical category "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy, rollback or merge." With `continuous_deployment` enabled and the forged context marked required/blocking, this can force `ContinuousDeliveryJob` to ship an attacker-influenced commit, or block a legitimate one by sending `failure`. This is repeatable against any commit SHA the attacker can reproduce/control that coincides with a commit present in a victim's Shipit-tracked stack, and is not limited to a single victim — any stack tracking a repository whose commit history intersects (via forks, shared upstream, cherry-picks, mirrors) with a repository the attacker controls is exposed.

### Likelihood Explanation
Preconditions: (1) the attacker must control (own, or be able to trigger webhooks from) some GitHub repository, which is trivial for any GitHub user; (2) the victim stack must have a commit whose SHA the attacker can reproduce or already shares (common in forked/mirrored codebases, monorepo splits, or simply by rebasing identical content) — no secret or privileged access to the victim repo is required, since SHA collision here is intentional content matching, not cryptographic collision; (3) the victim stack should have `continuous_deployment` enabled and `security/scan` configured as a required/blocking status for full "ship" impact, though even without continuous_deployment, silently flipping a required status on a foreign stack's commit record is itself a cross-tenant integrity violation. Attacker cost is a single unauthenticated-looking HTTP webhook request signed with a secret they legitimately possess (their own repo's). This is fully repeatable and scriptable.

### Recommendation
In `app/models/shipit/webhooks/handlers/status_handler.rb`, scope the commit lookup to the authenticating repository, mirroring `CheckSuiteHandler`/other handlers' use of `stacks`, e.g. replace `Commit.where(sha: params.sha)` with a query restricted to `stacks.flat_map(&:commits).where(sha: params.sha)` (or equivalently `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`), ensuring only commits belonging to stacks tracking the webhook's own `repository.full_name` can be updated.

### Proof of Concept
```ruby
# test/models/webhooks/status_handler_test.rb (conceptual, no live GitHub)
test "status webhook does not affect commits on stacks for a different repository" do
  victim_stack = shipit_stacks(:shipit)
  victim_stack.update!(continuous_deployment: true)
  victim_commit = victim_stack.commits.create!(sha: 'deadbeef' * 5, ...)
  # victim requires security/scan as a blocking status
  victim_stack.stub(:required_statuses, ['security/scan'])

  attacker_payload = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'context' => 'security/scan',
    'repository' => { 'full_name' => 'attacker/evil', 'owner' => { 'login' => 'attacker' } }
  }

  # BEFORE: victim_commit.deployable? == false (no security/scan status yet)
  assert_equal false, victim_commit.reload.deployable?

  Shipit::Webhooks::Handlers::StatusHandler.call(attacker_payload)

  # AFTER: assert the binding holds -- a payload authenticated for attacker/evil
  # must NOT mutate a commit belonging to victim_stack's repository.
  refute victim_commit.reload.statuses.exists?(context: 'security/scan'),
    "status for unrelated repository should not attach to victim's commit"
end
```
This test demonstrates the equality `commit.stack.repository.full_name == payload['repository']['full_name']` is currently violated by `StatusHandler#process`, and should be enforced by scoping the lookup through `stacks` as recommended.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```

**File:** app/models/shipit/commit.rb (L366-386)
```ruby
    def add_status
      already_deployed = deployed?

      previous_status = status
      yield
      reload # to get the statuses into the right order (since sorted :desc)
      new_status = status

      unless already_deployed
        payload = { commit: self, stack:, status: new_status.state }
        Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
      end

      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
      new_status
    end
```
