### Title
`StatusHandler#process` matches commits by `sha` alone across all repositories/tenants, letting a webhook signed for one GitHub organization mutate another organization's `Commit`/`Status` rows and trigger deploys - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` selects the HMAC secret using `repository_owner` (`params.dig('repository', 'owner', 'login')`) purely to authenticate *which organization* sent the request, and never checks that the named `repository` actually owns the data mutated downstream. `StatusHandler#process` looks up `Commit.where(sha: params.sha)` with no repository/stack scoping at all, so a validly-signed webhook from organization A can create a `Status` for a commit belonging to organization B's stack.

### Finding Description
Binding claimed: `repository_owner` (used in `Shipit.github(organization: repository_owner)` at `app/controllers/shipit/webhooks_controller.rb:25`) == owner of `repository.full_name` used by every downstream write. This binding is **broken** for `StatusHandler`.

- `verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) only uses `repository_owner` to pick which configured GitHub App/`webhook_secret` to HMAC-verify against [1](#0-0) . It never compares that owner to the repository whose data will actually be touched.
- The base `Handler` class *does* provide a repository-scoped `stacks` helper derived from `payload.dig('repository', 'full_name')`: [2](#0-1) . `PushHandler` and `CheckSuiteHandler` correctly use this scoped `stacks` relation before touching any record [3](#0-2) [4](#0-3) .
- `StatusHandler#process`, however, bypasses `stacks` entirely and queries `Commit` globally by `sha`: [5](#0-4) . The `repository`/`repository_owner` field of the payload is read only by the controller for signature routing and is never consulted again by this handler.
- `Commit#create_status_from_github!` → `add_status` then creates a `Status`, fires hooks, and calls `stack.schedule_merges` for pending/success states [6](#0-5) , and `Status` itself schedules continuous delivery on create [7](#0-6) .

Attack: In a multi-tenant Shipit deployment (`docs/setup.md` "Using Multiple Github Applications" configuration, out of scope to cite as doc but confirms this is a supported/expected topology), each org has its own GitHub App and `webhook_secret`. An attacker who owns/controls a repository in Organization A (already configured in Shipit) can:
1. Read a real, public commit `sha` belonging to Organization B's tracked repository (commit SHAs of public repos are visible without authentication).
2. Send `POST /webhooks` with `X-Github-Event: status`, a body whose `repository.owner.login` = `"OrgA"` (so `verify_signature` picks Org A's `webhook_secret`), but `sha` set to Org B's commit SHA, `state: "success"`.
3. Sign the raw body with Org A's `webhook_secret` (the attacker legitimately possesses this, since it's their own configured org).
4. `verify_signature` passes because the HMAC matches Org A's secret and the payload owner is Org A — this is exactly what it checks.
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, finds Org B's commit (no repository filter), and creates a `Status` row on it, potentially flipping its state to `success`/`pending` and triggering `stack.schedule_merges` / continuous delivery for Org B's stack.

Existing guards do not stop this: `drop_unhandled_event` only checks the event type is handled; the `ExplicitParameters` schema (`params do requires :sha ... end`) only validates types/presence, not repository identity; there is no `force_github_authentication`, `User#authorized?`, or `require_permission!` check on this unauthenticated webhook path (by design, since webhooks are org-authenticated, not user-authenticated); no model validation ties `Status`/`Commit` lookup to the payload's `repository.full_name`.

### Impact Explanation
An attacker with legitimate control of one org/repo (that has its own configured GitHub App in a multi-org Shipit instance) can forge commit-status writes against any other tenant's commit whose SHA they can learn (trivial for public repos). This can flip a target stack's CI status to `success`, unblock/trigger `stack.schedule_merges` and continuous deployment for a repository/organization the attacker never authenticated against — this is a cross-tenant write causing an unauthorized deploy trigger, matching the Critical category "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy, rollback or merge." The attack is repeatable against any commit SHA known to the attacker and any org configured in the same Shipit instance.

### Likelihood Explanation
Preconditions: Shipit configured for multiple GitHub organizations (each with a distinct `webhook_secret`), attacker legitimately controls at least one such org (Org A) and thus its App's webhook secret — no privileged Shipit role or secret of the victim org is needed. Attacker cost is a single crafted HTTP POST with a correctly computed HMAC using their own known secret and a publicly-visible target commit SHA. Fully repeatable and requires no interaction with the victim org or GitHub UI beyond reading its public commit history.

### Recommendation
In `StatusHandler#process` (and any other handler that queries by `sha`/`ref` without going through `stacks`), scope the lookup to the repository named in the payload, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`, mirroring the pattern already used in `PushHandler`/`CheckSuiteHandler` (`app/models/shipit/webhooks/handlers/handler.rb`'s `stacks`/`repository_name`). Ensure `repository_owner` used for HMAC selection is also enforced as the owner of every `Commit`/`Stack` mutated within the handler.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`, not present today — new file):
```ruby
test "status webhook signed by org A cannot mutate a commit belonging to org B's stack" do
  org_a_stack = shipit_stacks(:shipit) # e.g. repo_owner == 'shopify'
  org_b_stack = shipit_stacks(:cyclimse) # different repo_owner, e.g. 'other-org'
  victim_commit = org_b_stack.commits.first

  payload = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'repository' => { 'full_name' => "#{org_a_stack.repo_owner}/#{org_a_stack.repo_name}",
                       'owner' => { 'login' => org_a_stack.repo_owner } }
  }

  assert_no_difference -> { org_a_stack.commits.count } do
    assert_difference -> { victim_commit.statuses.count }, 1 do
      Shipit::Webhooks::Handlers::StatusHandler.call(payload)
    end
  end

  assert_equal 'success', victim_commit.reload.state
end
```
Assertion binding: `payload['repository']['owner']['login']` (= org A, used for signature/org selection) != `org_b_stack.repo_owner` (actual owner of the mutated commit) — yet `victim_commit.statuses.count` still increases, proving the divergence.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```
