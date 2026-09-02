### Title
`StatusHandler` mutates commits/statuses across tenants without re-validating the webhook's `repository` against the matched commit's stack - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` authenticates a `status` webhook against the organization named in the payload's own `repository.owner.login`, but `StatusHandler#process` then looks up commits globally by `sha` with no re-check that the matched commit's stack belongs to that same, verified repository/organization. An attacker who controls a repository already onboarded to Shipit (and therefore can produce a payload that passes signature verification for their own org) can name any `sha` tracked by an unrelated repository and create a `Status` on it.

### Finding Description
The broken binding is: `Shipit.github(organization: repository_owner_from_payload).verified` should imply `commit.stack.repository.owner == repository_owner_from_payload` for every `Commit` mutated by the handler — but this equality is never checked.

Path:
- `WebhooksController#verify_signature` derives `github_app` purely from `params.dig('repository', 'owner', 'login')` (i.e. attacker-controlled JSON) and validates the HMAC signature against that org's secret [1](#0-0) , then `repository_owner` is read straight from the payload [2](#0-1) .
- `#create` dispatches to `Shipit::Webhooks.for_event('status')`, which resolves to `Handlers::StatusHandler` [3](#0-2) .
- `StatusHandler#process` calls `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — this is a global lookup with no reference to `params.repository` or `payload.dig('repository','full_name')` at all [4](#0-3) .
- By contrast, the base `Handler` class exposes a `stacks` helper that explicitly scopes to `Repository.from_github_repo_name(repository_name)` before touching any `Stack` [5](#0-4) , but `StatusHandler` bypasses this helper entirely and queries `Commit` directly by `sha`.
- `sha` is not globally unique in the schema; the only index is `(stack_id, sha)` [6](#0-5) , so `Commit.where(sha:)` can and will match commits belonging to arbitrary, unrelated stacks/repositories if the raw sha string happens to be shared or is deliberately reused (an attacker can trivially copy a real, public sha from a victim repo they don't own).
- `create_status_from_github!` → `add_status` triggers real side effects on the mutated commit: it emits `commit_status`/`deployable_status` hooks, and calls `stack.schedule_merges` when the new status is `pending` or `success`, which can advance automatic merges/continuous delivery on the victim's stack [7](#0-6) .

Existing guards do not prevent this: `verify_signature` only proves the request was signed for *some* organization the attacker controls, not that it is authorized to touch the `sha` referenced in the body; `drop_unhandled_event` only filters unregistered event types; `ExplicitParameters` in `StatusHandler.params` validates the shape of `sha`/`state`/etc. but performs no repository-ownership check. The test file's existing `:state` tests (`test/controllers/webhooks_controller_test.rb` lines 42-73) always use `repository_params` matching the same tenant as the commit under test, so the cross-tenant case is never exercised.

### Impact Explanation
An attacker who owns/controls one repository already integrated with Shipit (i.e., some org with a `webhook_secret`/GitHub App config known/derivable to them for their own repo) can forge a `status` event naming a `sha` belonging to a completely different, victim repository/stack. This creates a `Status` row on the victim's commit, can flip its computed state (e.g., to `success`), and can trigger `stack.schedule_merges`, `deployable_status` hooks, and continuous-delivery scheduling for a tenant the attacker never authenticated against. This is a payload for one repository mutating another's commit/stack state — matching the Critical category ("a payload for one repository mutating another's stack, commit, task or team").

### Likelihood Explanation
The attacker needs no Shipit credentials, sessions, or secrets belonging to the victim. The only precondition is that the attacker controls (or is a legitimate low-privilege contributor to) some repository that is already onboarded to Shipit, so that `Shipit.github(organization: repository_owner)` resolves and `verify_webhook_signature` succeeds for that org (which does not require the victim's secret at all). The target `sha` is trivially obtainable from any public commit page. This is a low-cost, fully repeatable attack — any number of forged status events can be posted, against any sha the attacker can discover.

### Recommendation
In `StatusHandler#process`, scope the commit lookup by the repository named in the payload rather than by `sha` alone, e.g. use the inherited `stacks` scope (`stacks.flat_map(&:commits)` or `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`) so a match is only made against commits belonging to stacks whose `Repository` corresponds to `payload.dig('repository', 'full_name')` — mirroring the pattern already used by `PullRequest::*Handler`.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb`):
1. Stub signature verification as done in existing tests (`GithubHook.any_instance.stubs(:verify_signature).returns(true)` and/or the standard `repository_params`/org stub).
2. Create/reuse two distinct fixtures: `shipit_commits(:first)` belonging to `shipit_stacks(:shipit)` (victim), and a second, unrelated `Repository`/`Stack` (attacker-controlled, e.g. `shipit_stacks(:cyclimse)`).
3. Build a `status` payload where `repository` matches the attacker's own repo (`repository_params` for the attacker's org/repo, distinct from `shipit`'s), but `sha` equals `shipit_commits(:first).sha`.
4. Assert:
   - Binding LHS: `verify_signature` succeeds because `Shipit.github(organization: attacker_org)` matches the attacker's own signed payload.
   - Binding RHS (expected/correct): `commit.stack.repository.owner` (`shipit`) != attacker's `repository.owner`.
   - `assert_no_difference 'shipit_commits(:first).statuses.count'` should hold under a fixed implementation, but currently `assert_difference 'shipit_commits(:first).statuses.count', 1` succeeds, demonstrating the missing repository-scope check.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks.rb (L6-23)
```ruby
      def default_handlers
        {
          'push' => [Handlers::PushHandler],
          'pull_request' => [
            Handlers::PullRequest::OpenedHandler,
            Handlers::PullRequest::ClosedHandler,
            Handlers::PullRequest::ReopenedHandler,
            Handlers::PullRequest::EditedHandler,
            Handlers::PullRequest::AssignedHandler,
            Handlers::PullRequest::LabeledHandler,
            Handlers::PullRequest::UnlabeledHandler,
            Handlers::PullRequest::LabelCapturingHandler
          ],
          'status' => [Handlers::StatusHandler],
          'membership' => [Handlers::MembershipHandler],
          'check_suite' => [Handlers::CheckSuiteHandler]
        }
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

**File:** db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb (L1-10)
```ruby
class IndexCommitsOnStackIdAndSha < ActiveRecord::Migration[5.1]
  def change
    add_index :commits, %i(sha stack_id), unique: true
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
