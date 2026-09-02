### Title
`StatusHandler#process` matches `Commit` rows across every Stack via unscoped `sha` lookup - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` queries `Commit.where(sha: params.sha)` with no `stack_id` or `repository_id` predicate, then calls `commit.create_status_from_github!(params)` on every match. Since `verify_signature` only authenticates that the payload's own repository/organization owns a valid `webhook_secret`, but never constrains which `Commit` rows the handler can touch, a verified webhook for org A's repository can write a `Status` onto a `Commit` belonging to org B's `Stack` if the two commits share the same `sha`.

### Finding Description
The broken binding, stated explicitly: the code implicitly assumes `Commit.sha == params.sha` implies `Commit.stack.repository.owner == repository_owner(payload)`, but no such constraint exists in the query or anywhere upstream.

Trace:
- `Shipit::WebhooksController#create` parses the raw payload and dispatches to handlers matched by `X-Github-Event`: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [1](#0-0) .
- `verify_signature` resolves `Shipit.github(organization: repository_owner)` from `payload.dig('repository','owner','login')` and validates the HMAC signature against *that* organization's `webhook_secret` [2](#0-1) [3](#0-2) . This proves the payload came from the org that owns the named repository - nothing more. It does not scope the handler's DB access to that repository's stacks.
- `Handler.call(params)` calls `new(params).process`; `Handler#stacks` (used by other handlers like `CheckSuiteHandler`) resolves `Repository.from_github_repo_name(repository_name)&.stacks`, correctly scoping to the verified repository's stacks [4](#0-3) . `CheckSuiteHandler#process` uses this correctly: `stacks.where(branch: ...).each { |stack| stack.commits.where(sha: ...) }` [5](#0-4) .
- `StatusHandler#process`, by contrast, never calls `stacks` or uses `repository_name` at all - it queries the global `Commit` table directly: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [6](#0-5) .
- `Commit#create_status_from_github!` writes a `Status` row scoped to `commit.stack_id`, i.e., whatever `Stack` the matched `Commit` belongs to: `statuses.replicate_from_github!(stack_id, github_status)` [7](#0-6) .
- The DB schema even documents that `sha` is only unique per-stack, not globally: the index is `add_index :commits, %i(sha stack_id), unique: true` [8](#0-7) , confirming multiple `Commit` rows with identical `sha` across different `stack_id`s are an expected, supported condition.

Attacker flow: attacker (or any independent tenant) owns/controls repository B, which happens to share a commit `sha` with repository A (e.g., both forked from a common upstream, or a submodule/cherry-picked commit). Attacker triggers a genuine GitHub `status` event on repository B (e.g., by pushing that commit and letting any CI integration post a status, or by controlling a CI app installed on B that emits the status webhook for the shared sha). The webhook is correctly HMAC-signed by org B's `webhook_secret`, passes `verify_signature`, and is dispatched to `StatusHandler`. Because the handler doesn't filter by repository, the unscoped `Commit.where(sha: ...)` also returns org A's `Commit` row with the identical sha, and it too gets a new `Status` in org A's `Stack` - rewriting CI state that org A never authenticated.

Existing guards that were checked and found insufficient: `verify_signature`/`GitHubApp#verify_webhook_signature` only authenticate the sender's own org, not the target rows touched; `drop_unhandled_event` and `ExplicitParameters` schema (`requires :sha, String`, etc. in `StatusHandler.params`) only validate payload shape, not scope; there is no `stack_id`/`repository_id` predicate anywhere in the query.

### Impact Explanation
A verified `status` webhook from one repository/organization can mutate `Status`/CI state for a `Commit` in a completely unrelated `Stack`/organization, as long as the `sha` collides. This affects `deployable_status`, `commit_status` webhooks fired by `Commit#add_status`, and can flip `Commit#state`, which per the tests can trigger `ContinuousDeliveryJob` and therefore an unauthorized deploy in the victim stack if `continuous_deployment: true` [9](#0-8) . This is a cross-tenant write where one repository's webhook mutates another repository's stack/commit state, matching the "Critical" category (payload for one repository mutating another's stack/commit, or unauthorized deploy).

### Likelihood Explanation
Requires two Stacks whose commit histories intersect (shared submodule, common upstream/fork, cherry-pick, monorepo split, or -- most trivially -- an attacker importing a `Commit` with a chosen `sha` into their own `Stack` matching a target's known/public commit `sha`, since GitHub commit SHAs are public and predictable per public repos). The attacker only needs control over one repository's GitHub webhook delivery (something any repo owner controls, no privileged Shipit access needed) and knowledge of a target commit sha (often public). No Shipit secrets, sessions, or API tokens are needed. This is repeatable at will against any known target sha.

### Recommendation
Scope `StatusHandler#process` to the verified repository's stacks, mirroring `CheckSuiteHandler`: iterate `stacks.flat_map(&:commits).where(sha: params.sha)` or equivalently `stacks.joins(:commits).where(commits: { sha: params.sha })`, using the inherited `stacks` helper (which resolves `Repository.from_github_repo_name(repository_name)&.stacks`) instead of the global `Commit` table.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "status webhook does not leak across stacks with colliding shas" do
  stack_a = shipit_stacks(:shipit) # belongs to org A repository
  stack_b = shipit_stacks(:cyclimse) # belongs to org B repository, independent

  shared_sha = "deadbeef" * 5
  commit_a = stack_a.commits.create!(sha: shared_sha, message: "m", author: shipit_users(:walrus), committer: shipit_users(:walrus))
  commit_b = stack_b.commits.create!(sha: shared_sha, message: "m", author: shipit_users(:walrus), committer: shipit_users(:walrus))

  payload = {
    'repository' => { 'full_name' => stack_b.repository.full_name, 'owner' => { 'login' => stack_b.repository.owner } },
    'sha' => shared_sha,
    'state' => 'success',
    'context' => 'ci/attacker'
  }

  Shipit::Webhooks::Handlers::StatusHandler.call(payload)

  assert_equal 1, commit_b.reload.statuses.where(context: 'ci/attacker').count
  assert_equal 0, commit_a.reload.statuses.where(context: 'ci/attacker').count # currently FAILS: also 1
end
```
Binding to assert: `Status.stack_id == stack_b.id` for every `Status` created by this webhook, and never `Status.stack_id == stack_a.id`. Under current code, `commit_a` also receives the status, proving the vulnerability.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L15-38)
```ruby
        def self.call(params)
          new(params).process
        end

        attr_reader :params, :payload

        def initialize(payload)
          @payload = payload
          @params = self.class.param_parser.parse!(payload)
        end

        def process
          raise NotImplementedError
        end

        private

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

**File:** db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb (L1-5)
```ruby
class IndexCommitsOnStackIdAndSha < ActiveRecord::Migration[5.1]
  def change
    add_index :commits, %i(sha stack_id), unique: true
  end
end
```

**File:** test/models/commits_test.rb (L233-243)
```ruby
    test "updating state to success triggers new deploy when stack has continuous deployment" do
      @stack.reload.update(continuous_deployment: true)
      @stack.deploys.destroy_all

      assert_difference "Deploy.count" do
        assert_enqueued_with(job: ContinuousDeliveryJob, args: [@stack]) do
          @stack.commits.last.statuses.create!(stack_id: @stack.id, state: 'success', context: 'ci/travis')
        end
        ContinuousDeliveryJob.new.perform(@stack)
      end
    end
```
