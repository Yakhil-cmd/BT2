### Title
`StatusHandler#process` resolves commits by SHA only, ignoring repository scope, allowing cross-tenant Status forgery - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits with `Commit.where(sha: params.sha)` and attaches the incoming (attacker-controlled) GitHub status to every matching commit across the entire instance, regardless of which repository/organization the signed webhook actually came from. Every other handler in this codebase (`PushHandler`, the `PullRequest::*` handlers) restricts itself to the `stacks` helper scoped by `payload.dig('repository', 'full_name')`; `StatusHandler` does not, so a validly-signed webhook from repository A can write a `Shipit::Status` onto a commit belonging to stack B's repository, flipping `Commit#deployable?` for B.

### Finding Description
The binding that must hold is: for every `Status` created from a webhook, `status.commit.stack.repository.full_name == payload.dig('repository', 'full_name')` (the repo whose signature authenticated the request). Tracing the code shows this is not enforced.

- `WebhooksController#verify_signature` only proves the request was signed by `repository_owner` taken from the *same* payload used to look up commits [1](#0-0) . It authenticates the sender, it does not scope what the sender is allowed to mutate.
- `Handler` base class exposes a repository-scoped `stacks` helper (`Repository.from_github_repo_name(repository_name)&.stacks`) that other handlers use to constrain writes [2](#0-1) . `PushHandler#process` uses it: `stacks.not_archived.where(branch:).find_each { ... }` [3](#0-2) .
- `StatusHandler#process` does **not** use `stacks` at all; it does a global lookup by SHA: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [4](#0-3) .
- `Commit` belongs to exactly one `Stack`/repository, but the table has no uniqueness constraint on `sha` across stacks [5](#0-4) , so any commit whose SHA is duplicated in another stack (fork network / shared history / cherry-picked identical commit content) will silently receive the forged status.
- `create_status_from_github!` → `statuses.replicate_from_github!` persists the `Status` row keyed on `stack_id`, `state`, etc. with no column recording which repository/org actually authenticated the write [6](#0-5) ; the schema for `statuses` confirms there is no owner/organization/creator column, only `stack_id`, `commit_id`, `state`, `context`, `target_url`, `description` [7](#0-6) .
- The created `Status` immediately drives real effects: `after_create :enable_ci_on_stack` and `after_commit :schedule_continuous_delivery` fire against the *victim's* stack/commit [8](#0-7) , and `Commit#deployable?` becomes `success? && !blocked?` [9](#0-8) , which is exactly what the "ignore_ci?" framing in the question describes — but the flip happens purely because the write itself is unauthenticated for stack B, not because of any special interaction with `ignore_ci?`.

Exploit flow: attacker forks (or otherwise obtains a repo sharing commit history with) a repository that already has a Shipit stack B. The attacker installs/points a GitHub webhook for the `status` event from their own repository A at the Shipit host — this is entirely self-service and requires no Shipit secret, since GitHub computes and sends the valid signature for repo A's organization. The attacker sets a `success` status via the GitHub API on their own repo A for a commit SHA that is shared with stack B (identical commit content/parents/timestamps). GitHub delivers the signed `status` webhook; `verify_signature` passes because it only checks that the payload's `repository_owner` (A) matches the signature — it never checks whether the commits being mutated belong to A. `StatusHandler#process` then finds and mutates the commit row under stack B as well, because the lookup is `Commit.where(sha: ...)` with no repository filter.

### Impact Explanation
An attacker who controls only their own repository can write a `Shipit::Status` record (state, context, description, target_url) onto a commit belonging to an unrelated stack/repository/organization they never authenticated for, as long as a SHA collision exists (forks, shared history, or intentionally re-created identical commits). This can flip `Commit#deployable?` to true on the victim stack, unblock `blocking_statuses` checks, trigger `schedule_continuous_delivery`, and enable an unauthorized deploy path on stack B. This is a cross-tenant write matching the Critical category "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy." It is repeatable against any stack whose commits share a SHA with a repository the attacker controls.

### Likelihood Explanation
Preconditions: the attacker must own/administer a real GitHub repository (trivial, self-service, forking is free) and be able to point a `status` webhook at the Shipit host (also self-service if the Shipit deployment allows any repository/org to register — common in multi-tenant/GitHub-App Shipit installs). The hard constraint is producing a commit SHA collision with the victim's tracked commit, which is realistic for forked repositories (identical history until divergence) and for setups where the same underlying repository backs multiple Shipit stacks (e.g., staging/production environments tracking the same commits). No Shipit secret, session, or API token is required at any point.

### Recommendation
Scope `StatusHandler#process` (and any other handler resolving by SHA) to the webhook's own repository, mirroring `PushHandler`: replace `Commit.where(sha: params.sha)` with a lookup restricted to `stacks` (the repository-scoped association already provided by `Handler#stacks`), e.g. `stacks.flat_map { |stack| stack.commits.where(sha: params.sha) }`, so a status can never be attached to a commit outside the repository that authenticated the webhook.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
require 'test_helper'

module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerCrossTenantTest < ActiveSupport::TestCase
        test "status webhook from repo A must not create a Status on a commit owned by repo B" do
          repo_a = Repository.create!(owner: 'attacker-org', name: 'attacker-repo')
          repo_b = Repository.create!(owner: 'victim-org', name: 'victim-repo')
          stack_a = Stack.create!(repository: repo_a, environment: 'production')
          stack_b = Stack.create!(repository: repo_b, environment: 'production')

          shared_sha = 'a' * 40
          commit_a = stack_a.commits.create!(sha: shared_sha, message: 'shared history')
          commit_b = stack_b.commits.create!(sha: shared_sha, message: 'shared history')

          payload = {
            'sha' => shared_sha,
            'state' => 'success',
            'context' => 'ci/forged',
            'repository' => { 'full_name' => 'attacker-org/attacker-repo' },
          }

          assert_no_difference -> { commit_b.statuses.count } do
            StatusHandler.call(payload)
          end
          # Binding under test: status.commit.stack.repository.full_name == payload['repository']['full_name']
          # Currently FAILS: commit_b (victim-org/victim-repo) also receives the forged status
          # because StatusHandler#process uses Commit.where(sha:) with no repository scope.
        end
      end
    end
  end
end
```
Running this against the current `StatusHandler#process` implementation shows `commit_b.statuses.count` increases by 1 even though the webhook was signed only for `attacker-org/attacker-repo`, proving the cross-tenant write.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/commit.rb (L11-12)
```ruby
    belongs_to :stack
    has_many :statuses, -> { order(created_at: :desc) }, dependent: :destroy, inverse_of: :commit
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```

**File:** app/models/shipit/status.rb (L23-33)
```ruby
    class << self
      def replicate_from_github!(stack_id, github_status)
        find_or_create_by!(
          stack_id:,
          state: github_status.state,
          description: github_status.description,
          target_url: github_status.target_url,
          context: github_status.context,
          created_at: github_status.created_at
        )
      end
```

**File:** test/dummy/db/schema.rb (L293-303)
```ruby
  create_table "statuses", force: :cascade do |t|
    t.integer "commit_id", limit: 4
    t.string "context", limit: 255, default: "default", null: false
    t.datetime "created_at"
    t.text "description", limit: 65535
    t.integer "stack_id", null: false
    t.string "state", limit: 255
    t.string "target_url", limit: 255
    t.datetime "updated_at"
    t.index ["commit_id"], name: "index_statuses_on_commit_id"
  end
```
