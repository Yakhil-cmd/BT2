### Title
`StatusHandler#process` applies GitHub `status` webhooks to any commit sharing a `sha`, with no scoping to the repository that sent the webhook - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves target commits with `Commit.where(sha: params.sha)`, an unscoped, engine-wide query that ignores which repository/organization the incoming, signature-verified webhook actually came from. Every sibling handler (`PushHandler`, `CheckSuiteHandler`) instead scopes through the `stacks` helper, which is derived from `Repository.from_github_repo_name(payload.dig('repository','full_name'))`. `StatusHandler` alone skips this scoping, so a validly signed webhook from repository A can write a `Status` (and recompute `deployable?`) for a commit belonging to repository B's stack whenever the two share a `sha`.

### Finding Description
Binding claimed: `{commits authorized by attacker's webhook_secret} == {commits an attacker-controlled webhook payload can actually mutate via StatusHandler#process}`. Tracing the code shows this binding is **broken**, independent of the `locked?` question raised in the prompt.

- `WebhooksController#verify_signature` selects the HMAC secret via `Shipit.github(organization: repository_owner)`, where `repository_owner` comes straight from the attacker-controlled payload (`params.dig('repository','owner','login')`), and only proves the request was signed for *that organization*. [1](#0-0) [2](#0-1) 
- Once the signature for the attacker's own org/repo verifies, `Shipit::Webhooks.for_event('status')` dispatches to `StatusHandler`, whose `process` does:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [3](#0-2) 
This query is **not** scoped by `payload.dig('repository','full_name')` at all — contrast with `PushHandler#process` and `CheckSuiteHandler#process`, both of which resolve `stacks` from `Repository.from_github_repo_name(repository_name)` before touching any commit: [4](#0-3) [5](#0-4) [6](#0-5) 
- `Commit` has no repository-derived scoping baked into the model either — `belongs_to :stack` is the only ownership link, and `Commit.where(sha: ...)` runs across the entire `commits` table for every stack in the installation. [7](#0-6) 
- `create_status_from_github!` unconditionally creates the `Status` and recomputes derived state (`deployable?`, `schedule_continuous_delivery`, `ProcessMergeRequestsJob`), regardless of which repository's stack the commit belongs to: [8](#0-7) [9](#0-8) [10](#0-9) 

Exploit flow: attacker owns/controls a repository R (their own fork or a repository under an organization they legitimately administer and that is separately onboarded to the same Shipit instance). GitHub sends a correctly signed `status` webhook for R (attacker can produce this legitimately, e.g. by posting a commit status to their own repo via the GitHub API - no Shipit secret needed, only their own repo's normal GitHub permissions). If a commit with the same `sha` also exists in victim repository V's stack (a routine occurrence for forks, mirrors, or shared history prior to divergence), `StatusHandler#process` finds and updates *that* commit too, because the query only matches on `sha`, never on `repository_name`. `locked?` is a manual, per-commit flag the victim operator sets independently of this attack surface — an unlocked victim commit is the normal, default state, so the missing repository check is reachable in the common case, not just an edge case.

The `locked?` short-circuit in `deployable?` is a red herring for this specific finding: the actual defect is that `StatusHandler#process` never establishes repository ownership before mutating a shared-sha commit, so nothing — not signature verification, not `locked?`, not any model validation — confines the effect of the webhook to the attacker's own stack.

### Impact Explanation
An attacker who fully controls only repository R can, via a webhook that is legitimately signed for R, write a `Status` row onto a commit belonging to stack V (a different repository/tenant they do not control), flip `Commit#deployable?` to true for V, and trigger `ProcessMergeRequestsJob`/`schedule_continuous_delivery` on V's stack — i.e., "a payload for one repository mutating another's stack, commit, task" and potentially an unauthorized deploy/merge, matching the Critical impact bucket. This is repeatable for every shared-sha commit and works against any victim stack sharing history with a repository the attacker administers.

### Likelihood Explanation
Requires: (1) the attacker legitimately owns/administers a GitHub repository already onboarded to the same Shipit instance (fork, mirrored repo, or any repo under an org with a GitHub App/webhook secret they have valid access to), and (2) a commit `sha` shared between that repository and the victim's stack (common for forks/mirrors before divergence, or repos deliberately tracked as multiple Shipit stacks). No Shipit secrets, sessions, or API tokens are needed beyond the attacker's own repository's ability to emit a real, correctly-signed webhook. Given typical multi-tenant Shipit deployments (many repos/orgs onboarded, forks common), this is practically reachable.

### Recommendation
Scope `StatusHandler#process` the same way as `PushHandler`/`CheckSuiteHandler`: resolve `stacks` via `Repository.from_github_repo_name(payload.dig('repository','full_name'))` and restrict the commit lookup to `stacks.flat_map(&:commits).where(sha: params.sha)` (or equivalent join), so only commits belonging to the repository that actually sent the webhook can be updated.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
require 'test_helper'

module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerCrossTenantTest < ActiveSupport::TestCase
        test "process must not update a commit belonging to a different repository than the webhook's" do
          victim_stack = shipit_stacks(:shipit)          # repo: shopify/shipit2, e.g.
          attacker_stack = shipit_stacks(:cyclimse)       # different repository entirely

          shared_sha = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
          victim_commit = victim_stack.commits.create!(sha: shared_sha, message: 'victim commit', author: AnonymousUser.new, authored_at: Time.now, committer: AnonymousUser.new, committed_at: Time.now)
          attacker_stack.commits.create!(sha: shared_sha, message: 'attacker commit', author: AnonymousUser.new, authored_at: Time.now, committer: AnonymousUser.new, committed_at: Time.now)

          refute victim_commit.locked?
          refute_predicate victim_commit.reload, :deployable? # no success status yet

          attacker_payload = {
            'sha' => shared_sha,
            'state' => 'success',
            'repository' => { 'full_name' => attacker_stack.repository.github_repo_name },
            'branches' => [{ 'name' => attacker_stack.branch }]
          }

          # Binding under test:
          # LHS: commits authorized by attacker's webhook (should be only attacker_stack's commits)
          # RHS: commits actually mutated by StatusHandler#process
          Shipit::Webhooks::Handlers::StatusHandler.call(attacker_payload)

          assert_predicate victim_commit.reload, :deployable?, # LHS != RHS: victim commit mutated by attacker's payload
            "cross-tenant commit mutated by a webhook not scoped to its repository"
        end
      end
    end
  end
end
```
This demonstrates that `StatusHandler#process`'s failure to scope by `payload['repository']['full_name']` (present in `Handler#repository_name`/`#stacks` for other handlers but unused here) lets an attacker-signed webhook for their own repository mutate an unrelated victim commit/stack purely because the `sha` matches, independent of `locked?`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/commit.rb (L11-12)
```ruby
    belongs_to :stack
    has_many :statuses, -> { order(created_at: :desc) }, dependent: :destroy, inverse_of: :commit
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

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```
