This confirms the divergence: every other webhook handler (`PushHandler`, `CheckSuiteHandler`) scopes its work through the `Handler#stacks` helper, which resolves stacks strictly via `Repository.from_github_repo_name(payload.dig('repository', 'full_name'))` [1](#0-0) , tying the mutated stack to the repository named in the authenticated payload. `StatusHandler#process`, however, bypasses this entirely and resolves target commits/stacks by a bare, repository-unscoped `Commit.where(sha: params.sha)` lookup [2](#0-1) , and the `commits` table's uniqueness constraint is `(sha, stack_id)`, not `sha` alone [3](#0-2) , i.e. the schema explicitly permits the same SHA to exist under multiple different stacks/repositories.

### Title
Cross-tenant `Stack#enable_ci!`/`Status` mutation via repository-unscoped SHA lookup in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up target commits solely by `sha` across the entire `commits` table, with no scoping to the repository/organization that authenticated the webhook. Because the `commits` table allows the same `sha` to exist under different stacks (unique on `[sha, stack_id]`, not `sha` alone), a webhook correctly signed by attacker-controlled org A can create a `Status` on a commit belonging to victim stack B and trigger `Status#after_create` → `commit.stack.enable_ci!` on B, a stack the attacker never authenticated for.

### Finding Description
The claimed binding is: `stack_governed_by_authenticating_org == stack_whose_enable_ci!_is_invoked`. This holds for `PushHandler` and `CheckSuiteHandler`, which both route through `Handler#stacks`, itself derived from `payload.dig('repository','full_name')` resolved via `Repository.from_github_repo_name` [1](#0-0) [4](#0-3) [5](#0-4) . `StatusHandler` does not use `stacks` at all: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [2](#0-1) . The controller's `verify_signature` only checks the signature against `Shipit.github(organization: repository_owner)`, where `repository_owner` is read from the attacker-supplied `payload['repository']['owner']['login']` [6](#0-5) [7](#0-6) ; it never restricts which `Commit`/`Stack` records the handler is allowed to touch. So an attacker who owns a Shipit-registered org/repo (e.g., a fork of the victim's public repo, which shares upstream commit SHAs by construction) can send a `status` webhook, correctly signed with their own org's `webhook_secret`, whose `sha` matches a `Commit` row that actually belongs to the victim's stack (found because `commits` is only unique per `[sha, stack_id]`, not globally). `commit.create_status_from_github!` → `add_status` → `statuses.replicate_from_github!(stack_id, ...)` [8](#0-7)  creates the `Status` under the **victim commit's real `stack_id`**, and `Status#after_create :enable_ci_on_stack` fires `commit.stack.enable_ci!` on the victim stack [9](#0-8) , plus writes attacker-controlled `state`/`description`/`context` onto the victim's commit status, which feeds `Commit#deployable?`/`blocked?` used for deploy gating [10](#0-9) . None of `verify_signature`, `ExplicitParameters` schema, or model validations check that the resolved `Commit`/`Stack` belongs to the authenticated repository — they only validate signature-vs-claimed-org and field shapes.

### Impact Explanation
The attacker can force `Stack#enable_ci!` (a cache write toggling CI-enabled state, `Rails.cache.write(ci_enabled_cache_key, true)`) [11](#0-10)  and inject a fabricated `Status` row (arbitrary state/description/context/target_url) onto a commit belonging to a stack/repository they never authenticated for. This is a cross-repository mutation of another tenant's commit/CI state via a webhook payload verified against a different organization's secret — matching the Critical category "a payload for one repository mutating another's stack, commit, task or team." The attack is repeatable against any stack whose commits happen to share a SHA with a repository the attacker controls (most straightforwardly, forks of the victim's public repository, since forked commits retain identical SHAs for shared history).

### Likelihood Explanation
Preconditions: the attacker must control a GitHub org/repo already registered with Shipit (own `webhook_secret`/app installation) — a normal, unprivileged capability for anyone who can register their own org with the Shipit instance or fork/mirror a tracked public repo. The victim stack must have a `Commit` row with a SHA also reachable by the attacker's own controlled repo (trivial via forking, since git preserves SHAs across forks — no cryptographic SHA-1 collision is required). No victim secrets, sessions, or elevated roles are needed; the attacker only ever authenticates as themselves. This is straightforward and repeatable per matching SHA.

### Recommendation
Scope `StatusHandler#process` the same way as `PushHandler`/`CheckSuiteHandler`: resolve commits only within `stacks` (i.e., `stacks.joins(:commits).merge(Commit.where(sha: params.sha))` or equivalent), so the affected `Stack` must belong to the repository named in `payload['repository']['full_name']` that was actually signature-verified, rather than a global `Commit.where(sha:)` lookup.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "process does not mutate a stack outside the authenticated repository" do
  victim_stack = shipit_stacks(:shipit)          # ignore_ci: false
  colliding_sha = 'deadbeef' * 5
  victim_commit = victim_stack.commits.create!(sha: colliding_sha, message: 'x', author: shipit_users(:walrus), committer: shipit_users(:walrus), authored_at: Time.now, committed_at: Time.now)

  attacker_stack = shipit_stacks(:cyclimse)      # different repository/org
  attacker_stack.commits.create!(sha: colliding_sha, message: 'x', author: shipit_users(:walrus), committer: shipit_users(:walrus), authored_at: Time.now, committed_at: Time.now)

  Rails.cache.delete(victim_stack.ci_enabled_cache_key)
  refute victim_stack.ci_enabled?

  payload = ExplicitParameters::Parameters.define {
    requires :sha, String; requires :state, String
    accepts :description, String; accepts :target_url, String
    accepts :context, String; accepts :created_at, String
  }.parse!(sha: colliding_sha, state: 'success', context: 'attacker/ci')

  # Binding under test: stack authenticated by attacker's org (attacker_stack)
  # must equal stack whose enable_ci! fires. It does not:
  Shipit::Webhooks::Handlers::StatusHandler.call(payload)

  assert victim_stack.reload.ci_enabled?, "victim_stack.enable_ci! fired even though only attacker_stack's org authenticated the webhook"
end
```

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb (L1-5)
```ruby
class IndexCommitsOnStackIdAndSha < ActiveRecord::Migration[5.1]
  def change
    add_index :commits, %i(sha stack_id), unique: true
  end
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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L227-237)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end

    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
    end
```

**File:** app/models/shipit/status.rb (L18-40)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

    delegate :broadcast_update, to: :commit

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
    end

    private

    def enable_ci_on_stack
      commit.stack.enable_ci!
    end
```

**File:** app/models/shipit/stack.rb (L579-581)
```ruby
    def enable_ci!
      Rails.cache.write(ci_enabled_cache_key, true)
    end
```
