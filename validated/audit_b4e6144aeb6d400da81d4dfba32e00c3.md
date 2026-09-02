Confirmed: `webhook_secret` is configured per-organization/app (`Shipit.github(organization: repository_owner)`, `lib/shipit/github_app.rb:44-50,76-83`), and `verify_signature` only proves the request was authentically sent by that organization's GitHub App/webhook secret [1](#0-0) . Nothing about this proves anything about which `Commit`/`Stack` rows get touched. Compare `PushHandler`, which correctly scopes mutations via `stacks.not_archived.where(branch:)` — i.e., it resolves the target `Stack`s strictly from the verified `payload['repository']['full_name']` through `Handler#stacks`/`Repository.from_github_repo_name` [2](#0-1) [3](#0-2) . `StatusHandler#process`, in contrast, never calls `stacks` or reads `repository_name` at all — it does a bare `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [4](#0-3) .

`Commit` has no uniqueness validation on `sha` at all, scoped or global — `sha` is just a plain column [5](#0-4) , so two different `Stack`s (different repositories/tenants) can each hold a `Commit` row with an identical `sha` (e.g., both import the same upstream commit). `create_status_from_github!` then writes a `Status` scoped to `stack_id` taken from `commit.stack_id`, not from the payload's repository [6](#0-5) , and `Status.replicate_from_github!` just `find_or_create_by!(stack_id:, state:, ...)` with no repository check [7](#0-6) .

The broken binding, stated explicitly: `payload.dig('repository','full_name')` (the org whose secret verified the request) == `commit.stack.repository.full_name` for every `Commit` row matched by `Commit.where(sha: params.sha)`. This holds trivially for the first (colliding-repo) commit but is never checked, and does not hold, for the second tenant's commit — its repository never appears anywhere in the payload, yet its `Stack`'s `Status` table is written.

None of the listed guards intervene: `verify_signature` only authenticates the sending organization, not the set of `Commit`/`Stack` rows mutated; `drop_unhandled_event` and the `ExplicitParameters` schema only validate shape of `sha`/`state`/etc., not repository scoping; there is no `force_github_authentication`, `User#authorized?`, or `stacks` scope call anywhere in `StatusHandler`.

### Title
Cross-tenant Status write via SHA-collision in `StatusHandler#process` bypasses repository scoping - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves target commits purely by `sha` across the entire `commits` table, ignoring the verified webhook's `repository.full_name`. Any two `Stack`s (belonging to different, unrelated GitHub organizations/tenants) that happen to hold a `Commit` row with the same `sha` will both receive a `Status` write from a single webhook that was only cryptographically verified for one of those organizations.

### Finding Description
The broken binding: `payload.dig('repository','full_name')` == `commit.stack.repository.full_name` for each `Commit` returned by `Commit.where(sha: params.sha)`. This is required for the mutation to be authorized-by-the-signer, but `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) never checks it — unlike sibling handlers such as `PushHandler`, which resolve mutation targets exclusively through `Handler#stacks`, itself derived from `Repository.from_github_repo_name(repository_name)` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`).

Root cause: `Commit#sha` carries no uniqueness constraint, scoped or otherwise (`app/models/shipit/commit.rb`), so identical `sha` values legitimately exist across unrelated `Stack`s (e.g., two orgs vendoring/cherry-picking the exact same upstream commit object with identical tree/parent/author/committer/timestamp — an ordinary occurrence, not a cryptographic SHA-1 collision). `Commit#create_status_from_github!` (`app/models/shipit/commit.rb:165-169`) and `Status.replicate_from_github!` (`app/models/shipit/status.rb:24-33`) both operate purely off the `Commit`/`stack_id` found via that unscoped lookup, writing into whichever `Stack`'s `Status` table that `Commit` belongs to.

Attack flow: attacker legitimately owns/operates repository A, hooked to Shipit with its own GitHub App/webhook secret. Attacker performs an unmodified cherry-pick of an existing upstream commit into repository A (or otherwise causes repository A to reference a commit sha already present in tenant B's `Stack`). GitHub emits (or the attacker replays/crafts via their controlled repo) a `status` webhook for that sha, signed with A's `webhook_secret`. `verify_signature` passes (it only checks A's secret against A's payload) — `app/controllers/shipit/webhooks_controller.rb:24-30`. `StatusHandler#process` then matches every `Commit` with that sha, including tenant B's, and calls `create_status_from_github!` on it, writing a `Status` row scoped to B's `stack_id` — a record B's own repository/organization never authenticated.

Existing guards fail because they operate at the wrong layer: `verify_signature` authenticates the sender's organization but says nothing about which `Stack` rows may be touched; `ExplicitParameters` only validates the shape of `sha`/`state`/etc.; there is no repository-membership check anywhere in this handler.

### Impact Explanation
A single valid, signed webhook from organization A causes an unauthorized `Status` row to be written under organization B's `Stack`, matching the "payload for one repository mutating another's ... commit ... or task" Critical category. Since `Status` creation can flip a commit's `deployable?` state and trigger `schedule_continuous_delivery`/`ProcessMergeRequestsJob` (`app/models/shipit/status.rb:18-19`, `app/models/shipit/commit.rb` webhook-transition tests), this is not merely an inert extra DB row — it can move B's commit toward being considered CI-green and eligible for continuous deployment, without B's CI ever running or B's webhook secret being used. The attack is repeatable against any repository pair that happens to share a `Commit#sha`, and the blast radius spans all tenants hosted on the same Shipit instance.

### Likelihood Explanation
Requires: (1) attacker controls a real repository hooked into Shipit (so they can produce a genuinely-signed `status` webhook), and (2) a `Commit` with an identical `sha` already exists under a different tenant's `Stack` — realistic for shared/vendored/cherry-picked commits, submodule commits, or monorepo-derived repos split into multiple Shipit-tracked `Stack`s, not requiring an actual SHA-1 collision. No privileged Shipit role, session, or secret of the victim tenant is needed. Feasibility is moderate to high in any deployment where multiple tracked repositories can plausibly share commit history/objects.

### Recommendation
In `StatusHandler#process`, scope the `Commit` lookup to the stacks resolved from the verified payload's repository, mirroring `PushHandler`: replace `Commit.where(sha: params.sha)` with something like `stacks.flat_map(&:commits).where(sha: params.sha)` or `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`, so only commits belonging to the authenticated repository's own stacks can receive the status write.

### Proof of Concept
Minitest plan (e.g., `test/models/shipit/webhooks/handlers/status_handler_test.rb`):
1. Create two `Stack`/`Repository` fixtures under different organizations, `stack_a` (owned repo, webhook_secret_a) and `stack_b` (unrelated tenant).
2. Create `Commit` `commit_a` under `stack_a` and `Commit` `commit_b` under `stack_b`, both with `sha: "deadbeef..."` (same value).
3. Build a `status` payload with `sha: "deadbeef..."`, `state: "success"`, and `repository.full_name` pointing only to `stack_a`'s repo.
4. Call `Shipit::Webhooks::Handlers::StatusHandler.call(payload)` directly (or POST through the controller with signature stubbed valid only for `stack_a`'s org).
5. Assert: `commit_a.statuses.count` increased by 1 (expected/legitimate) AND `commit_b.statuses.count` also increased by 1 (the bug) — i.e., `assert_difference('commit_b.reload.statuses.count', 1) { StatusHandler.call(payload) }`, proving `stack_b`'s `Status` table was mutated despite `stack_b`'s repository never appearing in, or authenticating, the payload.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/commit.rb (L1-90)
```ruby
# frozen_string_literal: true

module Shipit
  class Commit < Record
    include DeferredTouch

    RECENT_COMMIT_THRESHOLD = 10.seconds

    AmbiguousRevision = Class.new(StandardError)

    belongs_to :stack
    has_many :statuses, -> { order(created_at: :desc) }, dependent: :destroy, inverse_of: :commit
    has_many :check_runs, -> { order(created_at: :desc) }, dependent: :destroy, inverse_of: :commit
    has_many :commit_deployments, dependent: :destroy
    has_many :release_statuses, dependent: :destroy
    belongs_to :merge_request, inverse_of: :merge_commit, optional: true

    deferred_touch stack: :updated_at

    before_create :identify_merge_request
    after_commit { broadcast_update }
    after_create { stack.update_undeployed_commits_count }

    after_commit :schedule_refresh_statuses!, :schedule_refresh_check_runs!, :schedule_fetch_stats!,
                 :schedule_continuous_delivery, on: :create

    belongs_to :author, class_name: 'User', optional: true, inverse_of: :authored_commits
    belongs_to :committer, class_name: 'User', optional: true, inverse_of: :commits
    belongs_to :lock_author, class_name: 'User', optional: true, inverse_of: false

    def author
      super || AnonymousUser.new
    end

    def author=(user)
      super(user.presence)
    end

    def committer
      super || AnonymousUser.new
    end

    def committer=(user)
      super(user.presence)
    end

    def lock_author
      super || AnonymousUser.new
    end

    def lock_author=(user)
      super(user.presence)
    end

    scope :reachable, -> { where(detached: false) }

    delegate :broadcast_update, :github_repo_name, :hidden_statuses, :required_statuses, :blocking_statuses,
             :soft_failing_statuses, to: :stack

    def self.newer_than(commit)
      return all unless commit

      where('id > ?', commit.try(:id) || commit)
    end

    def self.older_than(commit)
      return all unless commit

      where('id < ?', commit.try(:id) || commit)
    end

    def self.since(commit)
      return all unless commit

      where('id >= ?', commit.try(:id) || commit)
    end

    def self.until(commit)
      return all unless commit

      where('id <= ?', commit.try(:id) || commit)
    end

    def self.successful
      preload(:statuses).to_a.select(&:success?)
    end

    def self.detach!
      Commit.where(id: ids).update_all(detached: true)
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

**File:** app/models/shipit/status.rb (L24-33)
```ruby
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
