This confirms the vulnerability. `Commit` has `belongs_to :stack` and no uniqueness scoping on `sha` visible in the model [1](#0-0) , meaning multiple stacks (different repositories) can independently have `Commit` rows with the identical `sha` value. `StatusHandler#process` queries `Commit.where(sha: params.sha)` globally across *all* stacks with no filtering by the authenticated repository, unlike sibling handlers (e.g. `OpenedHandler`, `ClosedHandler`, `ReopenedHandler`) which explicitly resolve `Shipit::Repository.from_github_repo_name(params.repository.full_name)` before touching any stack-scoped data [2](#0-1) . The base `Handler` class even provides a `stacks` helper scoped by `repository_name` for exactly this purpose [3](#0-2) , but `StatusHandler` never uses it.

### Title
Cross-tenant Status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits by `sha` alone, with no scoping to the repository named in the authenticated webhook payload, then calls `create_status_from_github!` on every matching `Commit` row across the entire installation. An attacker who controls a repository whose `webhook_secret` verifies successfully can push a `status` webhook for a SHA that also exists as a `Commit` in a completely unrelated victim stack, causing a `Status` to be written against that victim commit.

### Finding Description
The broken binding: the question asserts `repository.full_name` in the verified payload (`attacker/evil`) must equal the repository of every `Commit` mutated by the handler, but the actual code enforces no such equality.

`WebhooksController#verify_signature` calls `Shipit.github(organization: repository_owner)` and verifies the signature against `attacker`'s own `webhook_secret` [4](#0-3) . This only proves the request was signed by the org named in the payload (`attacker`) — it says nothing about which `Commit`/`Stack` rows the handler is allowed to touch. `Shipit::Webhooks.for_event('status')` dispatches to `Handlers::StatusHandler` [5](#0-4) .

`StatusHandler#process` then does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [6](#0-5) 

`sha` is not a globally unique column on `Commit` — each `Stack` maintains its own commit history via `belongs_to :stack` [7](#0-6) , so two different stacks (for two different repositories) can legitimately have a `Commit` row with the identical `sha` (e.g., a shared open-source dependency commit, or a deliberately duplicated empty-tree commit). The base `Handler` class exposes a `stacks` scope built from `repository_name` (`payload.dig('repository', 'full_name')`) precisely to prevent cross-repository leakage [3](#0-2) , and other handlers like `OpenedHandler`/`ClosedHandler`/`ReopenedHandler` correctly resolve the specific `Repository` from `params.repository.full_name` before acting on any stack [2](#0-1) . `StatusHandler` does not use `stacks` or `repository_name` at all — it is the odd one out.

`Commit#create_status_from_github!` unconditionally creates a `Status` scoped to that commit's own `stack_id` [8](#0-7) , and `Status.replicate_from_github!` writes `stack_id`, `state`, `context`, etc. directly from the attacker-controlled `github_status` params [9](#0-8) . A newly-created `success` status on a stack can flip `Commit#deployable?`/CI state and trigger `after_create :enable_ci_on_stack`, `schedule_continuous_delivery` [10](#0-9) , potentially unlocking deploys for the victim stack.

Existing guards do not close this gap: `verify_signature` only authenticates the org that owns `attacker/evil`, not which stacks' commits may be mutated; `drop_unhandled_event` and the `ExplicitParameters` schema for `StatusHandler` only require `sha`/`state`/etc. and do not require or validate `repository.full_name` against the matched commits at all (`repository` is not even part of `StatusHandler`'s declared params) [11](#0-10) .

### Impact Explanation
An attacker who owns any repository registered as a Shipit stack (with a valid, self-controlled `webhook_secret` for their own org) can write a `Status` row (`state`, `context`, `description`, `target_url`) onto any `Commit` in any other stack in the installation, as long as they can get a `Commit` row with a colliding `sha` to exist in the victim stack (e.g. by matching a publicly known/shared commit SHA, such as a shared dependency commit or empty-tree commit). This is a cross-tenant write: the authenticated party (`attacker`'s org) never equals the mutated party (`victim/prod`'s stack). Setting `state: 'success'` can flip `deployable?`/CI status and unlock deploy eligibility for the victim stack, and is repeatable against arbitrary target stacks/commits as long as SHA collisions can be arranged. This matches "a payload for one repository mutating another's stack, commit ... task or team" — Critical.

### Likelihood Explanation
The attacker needs: (1) their own repository registered in Shipit as a stack, so they can pass `verify_signature` with their own secret; (2) a target `sha` that is also tracked as a `Commit` in the victim's stack (this can be arranged trivially with an open-source shared dependency commit, a vendored/cherry-picked commit, or by convincing the victim's Shipit to sync a specific commit, since git SHAs are content-addressed and identical content on both sides yields an identical SHA — no cryptographic break required). No GitHub App private key, no victim `webhook_secret`, no session, and no privileged role are required. This is directly reachable via a single unauthenticated (from Shipit's perspective) HTTP POST to `/webhooks`, fully repeatable.

### Recommendation
Scope `StatusHandler#process` to only the commits belonging to the repository named in the verified payload, mirroring the pattern used by the `PullRequest` handlers: require `repository.full_name` in the params schema, and filter with something like `stacks.joins(:commits).where(shipit_commits: { sha: params.sha })` or `Commit.where(sha: params.sha, stack_id: stacks.select(:id))` instead of the current global `Commit.where(sha: params.sha)`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb (conceptual)
test "status webhook for one repository does not create a Status on another repository's commit with the same sha" do
  victim_stack = shipit_stacks(:victim_prod) # repo victim/prod
  attacker_stack = shipit_stacks(:attacker_evil) # repo attacker/evil

  shared_sha = "a" * 40
  victim_commit = victim_stack.commits.create!(sha: shared_sha, ...)
  attacker_stack.commits.create!(sha: shared_sha, ...) # collision, attacker owns this stack

  payload = {
    "sha" => shared_sha,
    "state" => "success",
    "context" => "ci/travis",
    "repository" => { "full_name" => "attacker/evil", "owner" => { "login" => "attacker" } }
  }

  assert_no_difference -> { victim_commit.reload.statuses.count } do
    Shipit::Webhooks::Handlers::StatusHandler.call(payload)
  end

  # Currently FAILS: victim_commit.reload.statuses.last.stack_id == victim_stack.id
  # even though payload's repository.full_name ("attacker/evil") != "victim/prod"
end
```

### Citations

**File:** app/models/shipit/commit.rb (L4-18)
```ruby
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
```

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L49-54)
```ruby

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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

**File:** app/models/shipit/webhooks.rb (L19-19)
```ruby
          'status' => [Handlers::StatusHandler],
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L7-18)
```ruby
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
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

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
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
