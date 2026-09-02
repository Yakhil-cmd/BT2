I have sufficient evidence to confirm this finding. `StatusHandler#process` queries `Commit.where(sha: params.sha)` globally across the entire `commits` table with no repository/stack scoping, unlike every other handler (`PushHandler`, `CheckSuiteHandler`, and all `PullRequest::*Handler`s) which explicitly scope via `stacks` (derived from `Repository.from_github_repo_name(repository_name)`) or `repository.review_stacks`.

### Title
Cross-tenant Status forgery via unscoped `Commit.where(sha:)` lookup - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits by `sha` alone across the entire `commits` table, with no filter on the repository/organization that authenticated the webhook. Any attacker who owns a GitHub repository with a Shipit webhook configured (and thus can produce a validly-signed `status` event for their own org) can write a `Status` record onto a commit belonging to a completely unrelated stack, provided the shas collide (trivial for shared history, forks/templates, or well-known empty git objects).

### Finding Description
The claimed binding is: `verify_signature`'s `repository_owner` (used only to select the `GithubApp` for HMAC verification) should equal the repository scope that `StatusHandler#process` mutates. In `app/controllers/shipit/webhooks_controller.rb`, `verify_signature` picks `Shipit.github(organization: repository_owner)` [1](#0-0)  and then `create` fans the parsed payload out to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [2](#0-1) . This only authenticates *that the sender is a valid webhook source for `repository_owner`'s org* — it says nothing about which stack/commit the handler is allowed to mutate.

`StatusHandler#process` never consults `repository_name`/`stacks` at all:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [3](#0-2) 

Contrast with the base `Handler#stacks` helper, which every other stack-mutating handler uses to scope to the repository named in the payload:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end
``` [4](#0-3) 

`PushHandler` [5](#0-4)  and `CheckSuiteHandler` [6](#0-5)  both use `stacks` (repository-scoped) before touching any commit. All `PullRequest::*Handler`s similarly resolve `Shipit::Repository.from_github_repo_name(params.repository.full_name)` before acting, e.g. [7](#0-6) . `StatusHandler` is the sole handler mutating records purely by a payload-supplied SHA with zero repository binding, even though the `status` payload includes `repository.full_name` per GitHub's schema (unused by this handler and not required in its `params` block, unlike sibling handlers' `params` blocks).

**Exploit flow:** Attacker owns repo `attacker/repo` with a Shipit webhook configured on an org for which they have legitimate signing rights (they configured the webhook secret themselves, or the org's GitHub App is shared and Shipit trusts any repo under that org — either way `verify_signature` succeeds for their own webhook). They send a `status` event where `sha` equals a commit sha that also exists in `victim-org/other-repo`'s tracked stack (shared via fork/template lineage, or a known non-unique object like the empty tree `4b825dc642cb6eb9a060e54bf8d69288fbee4904`). `Commit.where(sha: ...)` matches across *all* stacks system-wide, and `commit.create_status_from_github!(params)` writes a `Status` for the victim's commit [8](#0-7) , which cascades into `Status#schedule_continuous_delivery` and, via `Commit#add_status`, `stack.schedule_merges` when state is `pending`/`success` [9](#0-8) , and `Status#enable_ci_on_stack` [10](#0-9) . This can flip a commit's CI state to `success`, trigger `ContinuousDeliveryJob` on a stack with `continuous_deployment: true` [11](#0-10) , or enqueue merge-queue processing (`ProcessMergeRequestsJob`) for a stack the attacker has no rights over, as shown in existing same-repo test behavior [12](#0-11) .

**Why existing guards fail:** `verify_signature` authenticates the org of the *sender's own* repo, not the org owning the *target* commit's stack; there is no `require_permission!`/`authorized?`/`stacks`-scope check anywhere in `StatusHandler`, `Handler#initialize`, or `Handler.call` [13](#0-12) . `ExplicitParameters` only validates the shape of the payload, not authorization. `Commit` has no uniqueness constraint on `sha` alone (confirmed absent in `app/models/shipit/commit.rb`), so a collision across stacks is architecturally possible, not merely theoretical.

### Impact Explanation
An attacker who authenticated only for their own repository/org can write a `Status` record for a commit belonging to a different tenant's stack, altering that stack's perceived CI/deploy-status and triggering downstream automation (`ContinuousDeliveryJob`, `ProcessMergeRequestsJob`, CI-enablement) without any authorization check against the victim's stack — a payload for one repository mutating another's stack/commit, matching the Critical "payload for one repository mutating another's stack, commit, task or team" category. It is repeatable against any repository/stack pair that ever shares a commit sha with the attacker's own repo.

### Likelihood Explanation
Requires: (1) Shipit configured with the engine mounted and a `status` webhook enabled for at least one repo the attacker legitimately controls, and (2) an existing sha collision between the attacker's repo and a victim stack's tracked commits (trivially satisfiable via forks/templates sharing history, or via well-known empty git objects present in many repos). No GitHub team membership, Shipit session, or API token is needed — only the ability to send one authenticated `status` webhook for the attacker's own repo, which is entirely within an unprivileged GitHub repo owner's normal capability.

### Recommendation
Scope `StatusHandler#process` to the repository that sent the webhook: require `repository.full_name` in the `params` schema (as sibling handlers do) and filter via `stacks.flat_map(&:commits).where(sha: params.sha)` or `Repository.from_github_repo_name(params.repository.full_name)&.stacks&.joins(:commits)&.where(commits: { sha: params.sha })`, mirroring the `Handler#stacks` pattern used elsewhere, so a status can never be written to a commit outside the sending repository's own stacks.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
require 'test_helper'

module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerTest < ActiveSupport::TestCase
        test "StatusHandler mutates commits regardless of the sending repository" do
          victim_commit = shipit_commits(:first) # belongs to some victim stack/repo
          shared_sha = victim_commit.sha

          # Attacker's payload claims a *different* repository than the victim's stack,
          # simulating a validly-signed webhook for the attacker's own org/repo.
          attacker_payload = {
            'sha' => shared_sha,
            'state' => 'success',
            'repository' => { 'full_name' => 'attacker/unrelated-repo' }
          }

          assert_difference -> { victim_commit.statuses.count }, 1 do
            StatusHandler.call(attacker_payload)
          end
          # Demonstrates: no repository/stack check ties the mutation to the sender.
        end

        test "sibling handlers do scope to the sending repository (contrast)" do
          # PushHandler / CheckSuiteHandler use Handler#stacks -> Repository.from_github_repo_name
          assert_includes Handler.private_instance_methods, :stacks
          refute_includes StatusHandler.instance_method(:process).source_location.first, 'stacks'
          # StatusHandler#process body contains no reference to `stacks` or `repository_name`
          source = File.read(Rails.root.join('..', 'app/models/shipit/webhooks/handlers/status_handler.rb'))
          refute_match(/stacks|repository_name|repository\.full_name/, source)
        end
      end
    end
  end
end
```

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L15-24)
```ruby
        def self.call(params)
          new(params).process
        end

        attr_reader :params, :payload

        def initialize(payload)
          @payload = payload
          @params = self.class.param_parser.parse!(payload)
        end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-34)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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

**File:** app/models/shipit/commit.rb (L366-384)
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
```

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```

**File:** app/models/shipit/status.rb (L42-44)
```ruby
    def schedule_continuous_delivery
      commit.schedule_continuous_delivery
    end
```

**File:** test/models/commits_test.rb (L763-777)
```ruby
    test "#add_status schedule a MergeMergeRequests job if the commit transition to `pending` or `success`" do
      commit = shipit_commits(:second)
      github_status = OpenStruct.new(
        state: 'success',
        description: 'Cool',
        context: 'metrics/coveralls',
        created_at: 1.day.ago.to_formatted_s(:db)
      )

      assert_equal 'failure', commit.state
      assert_enqueued_with(job: ProcessMergeRequestsJob, args: [@commit.stack]) do
        commit.create_status_from_github!(github_status)
        assert_equal 'success', commit.state
      end
    end
```
