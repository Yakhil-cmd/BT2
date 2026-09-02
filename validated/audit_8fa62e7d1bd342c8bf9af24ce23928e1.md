### Title
`StatusHandler#process` resolves commits by SHA globally, ignoring the webhook payload's repository, letting an attacker's status webhook trigger `ContinuousDeliveryJob` for an unrelated stack - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits with `Commit.where(sha: params.sha)` with no repository/stack scoping, unlike every other webhook handler in the engine which resolves the target stack through `Repository.from_github_repo_name(payload.repository.full_name)`. Because Shipit commit SHAs are content-addressed and identical across forks/shared history, a signed webhook whose `repository.full_name` names a repo the attacker controls can still mutate the `Status` (and thus `deployable?`) of a `Commit` belonging to a completely different `Stack`, and if that other stack has `continuous_deployment?` enabled, `ContinuousDeliveryJob.perform_later(stack)` is enqueued for a stack the attacker does not own.

### Finding Description
Binding that should hold: `commit.stack == Repository.from_github_repo_name(payload["repository"]["full_name"]).stacks.find_by(commits: sha)` — i.e., the stack whose data gets mutated by a `status` webhook must be the stack that owns the repository named in that verified webhook payload.

Trace:
- `Shipit::WebhooksController#create` parses the JSON body and dispatches to handlers for the event after `verify_signature` checks the HMAC using the *organization*'s webhook secret (`Shipit.github(organization: repository_owner)`), not a per-repository or per-stack credential: [1](#0-0) [2](#0-1) 
- The base `Handler` class exposes a repository-scoped `stacks` helper that every other handler (`PullRequest::OpenedHandler`, `ClosedHandler`, `LabeledHandler`, etc.) uses to resolve `repository.full_name` → `Stack` before acting: [3](#0-2) 
- `StatusHandler`, however, never touches `repository_name`/`stacks`. It resolves the target `Commit` purely by SHA, globally across the entire `commits` table: [4](#0-3) 
- `Commit#create_status_from_github!` then persists the status against `commit.stack_id` (the commit's *real* stack, e.g. `stack_a`), regardless of what repository the payload named: [5](#0-4) 
- `Status#schedule_continuous_delivery` (fired `after_commit` on the new `Status`) calls back into `Commit#schedule_continuous_delivery`: [6](#0-5) 
- `Commit#schedule_continuous_delivery` evaluates `deployable? && stack.continuous_deployment? && stack.deployable?` against `commit.stack` (`stack_a`) and enqueues `ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)` for that stack: [7](#0-6) 

Exploit flow:
1. Attacker controls `repository_b`, which is already onboarded to this Shipit instance (so `Shipit.github(organization: owner_b)` has a valid webhook secret and `verify_signature` will pass for signed payloads originating from that org/app installation — no Shipit secrets needed by the attacker, only a legitimately signed webhook from their own repo, e.g., a CI status they control).
2. `repository_b` shares git history with `repository_a` (e.g., it is a fork, or the attacker cherry-picked/replayed a commit that is bit-for-bit identical to one already tracked in `stack_a`), so a `Commit` with the same `sha` exists in both `stack_a.commits` and (potentially) `repository_b`'s own history.
3. Attacker sends (or triggers via their own CI) a `status` webhook with `repository.full_name = "attacker/repository_b"` and `sha = <shared_sha>`, `state = "success"`.
4. `verify_signature` passes (valid signature for `owner_b`'s org). `StatusHandler#process` runs `Commit.where(sha: shared_sha)`, which returns the `Commit` row belonging to `stack_a` (unrelated stack/repo), and calls `create_status_from_github!` on it.
5. This flips `stack_a`'s commit to `success`/`deployable?` and, if `stack_a.continuous_deployment?` is true, enqueues `ContinuousDeliveryJob.perform_later(stack_a)` — an unauthorized deploy trigger for a stack the attacker never touched or authenticated against.

Why existing guards fail: `verify_signature` only authenticates that the payload came from a GitHub org configured in Shipit — it says nothing about which repository/stack the payload is allowed to mutate. `drop_unhandled_event` and `ExplicitParameters` only validate the shape of the payload (`sha`, `state`, `branches`), not the repository binding. No `force_github_authentication`, `User#authorized?`, `require_permission!`, or `stacks` scoping is applied inside `StatusHandler`, in contrast to the `PullRequest::*Handler` classes which all consistently scope through `Repository.from_github_repo_name(params.repository.full_name)`.

### Impact Explanation
An attacker with control over their own onboarded repository can cause an **unauthorized deploy trigger** (`ContinuousDeliveryJob.perform_later(stack_a)`) for a stack (`stack_a`) belonging to a different tenant/repository that they do not own, purely by causing a colliding-SHA commit status to be posted from their own repo. This matches the Critical impact category "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy." The blast radius is bounded by the precondition of a shared/colliding SHA (typically forks of the same upstream repo, both onboarded as separate Shipit stacks, or any deliberately manufactured shared commit), but wherever that precondition holds it is fully repeatable per request and requires no elevated privilege.

### Likelihood Explanation
Requires: (1) the attacker's own repository already integrated with this Shipit instance under an org Shipit trusts (so a legitimately signed webhook can be produced), and (2) a `Commit` with an identical SHA already tracked under a different `Stack` with `continuous_deployment?` enabled — most plausible for forked repositories that are both tracked by the same Shipit installation, or any scenario where identical commit objects land in two different stacks' histories. This is a realistic and low-cost precondition (fork relationships are extremely common), and the attack is trivially repeatable against any shared-history commit.

### Recommendation
Scope `StatusHandler#process` (and `Commit.by_sha`/`by_sha!` lookups used from webhook contexts) to the repository named in the verified payload, mirroring the `Handler#stacks` pattern used elsewhere, e.g.:
```ruby
def process
  stacks.flat_map(&:commits).select { |c| c.sha == params.sha }.each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
or add a `stack_id`/`repository_id` filter to the `Commit.where(sha: params.sha)` query so it only matches commits belonging to `Repository.from_github_repo_name(payload.dig('repository','full_name'))`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
require 'test_helper'

module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerCrossStackTest < ActiveSupport::TestCase
        include ActiveJob::TestHelper

        test "a status webhook naming repository_b must not trigger CD for stack_a via SHA collision" do
          stack_a = shipit_stacks(:shipit)
          stack_a.update!(continuous_deployment: true)
          shared_sha = stack_a.commits.last.sha

          # Binding under test: ContinuousDeliveryJob is scoped to the stack whose
          # repository is named in the verified payload (repository_b), never stack_a.
          payload = {
            'sha' => shared_sha,
            'state' => 'success',
            'context' => 'ci/travis',
            'created_at' => Time.now.to_formatted_s(:db),
            'branches' => [{ 'name' => stack_a.branch }],
            'repository' => { 'full_name' => 'attacker/repository_b' }
          }

          assert_no_enqueued_jobs(only: ContinuousDeliveryJob) do
            StatusHandler.call(payload)
          end
          # currently FAILS: StatusHandler.call(payload) enqueues
          # ContinuousDeliveryJob.perform_later(stack_a) because Commit.where(sha:)
          # ignores payload['repository']['full_name'] entirely.
        end
      end
    end
  end
end
```
This test demonstrates the divergence: the payload names `repository_b`, yet `ContinuousDeliveryJob` is enqueued for `stack_a`, proving `StatusHandler` does not bind the mutated stack to the authenticated repository in the payload.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-12)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
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

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```

**File:** app/models/shipit/status.rb (L19-44)
```ruby
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

    def schedule_continuous_delivery
      commit.schedule_continuous_delivery
    end
```
