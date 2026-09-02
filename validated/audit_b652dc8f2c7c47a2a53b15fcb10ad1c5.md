### Title
Cross-repository `status` webhook can override a blocking CI status on another tenant's stack via global `Commit.where(sha:)` lookup - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits purely by `sha` across the entire `commits` table, with no scoping to the repository whose signature was verified, unlike every other webhook handler (`PushHandler`, `CheckSuiteHandler`, the `PullRequest` handlers) which all filter through the `stacks` helper tied to `payload.dig('repository', 'full_name')`. If a commit `sha` that exists in victim stack B's undeployed range also exists in a repository that the attacker controls (e.g. a fork sharing pre-fork history, or a mirrored/duplicated commit with identical author/committer/tree/parent metadata), a legitimately GitHub-signed `status` webhook for the attacker's own repository A will create a `Status` row attributed to stack B's `Commit`, corrupting `Commit#status`/`Commit#blocked?` for a tenant the attacker never authenticated against.

### Finding Description
The intended binding is: for every `Status` row written from a webhook, `repository_that_verified_the_webhook (A) == commit.stack.repository (B)`.

`WebhooksController#verify_signature` only checks that the payload was legitimately signed by GitHub *for the organization named in the payload's `repository.owner.login`* ( [1](#0-0) ), it says nothing about which `Commit`/`Stack` records may be mutated. That responsibility is delegated to each handler's `process` method, which is expected to scope through `Handler#stacks`, itself derived from `Repository.from_github_repo_name(repository_name)` where `repository_name` is `payload.dig('repository', 'full_name')` ( [2](#0-1) ). `PushHandler#process` and `CheckSuiteHandler#process` both correctly scope their writes through `stacks` ( [3](#0-2) [4](#0-3) ).

`StatusHandler#process`, however, does not use `stacks` or `repository_name` at all:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [5](#0-4) 

`Commit.where(sha: params.sha)` is a global, unscoped query across the entire `commits` table, spanning every stack/repository tracked by the Shipit instance. Any `Commit` row anywhere whose `sha` matches the value in the (correctly-signed-for-repo-A) payload receives a new `Status` via `create_status_from_github!` → `add_status` → `statuses.replicate_from_github!` ( [6](#0-5) [7](#0-6) ).

`Commit#blocked?` then re-derives `status` from all `statuses_and_check_runs` via `Status::Group.compact`, and `blocking?` is delegated to `status` ( [8](#0-7) [9](#0-8) ). If a newer/higher-priority `success` status is injected this way, the status hierarchy resolves to `success` and `blocked?` becomes `false`, exactly as the question describes.

Exploit flow:
1. Attacker owns/controls GitHub repository A, correctly registered with Shipit (so `Shipit.github(organization: repository_owner)` resolves and `verify_signature` passes for real GitHub-delivered events on A).
2. Attacker arranges for a commit with the same `sha` as the blocking commit in victim stack B's undeployed range to exist in repository A (e.g., a shared pre-fork ancestor commit, or a byte-identical duplicate commit pushed to A).
3. Attacker triggers a real `status` event on A with `state: success` for that `sha` (via GitHub API, CI, etc.), and GitHub delivers a genuinely signed webhook to `POST /webhooks`.
4. `verify_signature` passes because the signature is valid for organization A.
5. `StatusHandler#process` matches the `Commit` row belonging to stack B (not A) purely by `sha` and writes a new `success` `Status` on it.
6. `Commit#status` on stack B recomputes to `success`, `Commit#blocked?` returns `false` on stack B, unblocking deployment despite B's own CI still reporting failure.

None of the existing guards catch this: `verify_signature` validates webhook authenticity per-organization, not per-commit-ownership; `drop_unhandled_event` only checks the event type is registered; the `ExplicitParameters` schema in `StatusHandler` only validates payload shape (`sha`, `state`, etc.), not repository identity ( [10](#0-9) ); there is no model validation tying `Status#stack_id`/`commit_id` to the webhook's originating repository.

### Impact Explanation
A `Status` row is written for a `Commit` belonging to a repository/stack (B) that the attacker's webhook never authenticated against, directly matching the "payload for one repository mutating another's stack/commit" Critical category. This can flip `Commit#blocked?` from `true` to `false` on the victim stack, allowing an unauthorized/unintended deploy of a commit chain that the victim's own CI marked as blocking. The blast radius is any pair of stacks/repositories that happen to share (or can be made to share) an identical commit `sha` — most realistically forks/mirrors of the same upstream, or duplicate pushes of identical commit objects.

### Likelihood Explanation
The attacker needs: (1) control of a GitHub repository A already registered/onboarded in the target Shipit instance (so a real webhook signature validates), and (2) the ability to produce or possess a commit with a `sha` identical to a specific commit in victim stack B's pending/undeployed range. Because git SHA1 is content-addressed (tree + parents + author/committer identity/timestamps + message), an *exact* collision generally requires either a shared git history (fork of the same upstream, common in monorepo/fork-based workflows) or deliberately re-creating an identical commit object with matching authorship/timestamps — feasible when the victim's commit metadata is public (e.g., visible in a public repo). This is not a low-cost blind attack against arbitrary strangers, but it is fully deterministic and repeatable once a matching sha is obtained, requires no secrets, and the request itself (a real GitHub `status` event on the attacker's own repo) is indistinguishable from normal legitimate traffic.

### Recommendation
Scope `StatusHandler#process` to the requesting repository the same way `PushHandler` and `CheckSuiteHandler` do: restrict the `Commit` lookup to `stacks` derived from `Repository.from_github_repo_name(repository_name)`, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`, before calling `create_status_from_github!`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerCrossRepoTest < ActiveSupport::TestCase
        test "status webhook verified for repo A must not override blocking status on stack B's commit with colliding sha" do
          stack_b = shipit_stacks(:shipit) # repository B, e.g. "shopify/shipit-engine"
          stack_b.update!(blocking_statuses: ['ci/travis'])

          colliding_sha = 'a' * 40
          blocking_commit = stack_b.commits.create!(sha: colliding_sha, ...)
          stack_b.commits.create!(sha: 'b' * 40, ...) # newer commit whose #blocked? is under test
          blocking_commit.statuses.create!(stack: stack_b, state: 'failure', context: 'ci/travis')

          assert blocking_commit.blocking?
          # Binding under test: repo_A (payload.repository.full_name) == blocking_commit.stack.repository (B)
          refute_equal 'attacker/repo-A', stack_b.repository.full_name

          payload = {
            'sha' => colliding_sha,
            'state' => 'success',
            'context' => 'ci/travis',
            'branches' => [{ 'name' => stack_b.branch }],
            'repository' => { 'full_name' => 'attacker/repo-A', 'owner' => { 'login' => 'attacker' } }
          }

          StatusHandler.call(payload) # simulates a genuinely-signed webhook for repo A

          blocking_commit.reload
          assert_equal 'success', blocking_commit.status.state # BUG: overridden by cross-repo webhook
          refute blocking_commit.blocked?                       # BUG: victim's blocking CI failure suppressed
        end
      end
    end
  end
end
```
Expected (fixed) behavior: the assertions on `blocking_commit.status.state` and `blocked?` should still show `failure`/`true` because the webhook for `attacker/repo-A` must not be able to mutate a `Commit` belonging to stack B's repository.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L219-237)
```ruby
    delegate :pending?, :success?, :error?, :failure?, :blocking?, :state, to: :status

    def active?
      return false unless stack.active_task?

      stack.active_task.includes_commit?(self)
    end

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

**File:** app/models/shipit/commit.rb (L304-306)
```ruby
    def status
      @status ||= Status::Group.compact(self, statuses_and_check_runs)
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
