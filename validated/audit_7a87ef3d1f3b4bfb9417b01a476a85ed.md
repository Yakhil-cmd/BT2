### Title
`StatusHandler#process` mutates commits across all repositories via unscoped `Commit.where(sha:)` lookup - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` looks up commits solely by `sha` with `Commit.where(sha: params.sha).each`, without ever checking that the commit's `stack`/`repository` matches the `repository.full_name` in the verified webhook payload. Every other handler (e.g. `PushHandler`) uses the base `Handler#stacks` helper, which scopes strictly to `Repository.from_github_repo_name(repository_name)`, but `StatusHandler` bypasses this entirely.

### Finding Description
The claimed binding is: `stacks_mutated_by_webhook == stacks_whose_repository == payload.repository.full_name` (should be ≤ 1). Tracing the code:

- `WebhooksController#verify_signature` only verifies that the raw payload bytes were signed by the secret belonging to `repository_owner` (`Shipit.github(organization: repository_owner)`), i.e. it authenticates *who sent the payload*, not that the `sha` field inside the payload legitimately belongs to that repository: [1](#0-0) 

- `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the parsed JSON straight to `StatusHandler.call`, with no repository binding applied at the controller layer: [2](#0-1) 

- The base `Handler` class provides a correctly-scoped `stacks` helper that other handlers use: [3](#0-2) 
`PushHandler` demonstrates the correct pattern, scoping mutations to `stacks.not_archived.where(branch:)` derived from `repository_name`: [4](#0-3) 

- `StatusHandler#process`, in contrast, never calls `stacks`/`repository_name` at all — it queries `Commit` globally by `sha` and mutates every match regardless of which repository/stack owns that commit row: [5](#0-4) 

- `Commit#create_status_from_github!` performs a real, hook-firing mutation per matched row (creates a `Status`, can flip commit state, trigger `deployable_status`/`commit_status` hooks, and enqueue `ProcessMergeRequestsJob`): [6](#0-5) 
(hook-firing / merge-request side effects confirmed in test): [7](#0-6) 

**Exploit flow:** An attacker who owns/controls a low-privilege repository (or its GitHub App/webhook secret for that org, as an ordinary maintainer of their own repo) sends one signed `status` webhook naming their own `repository.full_name` but with a `sha` value known to also exist as a `Commit.sha` in unrelated victim `Stack`s (e.g. the sha of `git init`'s canonical empty tree, or the initial commit of a widely-forked template/boilerplate repo that many unrelated Shipit-tracked repos share history with, or simply a sha the attacker already knows is present in N stacks by common template/scaffold usage). `verify_signature` passes because the signature is valid for the attacker's own org/repo — it says nothing about the `sha` claim. `StatusHandler#process` then iterates over *every* `Commit` row across the entire installation matching that sha and calls `create_status_from_github!` on each, mutating N victim stacks' commit statuses from a single verified request that only authenticated one repository.

None of the existing guards prevent this: `verify_signature` authenticates the sender's org, not the sha-to-repository binding; `drop_unhandled_event` and the `ExplicitParameters` schema only validate presence/shape of `sha`/`state`/etc., not repository ownership; there is no `stacks`/`repository_name` scoping call anywhere in `StatusHandler`.

### Impact Explanation
A single forged/legitimate-looking webhook for one attacker-controlled repository writes `Status` rows and fires `commit_status`/`deployable_status` hooks and `ProcessMergeRequestsJob` on commits belonging to unrelated tenants' `Stack`s that happen to share a sha. This is a payload for one repository mutating another's commit/stack state — matching the Critical impact category ("a payload for one repository mutating another's stack, commit, task or team"). The blast radius scales with however many stacks contain a commit with the chosen sha (N, unbounded, no `.limit`, no per-repository filter), and is repeatable at will by the attacker for any sha they can identify as shared.

### Likelihood Explanation
Preconditions: attacker only needs the ability to trigger (or forge, if they control a repo with legitimate webhook delivery) a `status` event for a repository they control, and to know/guess a `sha` shared with other tracked stacks — realistic given widely-forked template repositories, monorepo mirrors, or shared initial commits are common. No Shipit session, API token, or secret is required beyond what a legitimate low-privilege repo owner already has (their own repo's ability to emit webhooks/GitHub App installation for their own org). This is a low-cost, highly repeatable attack.

### Recommendation
In `app/models/shipit/webhooks/handlers/status_handler.rb`, scope the `Commit` lookup to the stacks belonging to the payload's repository, mirroring `PushHandler`/base `Handler#stacks`:
```ruby
def process
  Commit.where(sha: params.sha, stack_id: stacks.select(:id)).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb` or via `WebhooksControllerTest`):
1. Create 3 `Stack`s with distinct `Repository`s (`repo_a`, `repo_b`, `repo_c`).
2. Create 3 `Commit` rows, one per stack, all sharing the identical `sha` (e.g. `"4b825dc642cb6eb9a060e54bf8d69288fbee4904"`, the git empty-tree sha).
3. POST a `status` webhook payload naming only `repository.full_name = repo_a` with that shared `sha`, signed/verified for `repo_a`'s org.
4. Assert binding both sides:
   - Before: `stacks_matching_repository = Stack.where(repository: repo_a).count # == 1`
   - After: `commits_mutated = Commit.where(sha: shared_sha).select { |c| c.statuses.any? }.map(&:stack_id).uniq.count`
   - `assert_equal 1, stacks_matching_repository`
   - `assert_equal 3, commits_mutated` (demonstrating the binding is violated: 3 ≠ 1)
5. This proves all 3 `Commit` rows (across 3 distinct victim stacks) received a new `Status` from a single webhook naming only `repo_a`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
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
