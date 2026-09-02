### Title
`StatusHandler#process` resolves `Commit` records by `sha` alone with no repository scope, allowing a shared-SHA webhook from one repository to mutate another repository's `Commit`/`Status` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` looks up commits via `Commit.where(sha: params.sha)` with no join or filter against the webhook's `repository.full_name`. Any commit SHA shared between two Shipit-tracked repositories (e.g. a fork sharing history with its upstream, both onboarded as separate `Repository`/`Stack` records) will have its `Status` updated by a webhook that only authenticated against one of them.

### Finding Description
The core binding the audit asks about — `commit.stack.repository.full_name == payload['repository']['full_name']` — is never enforced anywhere in the handler chain.

`Handler#stacks`/`#repository_name` exist as helpers in the base class [1](#0-0)  and other handlers (e.g. `PullRequest::ClosedHandler`, `UnlabeledHandler`) explicitly resolve `repository = Shipit::Repository.from_github_repo_name(params.repository.full_name)` and scope their target through `repository.review_stacks` / `repository.stacks` before acting [2](#0-1) . `StatusHandler` does none of this:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [3](#0-2) 

`params` for `StatusHandler` only requires `sha`/`state`/etc. and does not even require `repository` at all [4](#0-3) , so the repository field of the payload is never consulted to scope the `Commit` lookup. `Commit#sha` has no uniqueness constraint scoped or otherwise enforced against `Repository`; a `Commit` row belongs to a `Stack` which belongs to a `Repository` [5](#0-4) , but the SHA namespace is effectively global across all stacks.

**Path to exploitation**: `WebhooksController#create` verifies the GitHub webhook signature only against `Shipit.github(organization: repository_owner)`, i.e. it authenticates that the payload really came from GitHub for that specific owner/org — it does not, and cannot, prevent the payload's SHA from colliding with a commit belonging to a different repository/stack [6](#0-5) . An attacker who owns a repository that is a fork of (or otherwise shares git history with) a victim's Shipit-tracked repository can legitimately trigger a `status` webhook (e.g. via their own CI, or any service posting a commit status to their fork) for a SHA that also exists as a `Commit` row for the victim's stack (identical SHA1 commits occur naturally for any commit present in both the fork and upstream history prior to divergence). Because `StatusHandler` does not check `commit.stack.repository.full_name == payload['repository']['full_name']`, this genuinely-signed webhook for the attacker's own repository updates the `Status` of the victim's `Commit` row, which cascades into `Hook.emit(:commit_status, ...)`, `Hook.emit(:deployable_status, ...)`, and `stack.schedule_merges` / `ContinuousDeliveryJob` on the victim's stack [7](#0-6) .

None of the existing guards close this gap: `verify_signature` only proves the sender owns/controls the source org's webhook secret, not that the SHA is exclusive to that repository; `drop_unhandled_event` and the `ExplicitParameters` schema only validate payload shape, not repository/commit ownership.

### Impact Explanation
A `Status`/`create_status_from_github!` write lands on a `Commit` belonging to a `Stack`/`Repository` that never authenticated the request. This can flip a victim commit from pending/failure to success, unblocking `deployable?`/`blocked?` checks and triggering `stack.schedule_merges` and `ContinuousDeliveryJob.perform_later(stack)`, i.e. an unauthorized deploy path on a repository the attacker does not control. This is repeatable against any pair of Shipit-tracked repositories that share commit history (very common for fork-based PR workflows), matching the Critical category "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy."

### Likelihood Explanation
Preconditions: both the victim repository and an attacker-controlled repository (typically a fork) must be onboarded as Shipit `Repository`/`Stack` records, and they must share at least one commit SHA (trivial for forks that share history with upstream, or before the fork diverges). The attacker only needs the ability to have a commit-status webhook fired for their own repository, something any repository owner/collaborator can trigger (via their own CI/status API), with no Shipit credentials required. This is low-cost and repeatable.

### Recommendation
Scope the `Commit` lookup in `StatusHandler#process` by the webhook's repository, e.g. require `repository.full_name` in the params schema and filter via `stacks.flat_map(&:commits)` or `Commit.joins(stack: :repository).where(sha: params.sha, shipit_repositories: { full_name: params.repository.full_name })`, mirroring the pattern already used in `PullRequest::ClosedHandler`/`UnlabeledHandler` that scope through `Repository.from_github_repo_name`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "process does not update statuses for commits belonging to a different repository" do
  repo1 = shipit_repositories(:shipit)
  repo2 = create_repository(name: 'other-repo') # distinct Repository
  stack1 = create_stack(repository: repo1)
  stack2 = create_stack(repository: repo2)

  shared_sha = 'a' * 40
  commit1 = stack1.commits.create!(sha: shared_sha, message: 'shared')
  commit2 = stack2.commits.create!(sha: shared_sha, message: 'shared')

  payload = {
    'sha' => shared_sha,
    'state' => 'success',
    'context' => 'ci',
    'repository' => { 'full_name' => stack1.github_repo_name }
  }

  Shipit::Webhooks::Handlers::StatusHandler.call(payload)

  assert_equal commit1.stack.repository.full_name, payload['repository']['full_name']
  # Binding under test: every touched Commit's stack.repository must equal the webhook repository.
  assert_empty Shipit::Status.where(commit_id: commit2.id),
    "expected no status written for commit belonging to a different repository (stack2), " \
    "but StatusHandler wrote one because Commit.where(sha:) is unscoped by repository"
end
```
This test fails on current code because `StatusHandler#process` writes a `Status` for `commit2` (repo2's commit) even though the webhook payload's `repository.full_name` is `stack1.github_repo_name`.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-59)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end

          def review_stack
            @review_stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
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

**File:** app/models/shipit/commit.rb (L11-11)
```ruby
    belongs_to :stack
```

**File:** app/models/shipit/commit.rb (L366-386)
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
      new_status
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
