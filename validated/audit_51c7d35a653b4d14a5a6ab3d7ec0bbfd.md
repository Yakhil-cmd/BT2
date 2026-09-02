### Title
Cross-repository status/commit binding: `StatusHandler` matches commits by sha only, with no repository scope check - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits with `Commit.where(sha: params.sha)` and calls `create_status_from_github!` on every match, with no filtering by the webhook payload's `repository.full_name`. Unlike `PushHandler`, which restricts its query via the base `Handler#stacks` helper (`Repository.from_github_repo_name(repository_name)&.stacks`), `StatusHandler` never invokes `stacks` or otherwise checks that the matched `Commit#stack` belongs to the repository that emitted the webhook.

### Finding Description
The broken binding: `webhook.payload['repository']['full_name'] == commit.stack.repository.full_name` should hold for every `Commit` row mutated by a given webhook, but `StatusHandler` never asserts it.

Path:
1. `WebhooksController#create` verifies the HMAC signature only against `Shipit.github(organization: repository_owner)` [1](#0-0)  - this proves the event came from GitHub for that org, not that it is scoped to one specific repository/stack.
2. It then dispatches to `Shipit::Webhooks.for_event('status')` → `Handlers::StatusHandler` [2](#0-1) .
3. `StatusHandler#process` does:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [3](#0-2) 
This query is global across the `commits` table - it is not scoped to `stacks` for the repository named in the payload. Compare with `PushHandler`, which explicitly scopes via `stacks.not_archived.where(branch:)` where `stacks` is `Repository.from_github_repo_name(repository_name)&.stacks` [4](#0-3) [5](#0-4) .
4. `Commit#create_status_from_github!` unconditionally creates a `Status` scoped to `commit.stack_id` [6](#0-5) .
5. `Status` has `after_commit :schedule_continuous_delivery` which calls `commit.schedule_continuous_delivery` [7](#0-6) .
6. `Commit#schedule_continuous_delivery` checks `deployable? && stack.continuous_deployment? && stack.deployable?` and, if satisfied, enqueues `ContinuousDeliveryJob.set(wait: ...).perform_later(stack)` for that commit's own `stack` [8](#0-7) .

Root cause: if two independent `Stack` rows (mirrored repo, or a fork tracked as a separate stack) contain `Commit` rows with an identical sha (which is expected for shared git history/merge commits across forks/mirrors), a single GitHub-signed status webhook originating from *one* of those repositories will iterate and mutate `Commit`/`Status` rows for *both* stacks, and can trigger `ContinuousDeliveryJob` for both stacks' `continuous_deployment` pipelines.

Existing guards do not prevent this: `verify_signature` only authenticates the org/app, not the specific repo [1](#0-0) ; the `ExplicitParameters` schema for `StatusHandler` only validates the shape of `sha`/`state`/etc, not repository ownership [9](#0-8) ; and `Stack#deployable?`/`continuous_deployment?` gate whether a deploy is triggered but do nothing to bind the commit match to the originating repository.

### Impact Explanation
A single forged/legitimate-but-misdirected status event can write `Status` rows into, and schedule `ContinuousDeliveryJob` for, a `Stack` that never authenticated that event - this is a payload for one repository mutating another repository's commit/status/deploy-scheduling state, matching the Critical category ("a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy"). Blast radius scales with N: every `Stack` whose `Commit` table happens to share the sha receives the mutation and a CD scheduling attempt in one shot. If the target stack has `continuous_deployment` enabled and the commit becomes `deployable?`, this results in an unauthorized deploy trigger on a repository that did not send/authenticate that specific status.

### Likelihood Explanation
Requires: (a) two `Stack` records in the same Shipit instance whose `Commit` rows share a sha - realistic for mirrored/monorepo setups or forks tracked as separate stacks, since git commit shas are content-addressed and identical across clones/forks/mirrors for unchanged commits; (b) the attacker being able to cause (or already being able to observe) a legitimately-signed "status" webhook for one of those repositories, e.g., by pushing/opening a PR whose commit sha is shared with the other stack. No Shipit secrets are required - the attacker only needs ordinary GitHub interaction with one of the affected repositories. This is fully repeatable for any sha that happens to collide.

### Recommendation
Scope `StatusHandler#process` to the stacks belonging to the payload's repository, using the same `stacks` helper as `PushHandler`, e.g. `commits = Commit.where(sha: params.sha, stack_id: stacks.select(:id))`, rejecting or ignoring commits belonging to stacks whose repository doesn't match `payload.dig('repository', 'full_name')`.

### Proof of Concept
Minitest plan (no live GitHub):
```ruby
test "status webhook for one repo does not schedule CD for an unrelated stack sharing a sha" do
  stack_a = shipit_stacks(:shipit)                 # repository "org-a/repo-a"
  stack_b = Shipit::Stack.create!(repository: shipit_repositories(:other), environment: 'production', branch: 'master')
  shared_sha = 'deadbeef' * 5

  commit_a = stack_a.commits.create!(sha: shared_sha, ...)
  commit_b = stack_b.commits.create!(sha: shared_sha, ...)
  stack_a.update!(continuous_deployment: true)
  stack_b.update!(continuous_deployment: true)

  payload = {
    'sha' => shared_sha, 'state' => 'success', 'context' => 'ci/travis',
    'repository' => { 'full_name' => stack_a.repository.full_name, 'owner' => { 'login' => 'org-a' } }
  }

  assert_enqueued_with(job: Shipit::ContinuousDeliveryJob, args: [stack_a]) do
    Shipit::Webhooks::Handlers::StatusHandler.call(payload)
  end
  # Binding under test: payload.repository.full_name == commit.stack.repository.full_name
  # Current behavior: stack_b (different repository) also receives a Status and CD job, violating the binding.
  assert_enqueued_with(job: Shipit::ContinuousDeliveryJob, args: [stack_b]) do
    # This should NOT enqueue for stack_b, but currently does
  end
end
```

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
