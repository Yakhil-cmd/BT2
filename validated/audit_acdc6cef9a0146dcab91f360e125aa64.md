### Title
`StatusHandler#process` writes CI status to any commit sharing a SHA across all repositories, regardless of which repo authenticated the webhook - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` resolves target commits with `Commit.where(sha: params.sha)`, with no filter on `repository`/`stack`, unlike the base `Handler` class which exposes a repo-scoped `stacks` helper (`Repository.from_github_repo_name(repository_name)`). Any commit row in the database that happens to share the attacker-supplied SHA — even one belonging to an entirely different repository/stack — gets its CI status mutated, and downstream effects (`schedule_merges`, `ContinuousDeliveryJob`) fire for that unrelated stack.

### Finding Description
The invariant that should hold is: `commit.stack.github_repo_name == payload['repository']['full_name']` for every commit updated by a status webhook. `StatusHandler#process` breaks this: [1](#0-0) 

It never uses the `stacks` helper defined on the base `Handler` (`Repository.from_github_repo_name(repository_name)&.stacks`), which is exactly what other handlers rely on for repo scoping: [2](#0-1) 

`Commit#sha` is only unique within a `stack_id` (there is no global-uniqueness assumption enforced elsewhere in the model), so `Commit.where(sha: params.sha)` can legitimately return rows belonging to multiple, unrelated stacks/repositories whenever two repos (e.g., a mirror, a fork, or two Shipit stacks tracking the same upstream project) contain a commit with the identical SHA.

`WebhooksController#verify_signature` only proves that the payload was signed by the GitHub App/organization matching the `repository.owner.login` in the *attacker's own* payload — it says nothing about which commits in the DB share that SHA: [3](#0-2) 

So an attacker who owns/controls a repository that is registered under a Shipit-integrated GitHub organization (any repo they can push to and generate a `status` event for, e.g. via a CI integration they configure on their own repo) can legitimately produce a validly-signed `status` webhook for a SHA of their choosing. If that same SHA also exists as a `Commit` row under a victim's stack (plausible for mirrored/forked repositories, monorepo splits, or any workflow where identical commit objects appear in more than one GitHub repository), `Commit#create_status_from_github!` is invoked on the victim's commit: [4](#0-3) 

This calls `add_status`, which updates `Status::Group`, emits `Hook.emit(:deployable_status, ...)`, and — critically — calls `stack.schedule_merges` when the new status is `pending` or `success`, and via `Commit#schedule_continuous_delivery` can enqueue `ContinuousDeliveryJob` if `deployable?` now holds true: [5](#0-4) [6](#0-5) 

None of `verify_signature`, `drop_unhandled_event`, the `ExplicitParameters` schema, or model validations check that the resolved `Commit#stack` belongs to the repository that authenticated the request — the gap is a pure business-logic scoping omission in `StatusHandler#process`.

### Impact Explanation
A payload authenticated for repository A can flip CI status (`success`/`error`/`failure`) on a commit belonging to stack B, tricking `deployable?`/`blocked?` and triggering `stack.schedule_merges` or continuous deployment for stack B — an unauthorized deploy/merge/block on a repository that never authenticated the request. This matches the Critical category "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy, rollback or merge." The `bot_login` configuration only determines the identity used to *execute* the resulting deploy/merge action (i.e., whose GitHub credentials perform the merge/deploy), it does not gate whether the cross-repo write happens — the root cause and exploitability exist independent of `bot_login`, which is an amplifier of consequence, not a required precondition for the invariant violation itself.

### Likelihood Explanation
Exploitability requires the attacker's SHA to coincide with a commit SHA already tracked by a victim stack — this is not attacker-controlled in the general case (SHA is a hash over commit content+parents+metadata), so this is not trivially exploitable against an arbitrary stack. It is realistic in setups where the same commit legitimately propagates into multiple GitHub repositories tracked as separate Shipit stacks (mirrors/forks/vendored subtree syncs), a documented and common CI topology. The attacker also needs their own repo onboarded to the same Shipit-integrated GitHub organization/app so that `verify_signature` passes.

### Recommendation
Scope `StatusHandler#process` to the authenticating repository, mirroring the base `Handler#stacks` pattern, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or joining through `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`, so a status can never be applied to a commit outside the repository that generated the webhook.

### Proof of Concept
```ruby
test "status webhook does not update commits belonging to a different repository sharing the same sha" do
  repo_a = shipit_stacks(:shipit).repository # authenticates the webhook
  repo_b = create_repository(full_name: "victim/other-repo")
  victim_stack = create_stack(repository: repo_b)
  shared_sha = "a" * 40

  create_commit(stack: shipit_stacks(:shipit), sha: shared_sha)
  victim_commit = create_commit(stack: victim_stack, sha: shared_sha)

  payload = {
    "sha" => shared_sha,
    "state" => "success",
    "context" => "ci/build",
    "repository" => { "full_name" => repo_a.full_name, "owner" => { "login" => repo_a.owner } }
  }

  Shipit::Webhooks::Handlers::StatusHandler.call(payload)

  victim_commit.reload
  # Binding under test: victim_commit.stack.github_repo_name == payload['repository']['full_name']
  # This assertion currently FAILS because StatusHandler updates it anyway.
  assert_not victim_commit.statuses.exists?(context: "ci/build", state: "success"),
    "status webhook for repo_a must not mutate commit status belonging to repo_b's stack"
end
```

### Citations

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

**File:** app/models/shipit/commit.rb (L379-386)
```ruby
      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
      new_status
    end
```
