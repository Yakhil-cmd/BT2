### Title
`StatusHandler#process` applies GitHub status updates to commits without verifying the webhook's repository owns that commit - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Finding Description
The broken binding is: `commit.stack.repository.full_name == payload.dig('repository', 'full_name')` should hold before a status webhook is allowed to mutate that commit's state, but `StatusHandler#process` never checks it.

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [1](#0-0) 

This queries `Commit` globally by `sha` across the entire installation, with no filter on which repository/stack the webhook payload actually belongs to. Contrast this with the base `Handler` class and other handlers (e.g. `PullRequest::OpenedHandler`), which explicitly resolve the acting `Repository` via `Repository.from_github_repo_name(payload.dig('repository', 'full_name'))` and scope all subsequent lookups (`stacks`, `repository.review_stacks`, etc.) to that repository before doing anything: [2](#0-1) [3](#0-2) 

`WebhooksController#verify_signature` only authenticates that the raw payload bytes are validly signed for the *organization* named in `params.dig('repository', 'owner', 'login')` (`repository_owner`) - it never checks that the sha or commit referenced in the payload belongs to that same repository: [4](#0-3) 

Git commit SHA-1s are computed purely from commit content (tree, parents, author/committer, message, timestamps) - they are portable across any repository that shares that exact commit object, most trivially a fork of the target repository. An attacker who owns/forks repository B, and who has a legitimately configured (signed) webhook relationship with Shipit for B, can therefore:
1. Fork/mirror victim repository A (or otherwise obtain a repo containing an identical commit object, e.g. one that shares history with A).
2. Cause GitHub to emit (or directly forge/replay, since only B's org signature is checked) a `status` event for repository B referencing that shared `sha`, with `state: "success"`.
3. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, which matches the `Commit` row that belongs to victim stack A (created when that same commit landed on A), and calls `commit.create_status_from_github!(params)` on it — writing a forged `success` status onto stack A's commit despite the request never being scoped to, or authenticated for, stack A or repository A.
4. That triggers `Status#schedule_continuous_delivery` → `Commit#schedule_continuous_delivery`, which checks `deployable? && stack.continuous_deployment? && stack.deployable?` [5](#0-4)  — now true because of the forged status — and enqueues `ContinuousDeliveryJob.perform_later(stack)` for stack A.
5. `ContinuousDeliveryJob` invokes `Stack#trigger_continuous_delivery`, which calls `next_commit_to_deploy` and `trigger_deploy`, ultimately spawning a `Command`/deploy `Task` for stack A's commit using stack A's `GITHUB_TOKEN` and deploy environment: [6](#0-5) 

None of the listed guards prevent this: `verify_signature` only checks the org-level HMAC of the payload bytes, not repo/commit binding; `drop_unhandled_event`/`ExplicitParameters` only validate the shape of the `status` event, not its ownership of the sha; there is no `require_permission!`, `stacks` scope, or model validation anywhere in `StatusHandler`, `Status`, or `Commit#create_status_from_github!` that ties the incoming payload's repository to the commit being updated.

### Impact Explanation
A payload correctly signed for repository B (attacker-controlled) mutates a `Status`/`Commit` record belonging to a different, victim stack A, and can trigger an unauthorized deploy of stack A using stack A's `GITHUB_TOKEN` and deploy `Command`. This matches the explicitly listed Critical category: "a payload for one repository mutating another's stack, commit, task or task" and "an unauthorized deploy". The attack is repeatable against any stack whose commits happen to share a SHA with a commit reachable by the attacker's own repo (most easily achieved by forking the victim repo, which is the normal, unprivileged GitHub workflow), and is not limited to one victim — any tenant stack with `continuous_deployment` enabled and a matching shared commit is exploitable this way.

### Likelihood Explanation
Preconditions: victim stack A has `continuous_deployment: true`, an undeployed commit whose real CI is still pending/unresolved, and that commit's SHA is also reachable in a repository the attacker controls (trivial via forking, since git SHAs are content-derived and shared across forks/clones with identical history). The attacker needs their own repo/org to have a working (legitimately signed) webhook relationship with the Shipit instance — a normal, unprivileged state for any GitHub App installation on their own account — and simply needs to cause a `status` event referencing the shared sha (e.g., via their own CI, a script, or a direct API call as an owner of their own repo). No Shipit session, API token, or GitHub secret is required. Cost is low and the exploit is repeatable per matching commit.

### Recommendation
In `StatusHandler#process` (and any other sha-keyed handler), resolve the `Repository`/`Stack` scope from `payload.dig('repository', 'full_name')` first (as the base `Handler#stacks` helper already does), and restrict the `Commit.where(sha: ...)` lookup to commits belonging to stacks under that repository (e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or an equivalent `stack_id IN (...)` scoping), rejecting/ignoring any status update whose payload repository does not match the commit's own stack's repository.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb (conceptual)
test "status webhook from repository B cannot forge a status on a commit belonging to stack A" do
  stack_a = shipit_stacks(:shipit)              # repository "shopify/shipit-engine"
  stack_a.update!(continuous_deployment: true)
  commit = stack_a.commits.last                  # pending real CI, undeployed

  forged_payload = ExplicitParameters::Parameters.new(
    sha: commit.sha,
    state: 'success',
    context: 'ci/travis',
    branches: [{ name: stack_a.branch }],
    repository: { full_name: 'attacker/forked-repo' }  # NOT stack_a's repository
  )

  Command.any_instance.expects(:start).never # tightened assertion for a fixed version;
  # on the vulnerable version this fires ContinuousDeliveryJob for stack_a:
  assert_enqueued_with(job: Shipit::ContinuousDeliveryJob, args: [stack_a]) do
    Shipit::Webhooks::Handlers::StatusHandler.call(forged_payload)
  end

  assert_equal 'success', commit.reload.state # binding broken: commit mutated by repo B's payload
end
```
Both sides of the binding: `commit.stack.repository.full_name` (`"shopify/shipit-engine"`) vs. `forged_payload.dig('repository','full_name')` (`"attacker/forked-repo"`) — they differ, yet `StatusHandler#process` still updates `commit` and schedules continuous delivery for stack A, confirming the vulnerability.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-39)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
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

**File:** app/models/shipit/stack.rb (L210-229)
```ruby
    def trigger_continuous_delivery
      return if cached_deploy_spec.blank?

      commit = next_commit_to_deploy

      if should_resume_continuous_delivery?(commit)
        continuous_delivery_resumed!
        return
      end

      if should_delay_continuous_delivery?(commit)
        continuous_delivery_delayed!
        return
      end

      begin
        trigger_deploy(commit, Shipit.user, env: cached_deploy_spec.default_deploy_env)
      rescue Task::ConcurrentTaskRunning
      end
    end
```
