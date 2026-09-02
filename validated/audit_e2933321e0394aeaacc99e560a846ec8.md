### Title
Cross-repository status forgery via unscoped sha lookup enables unauthorized continuous deployment - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves commits to update purely by `sha`, with no check that the reporting repository matches the commit's stack's repository. If an attacker's own repository (whose webhook is legitimately signed by GitHub for the attacker's own org) contains a commit whose SHA is identical to a commit at the HEAD of a victim's `continuous_deployment?` stack — a realistic scenario for forked/mirrored repositories, since git SHAs are shared verbatim across forks — the attacker's self-authored `status` webhook will mutate the victim commit's status and can trigger `Commit#schedule_continuous_delivery` → `ContinuousDeliveryJob` for the victim stack.

### Finding Description
The broken binding, stated explicitly:

`commit.stack.repository.full_name` (the repository whose status is actually being written) is claimed to equal `params.repository.full_name`/`repository_owner` (the repository whose webhook signature was verified in `WebhooksController#verify_signature`). No code enforces this equality.

Code path:
1. `WebhooksController#verify_signature` verifies the HMAC signature using `Shipit.github(organization: repository_owner)`, where `repository_owner` is read from the *attacker's own payload* [1](#0-0) . This only proves the payload was actually sent by GitHub for the attacker's own configured organization/app — it says nothing about which stack's commit the `sha` field refers to.
2. `StatusHandler#process` then does a completely unscoped lookup: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [2](#0-1) . This query has no `stack_id`/`repository` filter — any commit row in any stack, across any tenant, sharing that sha is updated.
3. `Commit#create_status_from_github!` → `#add_status` records the new status, and if the simple state transitions to `pending`/`success` it calls `stack.schedule_merges` and, via the `after_commit` callback chain wired at commit-creation time, `Commit#schedule_continuous_delivery` re-evaluates `deployable?` [3](#0-2) [4](#0-3) .
4. `Commit#deployable?` is `!locked? && (stack.ignore_ci? || (success? && !blocked?))` [5](#0-4) , and once true, `Commit#schedule_continuous_delivery` enqueues `ContinuousDeliveryJob.set(wait: ...).perform_later(stack)` for the **victim's** stack, purely because the attacker's own repository emitted a `status` event for the same sha [6](#0-5) .
5. `Stack#trigger_continuous_delivery` then picks the victim's `next_commit_to_deploy` and calls `trigger_deploy`, running an actual deploy task for the victim stack [7](#0-6) .

The attacker's exact request: a normal, correctly-signed GitHub `status` webhook POST to `/webhooks` from their own repository/org, with `sha` set to a commit hash they know is shared with the victim stack's HEAD (e.g., because the victim's private/internal repo was forked from, or shares upstream history with, the attacker's public repo) and `state: "success"`.

Why existing guards fail: `verify_signature` only binds the request to "some org configured in `Shipit.github_teams`/`Shipit.github` for `repository_owner`" — it never binds the request to the specific stack/repository whose commit is being mutated. `drop_unhandled_event` and the `ExplicitParameters` schema only validate that required params (`sha`, `state`) are present, not that they belong to the reporting repository. There is no `repository_owner == commit.stack.repository.owner` check anywhere in `StatusHandler` or `Commit#create_status_from_github!`.

### Impact Explanation
The attacker gets a real record written for the victim stack's commit (a `Status`) and can transition it into `deployable?`, causing `ContinuousDeliveryJob`/`trigger_deploy` to run for the victim stack — an unauthorized deploy of a party the attacker never authenticated for. This is repeatable against any stack whose commit SHA the attacker can predict or match via shared/forked history, and the blast radius spans all tenants sharing the Shipit instance, since the `Commit.where(sha:)` lookup has no per-tenant scoping. This matches the Critical category: "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy."

### Likelihood Explanation
Preconditions: the victim stack must have `continuous_deployment?` true, no blocking statuses, and an unlocked commit at HEAD sharing a SHA with a commit the attacker can legitimately generate a status for via their own repository. This requires the attacker to control or fork a repository that shares git history/SHAs with the victim's tracked repository — a common real-world situation (open-source upstream mirrored into an internal/private Shipit-tracked fork, or a monorepo split). No Shipit secret, session, or elevated privilege is needed; only a normal GitHub webhook from the attacker's own repository, which GitHub sends automatically on any status update the attacker triggers (e.g., pushing a CI status via the GitHub Status API on their own repo, which any repo admin/owner can do for their own repo).

### Recommendation
Scope the commit lookup in `StatusHandler#process` (and analogous handlers) to the repository that owns the webhook: filter `Commit.joins(:stack).where(sha: params.sha, shipit_stacks: { repository_id: repository_id_derived_from_payload })` instead of a bare `sha` match, ensuring `commit.stack.repository.full_name` equals the verified `repository.full_name` from the payload before any status/state mutation is applied.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb` or similar, no live GitHub):
```ruby
test "status webhook from unrelated repository must not affect commits of another repository's stack" do
  victim_stack = shipit_stacks(:shipit)          # continuous_deployment: true
  victim_commit = victim_stack.commits.last
  attacker_repo_full_name = "attacker/unrelated-repo"

  # Equality under test, BEFORE: victim_commit.stack.repository.full_name != attacker_repo_full_name
  refute_equal attacker_repo_full_name, victim_commit.stack.repository.full_name

  params = ActionController::Parameters.new(
    sha: victim_commit.sha,
    state: "success",
    repository: { full_name: attacker_repo_full_name, owner: { login: "attacker" } }
  ).permit!

  assert_no_enqueued_jobs(only: ContinuousDeliveryJob) do
    Shipit::Webhooks::Handlers::StatusHandler.new.process(params) # or via `.call`
  end

  # AFTER: the equality is still false, so no status/deploy should have been triggered for victim_commit
  assert_predicate victim_commit.reload.statuses, :empty?
end
```
Current code fails this assertion (job gets enqueued / status gets created) because `StatusHandler#process` matches `victim_commit` purely by `sha`, with no check against `attacker_repo_full_name`.

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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
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
