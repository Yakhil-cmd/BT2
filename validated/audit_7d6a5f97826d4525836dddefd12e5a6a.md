This confirms the finding. `CheckSuiteHandler` and `PushHandler` both scope through `Handler#stacks`, which resolves `Repository.from_github_repo_name(repository_name)&.stacks` before touching any commit [1](#0-0) , but `StatusHandler#process` looks up `Commit.where(sha: params.sha)` globally with no repository/stack scoping whatsoever [2](#0-1) .

### Title
Global, unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` lets a status webhook from repository B mutate commit/stack state belonging to repository A - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves the target commit purely by SHA across the entire Shipit database, without verifying that the webhook's `repository.full_name` matches the repository that owns the commit/stack. Any `status` webhook whose payload passes `WebhooksController#verify_signature` for *some* trusted GitHub organization/repository will apply its state to every `Commit` row in Shipit sharing that SHA, including commits belonging to unrelated stacks, which can trigger `Status#schedule_continuous_delivery` → `Commit#schedule_continuous_delivery` → `ContinuousDeliveryJob` → `Stack#trigger_continuous_delivery` for a stack the payload never authenticated against.

### Finding Description
**Broken binding (equality that should hold but doesn't):**
`status.stack_id == Repository.from_github_repo_name(payload.repository.full_name).stacks.pluck(:id)` — i.e., a `Status` record created from a webhook should only ever attach to commits belonging to the repository named in that webhook's payload. Instead, the code enforces only: `status.commit.sha == payload.sha`, with no repository check at all.

**Code path:**
1. `WebhooksController#create` dispatches the parsed JSON payload to registered handlers for the `status` event after `verify_signature` succeeds for the organization derived from the payload's `repository.owner.login` [3](#0-2) .
2. `StatusHandler#process` then runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [2](#0-1) . Unlike `PushHandler` and `CheckSuiteHandler`, which both use `Handler#stacks` (derived from the payload's own `repository.full_name`) to scope the update to the correct repository's stacks [4](#0-3) [5](#0-4) , `StatusHandler` never calls `stacks` or filters by `repository_name` at all.
3. `Commit#create_status_from_github!` calls `add_status { statuses.replicate_from_github!(stack_id, github_status) }`, creating a `Status` scoped to `commit.stack_id` — the victim stack's own `stack_id`, not the payload's repository [6](#0-5) .
4. `Status` model fires `after_commit :schedule_continuous_delivery`, which calls `commit.schedule_continuous_delivery`, and if `deployable? && stack.continuous_deployment? && stack.deployable?` it enqueues `ContinuousDeliveryJob` [7](#0-6) [8](#0-7) .
5. `ContinuousDeliveryJob#perform` calls `stack.trigger_continuous_delivery`, which builds and runs a `Deploy` (a `Task` subclass) via `trigger_deploy` → `Command#start` using the stack's own `GITHUB_TOKEN`/deploy credentials [9](#0-8) .

**Why the fix works elsewhere but not here:** `PushHandler`/`CheckSuiteHandler` both resolve stacks strictly through `Handler#stacks`, tying the mutation to the exact repository named in the (signature-verified) payload. `StatusHandler` breaks this pattern and queries `Commit` globally by SHA, so it is the only handler capable of writing state for a repository other than the one that authenticated the webhook.

**Attacker requirement / feasibility caveat:** Because `WebhooksController#verify_signature` HMAC-validates the payload against the webhook secret configured for the organization in `repository.owner.login` [10](#0-9) , the attacker cannot forge a signature for an arbitrary unrelated org; they need GitHub itself to emit a validly-signed `status` event for a repository within an organization Shipit already trusts (per `Shipit.github_app_config`) [11](#0-10) . This is realistic when the GitHub App is installed org-wide ("all repositories"): a low-privileged member with only repo-creation rights (not a Stack/repository maintainer) can create a new repository B in that trusted org, push a commit that is bit-for-bit identical (same tree/parent/author/committer metadata, hence identical SHA1) to a pending commit on victim stack A in repository A of the same org, and have a CI/status integration post a `success` status against that SHA from repository B. Shipit's `StatusHandler` then applies that status to stack A's commit as well, because it never checks which repository the status came from.

### Impact Explanation
A signed webhook payload scoped to repository B is used to write a `Status` record and drive `Commit#deployable?` to `true` for a commit belonging to a *different* repository/stack (A) that never authenticated it — this is exactly the "payload for one repository mutating another's stack, commit" Critical category. If stack A has `continuous_deployment?` enabled, this results in an unauthorized `Deploy`/`Task` being triggered and `Command#start` executing with stack A's deploy credentials/`GITHUB_TOKEN`, i.e. an unauthorized deploy. The blast radius is bounded to stacks/repositories that share the same trusted GitHub organization as the attacker-controlled repository and that happen to contain a commit with the identical SHA (requiring the attacker to reproduce an exact commit object, not merely guess a SHA) — this is a real but non-trivial precondition, not a blind SHA-guessing attack.

### Likelihood Explanation
Preconditions: (1) the Shipit-configured GitHub App/org must be installed broadly enough that a low-privileged org member can create/push to a new repository under it and have GitHub sign events for that repository with the same webhook/app config Shipit trusts; (2) the attacker must produce a commit object with an identical SHA1 to a real pending commit on the victim stack (achievable by copying the exact commit — e.g. forking/duplicating it — since git hashes are content-addressed, not repository-scoped); (3) victim stack A must have `continuous_deployment` enabled and no other Shipit-side deploy gating blocks it. This is more elaborate than a simple forged-signature attack, but requires no secrets, no session, and no maintainer/API-client access — it is fully reachable by an unprivileged actor able to create a repo in a trusted GitHub org and control its content/CI status.

### Recommendation
Scope `StatusHandler#process` to the repository named in the payload, mirroring `PushHandler`/`CheckSuiteHandler`: replace `Commit.where(sha: params.sha)` with a scan restricted to `stacks.flat_map(&:commits).where(sha: params.sha)` (or `Commit.joins(stack: :repository).where(sha: params.sha, shipit_repositories: { id: repository.id })`), so that a status event can only ever attach to commits whose stack belongs to the repository that emitted the webhook.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb` or extending `test/controllers/webhooks_controller_test.rb`):
1. Create `repository_a` / `stack_a` (continuous_deployment: true, no active tasks) and `repository_b` (unrelated repo, different `full_name`), both under the same trusted GitHub org key used by `verify_signature`.
2. Create `commit = stack_a.commits.create!(sha: "deadbeef", ...)` representing the most recent undeployed commit, with no existing statuses (pending real CI).
3. Stub `Command#start` (Mocha) so no real process spawns.
4. Build a `status` webhook payload with `repository.full_name = repository_b.full_name`, `sha = "deadbeef"`, `state = "success"`.
5. POST to `/webhooks` with a valid signature for `repository_b`'s org (or directly invoke `Shipit::Webhooks::Handlers::StatusHandler.call(payload)` to bypass HTTP signature plumbing while still proving the model-layer flaw).
6. Assert the equality that should have held but didn't: `assert_not_equal repository_b.stacks.pluck(:id), [commit.reload.statuses.last.stack_id]` — i.e. assert `commit.statuses.last.stack_id == stack_a.id` even though the payload named `repository_b`.
7. Assert `ContinuousDeliveryJob` is enqueued for `stack_a` (`assert_enqueued_with(job: ContinuousDeliveryJob, args: [stack_a])`), proving the cross-repository payload triggered a deploy attempt on stack A.

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
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

**File:** app/controllers/shipit/webhooks_controller.rb (L10-49)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end

    private

    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
    end

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

**File:** app/models/shipit/status.rb (L18-44)
```ruby
    after_create :enable_ci_on_stack
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

**File:** lib/shipit.rb (L196-200)
```ruby
  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
```
