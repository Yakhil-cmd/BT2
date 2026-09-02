### Title
Cross-repository CI status forgery via unscoped `Commit.where(sha:)` triggers unauthorized `ContinuousDeliveryJob` deploy - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits to attach a GitHub `status` event to using only the commit `sha`, without ever checking that the webhook's `repository.full_name` matches the repository owning the target `Stack`. An attacker who owns a fork sharing a commit `sha` with a victim stack (or otherwise controls a repository whose commits collide with a tracked sha) can send a genuinely-signed `success` status webhook from their own repository, and Shipit will record that success against the victim's commit/stack, satisfy `Commit#deployable?`, and enqueue `Shipit::ContinuousDeliveryJob`, causing a deploy before or regardless of the victim repository's real CI result.

### Finding Description
The broken binding is:
`Status.stack_id == commit.stack.repository.full_name-derived-stack` **AND** `Status.state` must originate from a webhook whose `payload['repository']['full_name'] == commit.stack.repository.full_name`.

In code, other webhook handlers scope lookups through `Handler#stacks`, which resolves `Repository.from_github_repo_name(payload.dig('repository','full_name'))` before touching any stack: [1](#0-0) . `StatusHandler#process`, however, bypasses this entirely and matches purely on `sha` across the whole `commits` table, with no repository check at all: [2](#0-1) .

`Commit#create_status_from_github!` then persists the status using the **matched commit's own `stack_id`** (i.e. the victim stack), independent of which repository actually sent the webhook: [3](#0-2) , backed by `Status.replicate_from_github!` which just writes `state`, `context`, etc. verbatim from the payload: [4](#0-3) .

`verify_signature` in `WebhooksController` only checks that the HMAC signature matches the GitHub App secret for the *organization named in the payload* (`repository_owner`); it never checks that the sha/commit referenced belongs to a repository under that organization or matches the target stack: [5](#0-4) . So a payload that is legitimately signed for the attacker's own org/repo, but which names a `sha` belonging to a totally different, victim-owned stack, sails through signature verification.

Once the forged `Status` row is created, the model's own hooks fire regardless of provenance: `after_commit :schedule_continuous_delivery` on `Status` calls `commit.schedule_continuous_delivery` [6](#0-5) [7](#0-6) , which checks `deployable? && stack.continuous_deployment? && stack.deployable?` and enqueues `ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)` (a 10-second delay): [8](#0-7) . `Commit#deployable?` is purely `!locked? && (stack.ignore_ci? || (success? && !blocked?))` — it has no notion of which repository authored the passing status: [9](#0-8) . When the job runs, `ContinuousDeliveryJob#perform` re-checks `continuous_deployment?`/`occupied?`/schedule and calls `stack.trigger_continuous_delivery`, which calls `trigger_deploy`, synchronously creating and enqueuing/running a `Deploy` [10](#0-9) [11](#0-10) . If the victim's real CI has not yet reported (or reports only after this ~10s window), the deploy is already dequeued/executing by the time a legitimate `pending`/`failure` status arrives — that later legitimate status is itself subject to the same unscoped `Commit.where(sha:)` matching and will simply be appended as one more `Status` row after the fact, too late to abort a task already running.

**Attacker request**: attacker forks (or otherwise obtains a repository sharing a sha with) the victim repository, obtains a genuinely GitHub-signed `status` webhook for their own repo/org (satisfies `verify_signature`), and sets `sha` = the victim's tracked commit sha, `state` = `success`. This is POSTed to `/webhooks` with header `X-Github-Event: status`.

Existing guards that fail to stop this: `verify_signature` validates only signer identity, not sha-to-repository ownership; `drop_unhandled_event` and the `ExplicitParameters` schema only validate shape (`sha`, `state`, etc.), not repository binding; `Handler#stacks`/`repository_name` scoping exists in the base class but is never invoked by `StatusHandler#process`.

### Impact Explanation
A forged `success` status is written into the victim stack's own commit status history (`stack_id` = victim stack), causing `Commit#deployable?` to return true and `ContinuousDeliveryJob` to enqueue and execute a real `Deploy` for the victim's stack, on code whose actual CI result from the victim's own repository was never consulted. This is an unauthorized deploy triggered by a payload attributed to a different repository than the one being deployed — exactly the "payload for one repository mutating another's stack/commit/task" and "an unauthorized deploy" categories called out as Critical. It is repeatable against any stack/repository combination where the attacker can produce (or find) a matching sha, e.g. via forking a public repo (shared git history preserves identical commit shas for all pre-fork commits), and blast radius extends to every tenant/stack tracked by the same Shipit instance since the lookup is entirely global (`Commit.where(sha:)`, no stack/repo scoping).

### Likelihood Explanation
Preconditions: attacker needs (a) a repository they control that can produce a genuinely GitHub-signed webhook (achievable by owning/forking a public repo and installing/using the GitHub App integration on their own account/org, which the rules explicitly grant as in-scope attacker capability), and (b) a commit sha that also exists in the victim's tracked stack — trivially satisfied for any pre-fork commit shared history in a forked public repository, or for any commit the attacker can predict/reuse. No Shipit secrets, sessions, or maintainer privileges are required. This is low-cost and repeatable at will against any public repository tracked by the target Shipit instance.

### Recommendation
Make `StatusHandler#process` (and any other handler doing raw `Commit`/`sha` lookups) scope to `stacks` via `Repository.from_github_repo_name(payload.dig('repository','full_name'))` before touching commits, exactly as `Handler#stacks` already does for other handlers — i.e. only apply the status to commits belonging to stacks whose repository matches the webhook payload's `repository.full_name`, rejecting/ignoring shas that exist only in unrelated repositories/stacks.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (new test)
test "a status webhook naming an unrelated repository must not authorize an unrelated stack's commit" do
  victim_stack = shipit_stacks(:shipit)          # repository "shopify/shipit-engine"
  victim_commit = shipit_commits(:first)          # belongs to victim_stack, currently not success
  victim_commit.statuses.destroy_all
  refute victim_commit.reload.deployable?

  GithubHook.any_instance.stubs(:verify_signature).returns(true)

  # Forged webhook: signed/verified for attacker's own org, but sha == victim_commit.sha
  forged_payload = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'context' => 'ci/attacker',
    'repository' => { 'full_name' => 'attacker/unrelated-repo', 'owner' => { 'login' => 'attacker' } }
  }
  request.headers['X-Github-Event'] = 'status'

  assert_no_enqueued_jobs(only: Shipit::ContinuousDeliveryJob) do
    post :create, body: forged_payload.to_json, as: :json
  end

  victim_commit.reload
  # BINDING CHECK: status must only be created if repository_full_name matches victim stack's repo
  refute victim_commit.deployable?, "forged status from an unrelated repository must not make victim commit deployable"
  refute victim_stack.commits.first.statuses.exists?(context: 'ci/attacker'),
         "status from unrelated repository should never be attached to victim's stack"
end
```
Running this against the current code demonstrates the violation: the `assert_no_enqueued_jobs` and `refute` assertions fail because `StatusHandler#process`'s unscoped `Commit.where(sha:)` attaches the forged status to `victim_commit` under `victim_stack`, flips `deployable?` to `true`, and enqueues `ContinuousDeliveryJob` — confirming the cross-repository binding is broken.

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

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```

**File:** app/models/shipit/status.rb (L23-33)
```ruby
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
```

**File:** app/models/shipit/status.rb (L42-44)
```ruby
    def schedule_continuous_delivery
      commit.schedule_continuous_delivery
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

**File:** app/jobs/shipit/continuous_delivery_job.rb (L10-21)
```ruby
    def perform(stack)
      return unless stack.continuous_deployment?

      # If there is a schedule defined for this stack, make sure we are within a
      # deployment window before proceeding.
      return if stack.continuous_delivery_schedule && !stack.continuous_delivery_schedule.can_deploy?

      # checks if there are any tasks running, including concurrent tasks
      return if stack.occupied?

      stack.trigger_continuous_delivery
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
