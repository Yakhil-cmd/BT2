### Title
Cross-repository commit-status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits solely by SHA, with no check that the `repository` named in the webhook payload matches the commit's own stack/repository. Because the webhook signature is verified only against the organization named in the payload's `repository.owner.login`, an attacker who controls a GitHub organization/repo with the Shipit App installed can send a validly-signed `status` webhook naming their own repo but containing a SHA that also exists in a victim stack's commit history (e.g. via a shared git ancestor/fork), causing Shipit to write a `Status` and trigger `Commit#schedule_continuous_delivery` → `Stack#trigger_continuous_delivery` for the victim stack.

### Finding Description
The claimed binding is: `organization_that_signed_the_webhook == organization_owning_the_stack_that_trigger_continuous_delivery_acts_on`. Tracing the code shows this binding is **not enforced**:

- `WebhooksController#verify_signature` derives the signing org purely from the payload itself: `repository_owner = params.dig('repository','owner','login')`, then calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`. [1](#0-0) [2](#0-1) 
  This only proves the request was signed by *some* org's secret matching whatever `repository.owner.login` the attacker put in the payload — it says nothing about which commit/stack the handler will actually mutate.

- `StatusHandler#process` ignores the base `Handler#stacks` helper (which scopes lookups to `Repository.from_github_repo_name(repository_name)`), and instead resolves commits globally by SHA only:
```
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [3](#0-2) 
compare with the base class helper that other handlers use for repo scoping: [4](#0-3) 

- `Commit#create_status_from_github!` then creates the status using the **commit's own** `stack_id` (the victim stack), not anything derived from the attacker's payload: [5](#0-4) 

- `Status` has an `after_commit :schedule_continuous_delivery` hook that calls `commit.schedule_continuous_delivery`: [6](#0-5) 

- `Commit#deployable?` becomes true once `success? && !blocked?` (or `stack.ignore_ci?`), and `Commit#schedule_continuous_delivery` enqueues `ContinuousDeliveryJob` for the **victim's** `stack`: [7](#0-6) [8](#0-7) 

- That job ultimately runs `Stack#trigger_continuous_delivery`, which builds and enqueues a real `Deploy` for the victim stack if it is otherwise deployable: [9](#0-8) 

**Attacker's exact request:** a `POST /webhooks` with header `X-Github-Event: status`, body `{"sha": "<shared_sha>", "state": "success", "context": "ci/attacker", "repository": {"owner": {"login": "attacker-org"}, "full_name": "attacker-org/attacker-repo"}, ...}`, signed with `X-Hub-Signature` computed using `attacker-org`'s own `webhook_secret` (which the attacker legitimately possesses because they administer that org/installation). The `sha` value is chosen to collide with a commit that also exists on the victim stack (trivially achievable if the victim repo is public and the attacker forks it, sharing ancestor commit SHAs, or otherwise learns/reuses a SHA present in the victim's tracked branch).

**Why existing guards fail:** `verify_signature` validates the HMAC against the secret of the org named in the payload, which the attacker fully controls and can set to their own org — it never confirms that the `sha`/commit actually belongs to that org's repository. `StatusHandler#process` performs no such check either; it globally matches on `sha`. There is no unique-repository-scoped index or validation preventing the same SHA string from resolving to `Commit` rows belonging to different stacks/repositories in the `shipit_commits` table.

### Impact Explanation
An attacker who controls any organization/installation configured in Shipit (even one used only for their own unrelated project) can cause an unauthorized `Status` write and, if continuous delivery is enabled and the victim commit is otherwise unlocked/unblocked, an unauthorized deploy (`Deploy` record + task execution) against a victim stack whose organization never authenticated or authorized the request. This is a "payload for one repository mutating another's stack/commit" and "unauthorized deploy" scenario — matching the Critical impact category. The attack is repeatable against any stack/commit whose SHA the attacker can predict or reproduce (most easily via forking a public tracked repo), and it crosses tenant boundaries in a multi-org Shipit deployment.

### Likelihood Explanation
Preconditions: (1) Shipit must be configured for at least one organization the attacker legitimately controls (any onboarded customer/org in a multi-tenant deployment, or the attacker's own org if Shipit tracks it for other purposes); (2) the victim stack must have `continuous_deployment` enabled, be unlocked, not blocked, and the target commit must not already be deployed/locked; (3) the attacker needs a commit SHA shared between their own controllable repo history and the victim's tracked branch — straightforward via forking a public repository, since git preserves commit SHAs across forks. No Shipit secrets, sessions, or API tokens are required beyond the attacker's own legitimately-issued webhook secret for their own org. This is a low-cost, repeatable, scriptable attack once the preconditions are met.

### Recommendation
Scope `StatusHandler#process` (and any similarly structured handler) to only touch commits belonging to the stack(s)/repository named and cryptographically authenticated in the webhook payload — i.e., use the `stacks` helper (`Repository.from_github_repo_name(repository_name)`) already defined in the base `Handler` class to restrict `Commit.where(sha: params.sha)` to `commit.stack_id IN stacks.ids`, mirroring how other handlers avoid cross-repository leakage.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "does not schedule continuous delivery for a victim stack via a same-sha status from an unrelated repo" do
  victim_commit = shipit_commits(:first) # belongs to victim stack with continuous_deployment: true
  victim_commit.stack.update!(continuous_deployment: true)
  victim_commit.statuses.destroy_all

  attacker_payload = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'context' => 'ci/attacker',
    'repository' => { 'owner' => { 'login' => 'attacker-org' }, 'full_name' => 'attacker-org/attacker-repo' }
  }

  assert_no_enqueued_jobs(only: Shipit::ContinuousDeliveryJob) do
    Shipit::Webhooks::Handlers::StatusHandler.call(attacker_payload)
  end
end
```
Before the fix, this test fails: `Commit.where(sha: params.sha)` matches `victim_commit` regardless of `attacker-org` not owning the victim's repository, `create_status_from_github!` creates a success `Status` on the victim's stack, `schedule_continuous_delivery` fires, and `ContinuousDeliveryJob`/`Stack#trigger_continuous_delivery` is enqueued/executed for the victim stack — demonstrating the binding `signing_org == stack_owning_org` does not hold.

### Citations

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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
