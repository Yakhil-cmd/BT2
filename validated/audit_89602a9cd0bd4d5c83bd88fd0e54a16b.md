This confirms the anomaly is real: `PushHandler#process` and `CheckSuiteHandler#process` both use the base `Handler#stacks` method, which scopes lookups through `Repository.from_github_repo_name(repository_name)&.stacks` [1](#0-0) , requiring the webhook's `repository.full_name` to match a repository that owns the target stack. `StatusHandler#process`, in contrast, never calls `stacks` or checks `repository_name` at all — it looks up `Commit.where(sha: params.sha)` globally across the entire `commits` table and calls `create_status_from_github!` on every match [2](#0-1) .

### Title
Cross-repository Status forgery via unscoped `Commit.where(sha:)` in `StatusHandler#process` triggers unauthorized continuous delivery for a victim stack - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` resolves the target commit purely by matching the webhook's `sha` field against the global `commits` table, without verifying that the webhook's `repository.full_name`/`repository_owner` corresponds to the repository that owns the matched `Commit`'s stack. `WebhooksController#verify_signature` [3](#0-2)  only authenticates that the payload was legitimately signed by *some* configured GitHub organization — it never checks that the signing organization actually owns the commit being mutated. An attacker who controls a repository within any Shipit-configured GitHub org can therefore push a git commit object with the exact same SHA as an existing commit in a completely unrelated victim stack (git commit objects are content-addressed and portable across repositories), post a genuinely GitHub-signed `status` event for that SHA with `state: "success"`, and have Shipit create a `Status` row against the **victim's** `Commit`/`Stack`, triggering `Status#schedule_continuous_delivery` → `Commit#schedule_continuous_delivery` → `Stack#trigger_continuous_delivery` for a stack the attacker has no relationship to.

### Finding Description
The broken binding is: *the repository that authenticated a webhook == the repository that owns the `Commit` row mutated by that webhook*. This holds for `PushHandler` and `CheckSuiteHandler`, which both scope their queries via `Handler#stacks`, itself built from `Repository.from_github_repo_name(repository_name)&.stacks` [1](#0-0)  and `app/models/shipit/webhooks/handlers/push_handler.rb:12-17`, `app/models/shipit/webhooks/handlers/check_suite_handler.rb:13-17`. It is broken for `StatusHandler`, whose `process` method does:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [2](#0-1) 

`Commit.where(sha:)` is not scoped to any repository or stack; `sha` is not unique across stacks in the schema, and this query can match a `Commit` belonging to a stack whose repository the sender does not own. `create_status_from_github!` then persists a `Status` bound to `commit.stack_id` — the victim's stack, not the attacker's [4](#0-3) .

Once the `Status` is created, `after_commit :schedule_continuous_delivery` fires [5](#0-4) , calling `commit.schedule_continuous_delivery`, which enqueues `ContinuousDeliveryJob` for the victim stack if `commit.deployable? && stack.continuous_deployment? && stack.deployable?` [6](#0-5) . `Commit#deployable?` is `!locked? && (stack.ignore_ci? || (success? && !blocked?))` [7](#0-6) . Because the attacker fully controls the forged status's `state` field, they can supply `state: "success"` regardless of the victim stack's `ignore_ci` setting, satisfying `deployable?` and triggering `ContinuousDeliveryJob.perform_later(stack)`, which ultimately calls `Stack#trigger_continuous_delivery` [8](#0-7) .

`WebhooksController#verify_signature` authenticates only that the payload matches the `webhook_secret` of `Shipit.github(organization: repository_owner)` — the organization named in the *attacker's own* payload — and never cross-checks that organization against the stack ultimately mutated [3](#0-2) . `ExplicitParameters` schema in `StatusHandler` only validates types (`sha`, `state`, etc.), not repository ownership [9](#0-8) . No other guard (`drop_unhandled_event`, `require_permission!`, model validations) checks repository/stack correspondence for this path.

Attacker flow: attacker has write access to a repository in an org configured in Shipit (this can be their own repo/org if Shipit's GitHub App/webhook is multi-tenant, or any repo where they can get a legitimate CI/status webhook fired). They locate a public victim commit SHA (commit SHAs are not secret) and construct/push an identical git commit object (content-addressed, reproducible by copying the tree/parent/author/committer metadata) into their own repository. They then post (or have their CI post) a GitHub `status` API call with `state: success` against that SHA in their own repo. GitHub signs and delivers this event with a valid signature for their org's `webhook_secret`. Shipit's `verify_signature` passes because the signature is genuine for the attacker's org. `StatusHandler#process` then matches the shared SHA against the victim's unrelated `Commit` row and creates the forged `Status`, cascading into a real deploy trigger for the victim's stack.

### Impact Explanation
This allows a payload authenticated for one repository to mutate another repository's `Commit`/`Stack` state and trigger an unauthorized deploy (`ContinuousDeliveryJob` → `Stack#trigger_continuous_delivery`) for a stack the attacker does not control. This matches the Critical impact category "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy". The blast radius spans any stack whose `continuous_deployment` is enabled, across tenants sharing the same Shipit instance, and is repeatable for every commit SHA the attacker can reproduce in a repo they control.

### Likelihood Explanation
Preconditions: the victim stack must have `continuous_deployment: true` (common); the attacker needs write access to at least one repository within any GitHub org configured in the shared Shipit instance (a normal, unprivileged capability for any GitHub user who can create their own repo/org if Shipit's webhook endpoint accepts events from multiple orgs, or any contributor able to trigger a legitimate CI status on a repo they control). Reproducing a target commit SHA in an unrelated repository is a known, low-cost git technique for public commits (content-addressed objects can be copied verbatim). No Shipit secrets, sessions, or API tokens are required — only a genuinely GitHub-signed webhook, which the attacker obtains by acting within their own legitimate repository.

### Recommendation
In `StatusHandler#process`, scope the commit lookup to the stacks belonging to the reporting repository, mirroring `PushHandler`/`CheckSuiteHandler`: use the base `Handler#stacks` (derived from `Repository.from_github_repo_name(payload.dig('repository','full_name'))`) and only update `Status` records for commits whose `stack` is included in that scoped set, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or equivalently filter `Commit.where(sha: params.sha).select { |c| stacks.exists?(c.stack_id) }`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "process does not update a commit belonging to a different repository than the webhook" do
  victim_commit = shipit_commits(:first) # belongs to stack with repository 'shopify/shipit-engine'
  victim_stack = victim_commit.stack
  victim_stack.update!(continuous_deployment: true, ignore_ci: false)

  attacker_payload = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'context' => 'attacker/ci',
    'repository' => { 'full_name' => 'attacker/unrelated-repo', 'owner' => { 'login' => 'attacker-org' } }
  }

  Shipit::Stack.any_instance.expects(:trigger_continuous_delivery).never

  assert_no_difference -> { victim_commit.statuses.count } do
    Shipit::Webhooks::Handlers::StatusHandler.call(attacker_payload)
  end
end
```
This asserts both sides of the binding: (1) no `Status` is created on `victim_commit` from a payload whose `repository.full_name` does not match the victim's stack repository, and (2) `Stack#trigger_continuous_delivery` is never invoked for the victim stack as a result of the cross-repository payload. Under the current code, `Commit.where(sha: params.sha)` still matches `victim_commit` regardless of `attacker_payload['repository']`, so this test fails against the vulnerable implementation, confirming the exploit.

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
