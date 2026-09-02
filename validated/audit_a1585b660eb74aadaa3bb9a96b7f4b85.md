### Title
Cross-tenant status forgery via unscoped `Commit.where(sha:)` lookup clears a victim stack's `blocking_statuses` gate - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` resolves the commit(s) to update purely by `sha`, with no scoping to the repository named in the (signature-verified) webhook payload, unlike every other handler in the same directory. Any org/repo owner who is already integrated with the Shipit instance (and therefore has a valid webhook signature for their own org) can send a `status` event whose `sha` matches a commit that exists in a completely different tenant's stack, updating that unrelated stack's `Status`/`Commit` records, clearing `blocking?`/`blocked?`, and triggering an unauthorized continuous deployment.

### Finding Description
The broken binding, stated as an equality that should hold but does not:

`repository_owner_that_signed_the_webhook == Commit#stack.repository.full_name` (for every `Commit` mutated by the handler)

Trace:
- `WebhooksController#verify_signature` only checks that the payload was signed by the org identified by `repository_owner` (`params.dig('repository','owner','login')`), via `Shipit.github(organization: repository_owner).verify_webhook_signature` [1](#0-0) . This proves only "this payload was signed by org X," not "org X owns the `sha` inside it."
- `Handler` base class exposes a `stacks` helper that scopes lookups to `Repository.from_github_repo_name(repository_name)&.stacks`, i.e., the repository named in the payload [2](#0-1) . Every other handler (`PushHandler`, `pull_request/*Handler`) uses this `stacks`/`repository` scoping before touching any record [3](#0-2) .
- `StatusHandler`, however, never calls `stacks` or resolves a repository at all. Its `params` schema doesn't even require a `repository` field, and `process` does a **global** lookup: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [4](#0-3) . This matches every `Commit` row across every stack/tenant that shares that sha, regardless of which org's key signed the request.
- `Commit#create_status_from_github!` creates a `Status` scoped to `commit.stack_id` (the victim stack, not the attacker's) [5](#0-4) [6](#0-5) .
- `Status#blocking?` is `!success? && commit.blocking_statuses.include?(context)` [7](#0-6) , and `Commit#blocked?` recomputes over `stack.commits.reachable.newer_than(...).older_than(self).any?(&:blocking?)` [8](#0-7) . Posting `state: success` for the blocking context flips `blocking?` to false for that commit, which flips `blocked?` false for every downstream undeployed commit in the victim stack.
- `Commit#deployable?` becomes true (`!locked? && (ignore_ci? || (success? && !blocked?))`) [9](#0-8) , and `Status#after_commit :schedule_continuous_delivery` fires `commit.schedule_continuous_delivery` [10](#0-9) [11](#0-10) , which eventually invokes `ContinuousDeliveryJob#perform` → `stack.trigger_continuous_delivery` [12](#0-11) , deploying the victim stack.

Existing guards fail because `verify_signature` binds only "who signed," never "which repository's sha is being asserted," and `StatusHandler` is the only handler that skips the `repository`/`stacks` scoping pattern used elsewhere in the codebase.

### Impact Explanation
An attacker who controls (or has integrated) their own repository/org on the same Shipit instance can clear another tenant's `blocking_statuses` safety gate and trigger an unauthorized deploy on a stack/repository they never authenticated against — this is a payload for one repository mutating and deploying another's stack, matching the Critical category ("a payload for one repository mutating another's stack ... an unauthorized deploy"). Repeatable against any stack whose commit sha the attacker can reproduce (realistic for public/open-source repos with shared history, forks, or cherry-picks that preserve the exact sha), and requires no privilege on the victim's org, no session, and no victim secret.

### Likelihood Explanation
Preconditions: (1) attacker owns/controls a repository already onboarded to the same Shipit instance so they hold a valid webhook signature for their own org; (2) victim stack has `ci.blocking` contexts configured and an undeployed commit currently pending/failing that context; (3) attacker can reproduce the exact victim commit sha (trivial for public repos/forks where the sha is public and content-addressed, since the same commit object can exist verbatim in multiple repositories). Cost is a single signed HTTP POST to `/webhooks`; the attack is fully repeatable and requires no interaction with GitHub's real webhook delivery (a direct curl with a valid HMAC for the attacker's own org suffices).

### Recommendation
Scope `StatusHandler#process` to the repository named (and signature-verified) in the payload, mirroring the other handlers: require `repository.full_name` in the `params` schema, and update only commits belonging to `stacks` (i.e., `Commit.where(sha: params.sha, stack_id: stacks.select(:id))` or `stacks.flat_map(&:commits)...`), so a signed webhook can only mutate commits/stacks under the repository that authenticated the request.

### Proof of Concept
Minitest (`test/models/webhooks/handlers/status_handler_test.rb` or `test/controllers/webhooks_controller_test.rb` style, no live GitHub):
1. Fixtures: two stacks in different repositories, e.g. `shipit_stacks(:soc)` (victim, configured with `ci.blocking: ['soc/compliance']`) with an undeployed blocking commit `shipit_commits(:soc_second)` (state pending/failure on `soc/compliance`), and an unrelated repository/org (e.g. `cyclimse`) that the attacker legitimately controls.
2. Build a `status` webhook payload: `{ sha: shipit_commits(:soc_second).sha, state: 'success', context: 'soc/compliance', repository: { full_name: 'attacker/unrelated-repo', owner: { login: 'cyclimse' } } }`, signed/stubbed as verified for the `cyclimse` org (`GithubHook.any_instance.stubs(:verify_signature).returns(true)` or stub `verify_webhook_signature` for `cyclimse`).
3. Assert the binding before: `assert_predicate shipit_commits(:soc_second), :blocking?` and `assert shipit_commits(:soc_third).blocked?` (or equivalent downstream commit).
4. POST the payload to `/webhooks` with `X-Github-Event: status`.
5. Assert the binding after diverges from the payload's authenticated repository: `refute_predicate shipit_commits(:soc_second).reload, :blocking?` and `refute shipit_commits(:soc_third).reload.blocked?`, while `shipit_commits(:soc_second).stack.repository.full_name` (the `soc` stack) is not equal to `'attacker/unrelated-repo'` (the signed payload's repository) — proving the mutation crossed tenant boundaries.
6. Optionally assert `assert_enqueued_with(job: ContinuousDeliveryJob, args: [shipit_stacks(:soc)])` fires as a result of the `Status#schedule_continuous_delivery` callback, demonstrating the unauthorized deploy trigger.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/commit.rb (L231-237)
```ruby
    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
    end
```

**File:** app/models/shipit/status.rb (L19-19)
```ruby
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```

**File:** app/models/shipit/status.rb (L24-33)
```ruby
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

**File:** app/models/shipit/status/common.rb (L46-48)
```ruby
      def blocking?
        !success? && commit.blocking_statuses.include?(context)
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
