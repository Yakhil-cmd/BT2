### Title
Unscoped commit lookup in `StatusHandler` lets a webhook authenticated for one GitHub organization write CI status onto commits owned by a different organization's stack - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
The webhook pipeline authenticates a delivery against the GitHub App/organization derived from the payload's `repository.owner.login` (or `organization.login`), then dispatches to per-event handlers that are expected to only mutate data belonging to that same repository. `Shipit::Webhooks::Handlers::Handler` provides a `stacks` helper that scopes all writes to `Repository.from_github_repo_name(repository_name)` [1](#0-0) , and most handlers (`PushHandler`, `CheckSuiteHandler`, pull-request handlers) use this scoped helper. `StatusHandler`, however, bypasses this entirely and updates **any** `Commit` row in the whole database whose `sha` matches the payload, regardless of which repository/organization it belongs to: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [2](#0-1) .

### Finding Description
The trust binding that should hold is: **organization authenticated by `WebhooksController#verify_signature`** == **repository/stack whose data is mutated by the handler**.

`WebhooksController#verify_signature` picks the GitHub App/secret to check the HMAC signature against using `repository_owner`, which is read straight out of the untrusted JSON payload (`params.dig('repository','owner','login') || params.dig('organization','login')`) [3](#0-2) [4](#0-3) . The signature only proves that *some* configured organization's webhook secret was used to sign this specific payload; it does not otherwise constrain which records a handler is allowed to touch.

`Shipit::Webhooks::Handlers::Handler#stacks` is the mechanism meant to enforce that a handler only touches records that belong to the repository named in the (now trusted) payload, by resolving `Repository.from_github_repo_name(repository_name)` from `payload.dig('repository','full_name')` [1](#0-0) . `PushHandler` and `CheckSuiteHandler` correctly use this scoped accessor [5](#0-4) [6](#0-5) .

`StatusHandler#process`, in contrast, never calls `stacks`/`repository_name` at all - it queries the global `Commit` table by `sha` only [2](#0-1) , and `Commit#create_status_from_github!` writes a new `Status` record and triggers `Hook.emit(:commit_status/:deployable_status, ...)` and `stack.schedule_merges` based on it [7](#0-6) [8](#0-7) . Since git commit SHAs are content-addressed and identical commits are common across forks/mirrors of the same codebase tracked as separate `Stack`/`Repository` records in Shipit (which happens routinely for organizations that mirror or fork a repo into another GitHub org), a payload correctly signed for organization A can create/update a `Status` on a `Commit` that in fact belongs to a `Stack` under organization B, purely because the SHA matches. Nothing in `StatusHandler` re-checks that the commit's `stack.repository` corresponds to the authenticated `repository_owner`/`repository.full_name`.

This mirrors the report's bug class exactly: a check is performed against the wrong object (SHA globally, with no association to the authenticated repository) with no mechanism tying the two together, letting a low-trust caller (a delivery correctly signed for one org) affect state that should require a different, higher-trust binding (the target org/repository).

### Impact Explanation
`Commit#deployable?`/`Commit#blocked?` and `stack.schedule_merges` are driven directly by `Status` records [9](#0-8) [10](#0-9) , and CI status is one of the standard gates before automatic/continuous deployment (`schedule_continuous_delivery`) [11](#0-10) . A cross-organization forged "success" status on the target stack's commit can therefore unblock or trigger an automatic deploy/merge that the legitimately-authenticated organization for that repository never approved - matching the "unauthorized deploy" criterion for High/Critical impact.

### Likelihood Explanation
Medium: it requires (a) the attacker to control (or have legitimate webhook delivery rights for) some GitHub organization/repo that Shipit is configured to trust, and (b) a SHA collision between a commit they can produce a status event for and a commit that exists in a different, victim Stack. SHA collisions are not contrived when organizations track forks/mirrors of the same upstream repository as separate Shipit stacks (a common real-world Shipit deployment pattern), since forked commits share identical SHAs with the upstream commit.

### Recommendation
`StatusHandler#process` should scope the commit lookup through the same `stacks` helper used by the other handlers, e.g. `stacks.joins(:commits).merge(Commit.where(sha: params.sha))`, so that only commits belonging to the stack(s) whose repository matches the authenticated `repository.full_name` are updated. More generally, audit all `Webhooks::Handlers::*` classes to ensure every one that ultimately mutates a `Commit`/`Stack` record derives that record through `Handler#stacks`/`repository_name`, never through a bare cross-repository lookup keyed only on an attacker-supplied SHA or number.

### Proof of Concept
1. Configure Shipit with two organizations, `orgA` (attacker-controlled repo/webhook) and `orgB` (victim, tracked stack `orgB/app`), where `orgB/app` is a fork of `orgA/app` (or otherwise shares commit history), so commit `sha=deadbeef...` exists identically in both `Commit` rows for `stack_a` (org A) and `stack_b` (org B).
2. Attacker triggers (or crafts, if `orgA`'s `webhook_secret` happens to be blank/optional as documented in `docs/setup.md`) a `status` webhook payload: `{"sha": "deadbeef...", "state": "success", "repository": {"owner": {"login": "orgA"}, "full_name": "orgA/app"}, ...}`, correctly signed with `orgA`'s webhook secret.
3. `WebhooksController#verify_signature` validates the signature against `orgA`'s secret and passes [12](#0-11) .
4. `StatusHandler#process` runs `Commit.where(sha: 'deadbeef...')`, which matches **both** the `orgA` commit and the `orgB` commit, and calls `create_status_from_github!` on both, creating a fabricated "success" `Status` on `orgB/app`'s commit despite the delivery never having been authenticated for `orgB` [2](#0-1) .
5. This flips `orgB`'s commit to `deployable?`/`success?` and can trigger `stack.schedule_merges`/continuous deployment for `orgB/app` [10](#0-9) .

Note: I could not fully verify from the index whether any additional per-request repository check exists elsewhere in the request pipeline (e.g., in `Shipit::Webhooks.for_event`) that might mitigate this before reaching `StatusHandler#process`; the code I retrieved shows no such check, but if such coverage exists elsewhere and was not indexed, that should be confirmed in a full checkout of the repository.

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

**File:** app/models/shipit/commit.rb (L227-237)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end

    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
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
