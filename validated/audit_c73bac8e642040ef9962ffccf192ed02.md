## Title
Unscoped commit lookup in `StatusHandler` allows cross-repository CI status forgery - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

## Summary
### Finding Description
The bug class in the report is a threshold check that uses a value tied to the wrong scope (`min` of two independently-controlled bounds instead of enforcing the stricter one), letting a weaker/attacker-favorable bound satisfy a check meant to be governed by a stricter, trusted bound. The same class of binding mismatch exists in `Shipit::Webhooks::Handlers::StatusHandler`.

`StatusHandler#process` resolves which commits to update purely by SHA, globally, with no scoping to the repository/organization that the inbound webhook was authenticated for: [1](#0-0) 

Compare this to `PushHandler`, which correctly scopes to `stacks` (derived from `payload.dig('repository', 'full_name')`) before acting: [2](#0-1) [3](#0-2) 

The webhook signature is verified against the organization derived from `repository.owner.login` in the payload itself: [4](#0-3) [5](#0-4) 

This creates a binding: "the organization/repository that authenticated the webhook" ≠ "the commit record that gets mutated." Because `Commit.where(sha: params.sha)` in `StatusHandler` is instance-wide (not filtered by `stacks`/`repository_name` the way `PushHandler` and the `Handler` base class's `stacks` helper do), a validly-signed status webhook for repository A can write a `Status` record onto any `Commit` row in the entire Shipit database that happens to share that SHA — including commits belonging to a completely different repository/organization B, if the SHA coincidentally (or intentionally, e.g. via forked/shared git history) matches a commit tracked under stack B.

### Impact Explanation
`create_status_from_github!` (invoked per matched commit) writes a `Status` row, calls `enable_ci_on_stack`, and — critically — triggers `stack.schedule_merges` and `ContinuousDeliveryJob` when the new status resolves to `success`: [6](#0-5) [7](#0-6) [8](#0-7) [9](#0-8) 

Since `deployable?` and continuous-delivery scheduling for stack B are gated on the status of commit B's row, a forged/legitimate-but-misrouted "success" status delivered under organization A's webhook can flip stack B's commit into a deployable state and trigger an unauthorized deploy or unblock the merge queue for a repository the sender has no authority over. This is a cross-repository write and can lead to an unauthorized deploy, matching the report's Critical impact bucket.

### Likelihood Explanation
The binding break is triggered purely by data already present in a validly-signed webhook payload (the `sha` field), with no additional secret or privilege beyond what is required to make GitHub send *any* status event that reaches this endpoint for *some* org configured in the instance. `Commit#sha` is a content-addressed hash; identical commits (shared upstream history, forks, cherry-picks, rebase-preserved commits) legitimately collide across repositories, so an attacker only needs to identify a SHA collision between a repository they can generate real, correctly-signed status events for and a commit already tracked in a victim stack. No forging of `webhook_secret`, no `ApiClient` token, and no repository write access to the victim repository is required — the write happens purely because `StatusHandler` never checks that the incoming event's `repository`/`organization` matches the stack owning the commit it updates.

### Recommendation
Scope `StatusHandler#process` the same way `PushHandler` and the `Handler` base class do: resolve the target commits through `stacks` (i.e., `stacks.joins(:commits).where(commits: { sha: params.sha })` or equivalent), so a status event can only affect commits belonging to the repository identified in the webhook's own `repository.full_name`, never commits from unrelated stacks/organizations.

## Proof of Concept
1. Two Shipit stacks exist: Stack A (`org-a/repo-a`) and Stack B (`org-b/repo-b`), both tracked by the same Shipit instance.
2. `repo-b`'s history contains a commit `deadbeef...` also present (via fork/shared history/cherry-pick) in `repo-a`.
3. A GitHub "status" event fires for `org-a/repo-a` with `sha: deadbeef...`, `state: success` (a normal, validly-signed webhook for org A).
4. `WebhooksController#verify_signature` validates the signature using org A's configured `webhook_secret` — this succeeds because the payload genuinely originated from org A's repo.
5. `StatusHandler#process` runs `Commit.where(sha: 'deadbeef...')`, which matches the commit rows in **both** Stack A and Stack B, and calls `create_status_from_github!` on each.
6. Stack B's commit now has a `success` status it never legitimately received from `org-b/repo-b`'s own CI, potentially marking it `deployable?` and triggering `schedule_continuous_delivery`/merge-queue processing for Stack B — an unauthorized state change on a repository the org-A sender never authenticated for.

### Citations

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/status.rb (L16-20)
```ruby
    validates :state, inclusion: { in: STATES, allow_blank: true }, presence: true

    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

```
