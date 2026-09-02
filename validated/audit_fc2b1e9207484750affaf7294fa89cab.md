### Title
Unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` lets a status webhook from one repository flip commit status for a same-SHA commit in an unrelated stack, triggering `ContinuousDeliveryJob` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves target commits purely by `sha`, with no filter on the repository that authenticated the webhook, breaking the invariant that "a status affects only the repository that authenticated it". Because `Commit.schedule_continuous_delivery` fires `ContinuousDeliveryJob` whenever a commit becomes `deployable?` on a `continuous_deployment?` stack, a status write on a shared-SHA `Commit` row belonging to a different stack can force a ship/block decision the attacker did not authenticate for.

### Finding Description
The broken binding: the intended invariant is `status.repository == commit.stack.repository` for every status write, but the actual code enforces only `status.sha == commit.sha`: [1](#0-0) 

`Commit` rows are stored per-`Stack` (not globally deduplicated per repository), so the same content-addressed SHA can legitimately exist as separate `Commit` records in multiple stacks — e.g. an ephemeral PR/review stack (see `Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter`) and the branch/production stack once the same commit becomes reachable there (fast-forward merges keep the SHA identical). Any webhook whose `X-Hub-Signature` verifies for its declared `repository.owner.login` is accepted: [2](#0-1) 

`drop_unhandled_event`/`verify_signature` validate that *a* valid signature exists for the org named in the payload, but nothing ties the `sha` in the body to the repository that signed it, and `StatusHandler` never re-derives or checks `commit.stack.repository` against the payload's `repository` field.

Once `commit.create_status_from_github!(params)` is applied, `add_status` recomputes `status`, and if the state transition makes the commit newly deployable/blocked, `Commit#schedule_continuous_delivery` is invoked on create; for existing commits the effective status change is picked up by whichever job/consumer reads `deployable?`/`blocked?`: [3](#0-2) [4](#0-3) 

For a `continuous_deployment?` stack, this is the exact mechanism that autonomously ships newly-green commits, so an attacker-controlled `failure`/`success` status write reaching the wrong stack's `Commit` row can flip its deployability without that stack's repository ever authenticating the status.

### Impact Explanation
An attacker who can get one legitimately-signed status webhook accepted for some repository they control can, if a `Commit` row with the same SHA also exists under a different, `continuous_deployment`-enabled stack (a realistic occurrence for PR/review-stack + branch-stack pairs sharing history), write a `review/approved: failure` (or `success`) status onto that unrelated stack's commit. This is a cross-tenant write: a payload from repository A mutates stack/commit state that belongs to repository/stack B, matching the "payload for one repository mutating another's stack/commit" Critical category, with the concrete consequence of blocking or forcing an unauthorized deploy decision on the victim stack.

### Likelihood Explanation
Exploitability is gated on: (1) the attacker being able to get a webhook accepted for *some* org/repo (requires a validly signed webhook for that org — `verify_webhook_signature` returns `true` unconditionally only when no `webhook_secret` is configured for that org, otherwise a real secret is required), and (2) an actual SHA collision between the attacker's repository/stack commit and the victim's `continuous_deployment` stack commit, which in practice only occurs when both stacks track overlapping/shared git history in the same underlying repository (e.g. review-app stack + main stack via fast-forward merges), not for arbitrary unrelated victim repositories. I could not fully verify from this pass whether `webhook_secret` is mandatory in all supported deployment configurations or whether it can be legitimately absent, which materially affects how "unauthenticated" the first precondition is.

### Recommendation
Scope `StatusHandler#process` (and the analogous check-run handler) to only update commits whose `stack.repository` matches the `repository` object in the webhook payload, e.g. `Commit.where(sha: params.sha).joins(:stack).merge(Stack.where(repository: repo_from_payload))`, instead of a bare `Commit.where(sha: params.sha)`.

### Proof of Concept
Add a minitest under `test/models/shipit/webhooks/handlers/status_handler_test.rb`-style coverage:
1. Create two `Stack`s for different repositories (`repo_a`, `repo_b`), `repo_b` with `continuous_deployment` enabled and `required_statuses` including `review/approved`.
2. Create `Commit` rows with the identical `sha` under each stack, with `repo_b`'s commit currently `deployable?`.
3. Call `Shipit::Webhooks::Handlers::StatusHandler.new.process` (or `.call`) with a payload for `sha`, `context: "review/approved"`, `state: "failure"`, `repository.owner.login` matching only `repo_a`.
4. Assert `Commit` under `repo_b`'s stack now has `blocked?`/`deployable?` flipped even though the payload never named `repo_b`, proving `commit.stack.repository != payload.repository` while the status was still applied — i.e., the binding `status.repository == commit.stack.repository` is violated.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
