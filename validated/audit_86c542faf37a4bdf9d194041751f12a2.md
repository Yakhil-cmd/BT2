### Title
Cross-repository/cross-stack `Status` forgery via unscoped SHA lookup in `StatusHandler#process` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves the target commit(s) for an incoming `status` webhook purely by `Commit.where(sha: params.sha)`, with no scoping to the repository that authenticated the webhook. Any commit record across every `Stack`/repository tracked by the Shipit instance that happens to share that SHA gets a new `Status` written and its deployability re-evaluated, which can drive `Commit#schedule_continuous_delivery` and an autonomous deploy under the bot identity.

### Finding Description
The broken binding is: `webhook.repository.full_name == commit.stack.repository.full_name` is assumed but never checked. In practice `StatusHandler#process` only enforces `webhook.sha == commit.sha`: [1](#0-0) 

The lookup `Commit.where(sha: params.sha)` iterates over *all* `Commit` rows across the entire installation matching that SHA — it does not join or filter on `stack_id`, `repository`, or the organization that authenticated the request. `WebhooksController#verify_signature` only proves that the payload was signed by the GitHub App configured for `repository_owner` (an organization), not that the specific repository named in the payload is the one that owns the target `Commit`: [2](#0-1) 

Once `create_status_from_github!` is invoked on the wrongly-matched commit, `add_status` re-evaluates `Status::Group`, fires `deployable_status`, and can call `stack.schedule_merges`, and `Commit#schedule_continuous_delivery` checks `deployable?` and `stack.continuous_deployment?` to enqueue `ContinuousDeliveryJob`: [3](#0-2) [4](#0-3) 

If the victim stack is configured with `bot_login` (`Shipit.user`) driving auto-triggered deploys, a `failure` status on a required context (e.g. `ci/lint`) that shares a SHA with an unrelated stack's commit will flip `deployable?`/`blocked?` for that unrelated stack and can block or unblock its automatic deploy pipeline, executed under the bot's identity — without the attacker ever authenticating against, or being a maintainer of, that victim repository.

None of the existing guards intercept this: `verify_signature` validates organization-level HMAC signature, not per-repository/per-commit binding; `drop_unhandled_event` only checks the event type is registered; the `ExplicitParameters` schema in `StatusHandler.params` only validates payload shape (`sha`, `state`, `context`, etc.), not repository identity; there is no `Repository`/`stack` scoping anywhere in `StatusHandler#process`.

### Impact Explanation
A `status` webhook that is validly signed for repository/org A can mutate a `Status` record — and therefore deployability, blocking state, and auto-triggered deploy/rollback decisions — of a `Commit` belonging to stack/repository B, provided both share the same commit SHA (a realistic occurrence for forked/mirrored repositories, monorepo submodules, or multiple `Stack` records tracking the same underlying repository). This is a payload for one repository mutating another's stack/commit, matching the Critical "unauthorized deploy, rollback" impact category, since the divergence can flip a stack's `deployable?`/`blocked?` state and, combined with a `bot_login`-driven continuous-deployment stack, trigger `ContinuousDeliveryJob` under the bot's identity.

### Likelihood Explanation
Exploitation requires: (1) the attacker can generate a validly-signed `status` webhook for *some* repository (their own fork, or any repo in an org whose GitHub App secret is shared across repos), and (2) a SHA collision exists between that repository's commit history and the victim stack's tracked commit — which is common for forks/mirrors of the same upstream, or multiple Shipit `Stack`s configured against the same GitHub repository. Given those preconditions the attack is fully repeatable and requires no privileged Shipit role, session, or API token — only the ability to produce a signed status event for one repo whose SHA also exists in the victim stack.

### Recommendation
Scope `StatusHandler#process` (and the analogous check_run/push handlers where applicable) to only touch commits belonging to a `Stack` whose repository matches `params.dig('repository', 'full_name')` (or the organization/owner + name pair from the payload), e.g. join through `Stack` and filter `Commit.joins(:stack).merge(Stack.where(repository: repo)).where(sha: params.sha)`, rejecting/ignoring statuses for commits whose owning repository does not match the authenticated payload's repository.

### Proof of Concept
Minitest plan (to be added under `test/models/shipit/webhooks/handlers/status_handler_test.rb` or `test/controllers/webhooks_controller_test.rb`):
1. Create two stacks/repositories: `victim_stack` (repository `victim/repo`, `bot_login` configured, `continuous_deployment` enabled, `required_statuses` includes `ci/lint`) and `attacker_stack` (repository `attacker/repo`).
2. Create a `Commit` on `attacker_stack` with `sha = "deadbeef..."` and create a `Commit` with the *same* `sha` on `victim_stack` (simulating a shared/forked commit), with victim's commit initially `success` (deployable).
3. Assert binding before: `victim_commit.deployable? == true` and `victim_stack.deployable? == true`.
4. POST a `status` webhook payload with `repository.full_name = "attacker/repo"` (signed for attacker's org/app secret), `sha = "deadbeef..."`, `context: "ci/lint"`, `state: "failure"`.
5. After processing, assert `victim_commit.reload.deployable? == false` (or that `ContinuousDeliveryJob`/block state changed) even though the webhook's `repository.full_name` never matched `victim/repo` — proving the write crossed repository boundaries.
6. Assert this occurs with no session, API token, or team membership tied to `victim/repo`.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
