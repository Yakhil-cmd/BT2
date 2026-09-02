### Title
Cross-repository commit-status forgery via unscoped SHA lookup enables unauthorized stack merge/deploy trigger - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves the target `Commit` purely by `Commit.where(sha: params.sha)`, with no check against the webhook payload's own `repository.full_name`. Any signed `status` event — including one signed for a repository the attacker controls — can therefore mutate the state of a completely unrelated victim `Stack`'s commit if the SHAs happen to collide, driving `Commit#add_status` and `stack.schedule_merges` for a stack that never appears anywhere in the attacker's payload.

### Finding Description
The claimed binding is: `Stack` consulted for `continuous_deployment?`/`deployable?` (i.e. `commit.stack`) `==` `Stack` derived from webhook `payload['repository']['full_name']`. Tracing the code shows this binding is in fact broken:

- `Handler` (the base class) exposes `repository_name` (`payload.dig('repository', 'full_name')`) and a `stacks` helper scoped to that repository [1](#0-0) , but `StatusHandler#process` never calls either of them:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [2](#0-1) 

- `create_status_from_github!` → `add_status` operates on `commit.stack` — the commit's real, DB-resolved stack — and unconditionally calls `stack.schedule_merges if new_status.pending? || new_status.success?` whenever the simple state changes [3](#0-2) . That `stack` object is never checked against `repository_name`/`payload['repository']`.
- `Commit#deployable?` (`!locked? && (stack.ignore_ci? || (success? && !blocked?))`) and `schedule_continuous_delivery` (`deployable? && stack.continuous_deployment? && stack.deployable?` → `ContinuousDeliveryJob.perform_later(stack)`) both read `commit.stack`, the same unauthenticated-relative object [4](#0-3) [5](#0-4) .

Attacker flow:
1. Attacker owns/controls a repository whose `status` webhook deliveries are legitimately signed for some organization the Shipit deployment trusts (per the question's stated premise).
2. Attacker crafts a `status` payload with `sha` equal to a victim `Stack`'s pending head commit SHA (attacker can predict/observe this from the victim's public commit history) and `state: "success"`, with `repository.full_name` set to the attacker's own repo.
3. `WebhooksController#verify_signature` only checks the signature against `repository_owner` derived from the *attacker's* payload — it has no notion of "this event must belong to the commit's real stack" [6](#0-5) .
4. `StatusHandler#process` matches the victim commit purely by SHA and applies the forged state to it, flipping `commit.state`/`success?` for the victim's `Stack`.
5. `add_status` detects the transition and calls `stack.schedule_merges` (confirmed by test to enqueue `ProcessMergeRequestsJob` for the victim stack, matched only by `commit.stack`, not by the attacker's declared repository) [7](#0-6) . With the commit now `success?` and unblocked, `deployable?` becomes true for the victim commit, and any subsequent evaluation of `schedule_continuous_delivery` (e.g. on later related jobs/refreshes) can enqueue `ContinuousDeliveryJob.perform_later(stack)` for the victim's stack.

No existing guard catches this: `verify_signature` only authenticates the calling organization, not that the commit belongs to that organization's repo; `StatusHandler` performs no repository/stack scoping at all (unlike the `stacks`/`repository_name` helper it inherits but ignores); the `ExplicitParameters` schema only validates shape (`sha`, `state`, etc.), not provenance.

### Impact Explanation
A payload legitimately signed for repository A can mutate commit/state data belonging to Stack B, and drive `stack.schedule_merges` (merge-request processing) and, transitively, continuous-delivery eligibility (`ContinuousDeliveryJob`) for a victim stack that never appears in the attacker's webhook payload. This is a cross-tenant "payload for one repository mutating another's stack/commit... or an unauthorized deploy/rollback/merge," matching the Critical category. It is repeatable against any stack/commit whose SHA the attacker can predict or collide with, and is not limited to a single victim.

### Likelihood Explanation
Preconditions: the attacker needs a channel to deliver a `status` webhook that passes `verify_signature` for *some* organization Shipit trusts (as stipulated by the question), and needs to know/guess a SHA that matches a pending commit on a victim stack (commit SHAs for public/tracked repos are typically discoverable via the Shipit UI or GitHub itself). No Shipit session, API token, or GitHub write access to the victim repo is required. This makes the attack low-cost and repeatable once the signing precondition is satisfied.

### Recommendation
In `StatusHandler#process`, scope the commit lookup to the stacks associated with `repository_name` (using the `stacks` helper already defined on `Handler`), e.g. `Commit.where(sha: params.sha, stack: stacks)`, so a status event can only affect commits belonging to the repository named in its own payload.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb (conceptual)
test "status webhook cannot alter commits belonging to a different repository/stack" do
  victim_stack = shipit_stacks(:shipit)
  victim_commit = shipit_commits(:first) # belongs to victim_stack
  victim_commit.statuses.destroy_all
  victim_commit.update!(state: nil)

  attacker_payload = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'context' => 'ci/attacker',
    'repository' => { 'full_name' => 'attacker/unrelated-repo' } # never matches victim_stack
  }

  ContinuousDeliveryJob.expects(:perform_later).never
  ProcessMergeRequestsJob.expects(:perform_later).never

  Shipit::Webhooks::Handlers::StatusHandler.call(attacker_payload)

  victim_commit.reload
  assert_not_equal 'success', victim_commit.state # currently FAILS: it becomes 'success'
end
```
This asserts the equality claimed in the binding — `commit.stack` (victim) must equal the stack derivable from `attacker_payload['repository']['full_name']` (attacker) — never holds, and demonstrates that under current code the victim commit's state, and downstream `stack.schedule_merges`/`ContinuousDeliveryJob` eligibility, are affected by a payload naming an entirely different repository.

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

**File:** test/models/commits_test.rb (L763-777)
```ruby
    test "#add_status schedule a MergeMergeRequests job if the commit transition to `pending` or `success`" do
      commit = shipit_commits(:second)
      github_status = OpenStruct.new(
        state: 'success',
        description: 'Cool',
        context: 'metrics/coveralls',
        created_at: 1.day.ago.to_formatted_s(:db)
      )

      assert_equal 'failure', commit.state
      assert_enqueued_with(job: ProcessMergeRequestsJob, args: [@commit.stack]) do
        commit.create_status_from_github!(github_status)
        assert_equal 'success', commit.state
      end
    end
```
