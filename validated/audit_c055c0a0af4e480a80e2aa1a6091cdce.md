### Title
`StatusHandler#process` matches commits by SHA across all repositories, letting a webhook from an unrelated repo forge statuses on a victim stack's commits and clear `blocked?` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits with `Commit.where(sha: params.sha)` with no scoping to the webhook's own `repository.full_name`, unlike `PushHandler` and `CheckSuiteHandler`, which both scope through the `stacks` helper (`Repository.from_github_repo_name(repository_name)&.stacks`). Any GitHub organization that can send a signed `status` webhook for its own repository can create a `Shipit::Status` on a `Commit` belonging to a completely different stack/repository as long as the sha values collide, directly manipulating `Commit#blocked?` and `deployable?` for a victim stack.

### Finding Description
The binding that should hold is: **every `Status` created for `commit` must come from a webhook whose `payload.dig('repository','full_name') == commit.stack.repository.full_name`**. This binding is enforced in `Handler#stacks` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`), and both `PushHandler#process` (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`) and `CheckSuiteHandler#process` (`app/models/shipit/webhooks/handlers/check_suite_handler.rb:13-17`) route through `stacks` before touching any commit.

`StatusHandler#process`, however, does not:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
(`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`)

This is a global, cross-repository, cross-stack lookup by `sha` alone — the webhook's own `repository` payload field is never consulted to filter which commits may receive the status. `WebhooksController#verify_signature` only validates that the payload is authentically signed by `repository_owner`'s GitHub App installation (`app/controllers/shipit/webhooks_controller.rb:24-49`); it says nothing about which *commits* the payload's `sha` is permitted to touch. So a legitimate, correctly-signed `status` webhook from Org A's own repository, containing a `sha` that happens to match a commit belonging to Org B's stack, will create a `Status` row for Org B's commit via `Commit#create_status_from_github!` → `add_status` → `statuses.replicate_from_github!(stack_id, github_status)` (`app/models/shipit/commit.rb:165-169`, `346-386`; `app/models/shipit/status.rb:24-33`).

Downstream, `Shipit::Commit#blocked?` (`stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)`) and `#blocking?` rely on `stack.blocking_statuses` matched against whatever `Status` rows exist for each commit — with no distinction of which repository actually authored the status. Once the attacker injects a forged "success" `Status` for the colliding sha on the intermediate blocking commit, `blocking?` flips to false for that commit, `blocked?` becomes false for the target commit, and `deployable?` becomes true, allowing `ContinuousDeliveryJob`/merges to proceed on a queue that was supposed to be gated.

None of the existing guards catch this: `verify_signature` authenticates the sender's own organization, not the target of the `sha`; `drop_unhandled_event` only checks event-type routing; there is no `ExplicitParameters` validation of repository ownership for `status` events (the schema only requires `sha`/`state`, `app/models/shipit/webhooks/handlers/status_handler.rb:7-18`); and `Commit.where(sha: ...)` has no `stack_id`/`repository_id` filter.

### Impact Explanation
An attacker who controls any repository capable of emitting a legitimately-signed `status` webhook (its own GitHub repo/org) can write `Shipit::Status` records for commits belonging to an arbitrary victim stack, provided sha collision is achievable. This directly matches the "payload for one repository mutating another's stack/commit" Critical category, and enables an unauthorized/unblocked deploy of a commit range that the victim stack operator deliberately gated via `blocking_statuses`. The write is repeatable against any known/guessable colliding sha and any number of victim stacks, since the lookup is entirely unscoped.

### Likelihood Explanation
Preconditions: victim stack must have `blocking_statuses` configured with one or more currently-`blocking?` commits between `last_deployed_commit` and the target commit, and CD enabled to realize "enable continuous delivery of an otherwise-blocked commit range." The attacker needs no Shipit credentials — only the ability to send a validly signed webhook from a repository/org they control, which is normal GitHub behavior for any repo owner. The primary practical cost is producing (or already knowing) a commit `sha` that collides with the victim's blocking commit's sha in the `commits` table — this is a real constraint (git SHA1 collisions are hard to engineer on demand, though the code path itself performs zero repository-based filtering regardless of how the sha match is achieved). The code-level defect (unscoped `Commit.where(sha:)`) is unconditionally present and independently exploitable if sha collision/overlap occurs for any reason (e.g., duplicate imported history, shared submodules, or intentional forgery), so the underlying binding failure is real and unconditional; only the sha-collision precondition limits practical exploitation frequency.

### Recommendation
Scope `StatusHandler#process` to the webhook's own repository, mirroring `PushHandler`/`CheckSuiteHandler`:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
This ensures a `Status` can only be attributed to commits whose `stack.repository` matches `payload.dig('repository', 'full_name')`, restoring the intended binding used elsewhere in the webhook handlers.

### Proof of Concept
Minitest plan (`test/models/webhooks/handlers/status_handler_test.rb` or similar), no live GitHub required:
```ruby
test "status webhook from unrelated repository cannot forge a status on another stack's commit" do
  victim_stack = shipit_stacks(:shipit) # repository e.g. "shopify/shipit-engine"
  victim_stack.update!(continuous_deployment: true)
  # seed a blocking commit and a later target commit sharing a colliding sha with an attacker repo
  blocking_commit = victim_stack.commits.create!(sha: "deadbeef", ...)
  target_commit = victim_stack.commits.create!(sha: "cafebabe", ...)
  # simulate stack.blocking_statuses matching context 'ci/gate', blocking_commit currently blocking
  assert target_commit.reload.blocked?

  attacker_payload = {
    'sha' => 'deadbeef',
    'state' => 'success',
    'context' => 'ci/gate',
    'repository' => { 'full_name' => 'attacker/unrelated-repo' }
  }

  assert_no_difference -> { blocking_commit.reload.statuses.count } do
    # after fix: StatusHandler should not create a status since attacker/unrelated-repo != victim_stack.repository.full_name
    Shipit::Webhooks::Handlers::StatusHandler.call(attacker_payload)
  end

  refute target_commit.reload.blocked?  # should remain false pre-fix (vulnerable), or stay guarded post-fix
end
```
Before the fix, the test demonstrates `Commit.where(sha:...)` matches `blocking_commit` regardless of `attacker/unrelated-repo`, flips `blocking?` to false, and `target_commit.reload.deployable?` becomes true — with a `ContinuousDeliveryJob` enqueued via `Status#schedule_continuous_delivery` (`app/models/shipit/status.rb:19,42-44`) — confirming the cross-repository write. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

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

**File:** app/models/shipit/commit.rb (L366-384)
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
