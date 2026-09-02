### Title
Cross-stack `Status` write via unscoped SHA lookup in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits by bare SHA across the entire database with no repository/stack scoping, unlike every other handler (e.g. `PushHandler`) which restricts writes to `stacks` derived from the payload's `repository.full_name`. Any properly-signed `status` webhook (which an attacker can generate legitimately from their own GitHub repository/org) can therefore create a `Status` row on a victim's `Commit`, provided the two repositories ever share a commit SHA (forks, shared upstream history, mirrored/multi-environment stacks tracking the same physical repo).

### Finding Description
The broken binding is: `Status.stack_id` (and the `Commit` it is attached to) **should** equal the stack that belongs to the repository whose GitHub App signature was verified for this specific webhook (`repository_owner`/`repository.full_name` in the payload). Instead: [1](#0-0) 

`process` runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — it never touches `stacks`/`Repository.from_github_repo_name`, the helper every other handler uses: [2](#0-1) [3](#0-2) 

`WebhooksController#create` only verifies that the signature matches the organization named in the payload (`repository_owner`); it does not further constrain which `Commit`/`Stack` rows the handler is allowed to mutate: [4](#0-3) [5](#0-4) 

So an attacker who owns/controls a GitHub repository (their own repo or a fork of the victim's public upstream repo) that Shipit has a valid GitHub App/webhook secret for can trigger a real, correctly-signed `status` event (e.g. by wiring up a real `codecov/project` integration on their own repo, or replaying one) for a SHA that also exists as a `Commit` row in a victim's stack — this happens whenever both stacks track overlapping git history (a fork of a public repo, a mirror, or multiple environment stacks tracking the same physical repository). `Commit.where(sha:)` matches the victim's `Commit` too, and `create_status_from_github!` is called on it: [6](#0-5) 

This creates/writes a `Status` scoped to the victim's `stack_id`, and immediately re-evaluates deployability/blocking through `add_status`, `Status::Group`, and `required_statuses`/`blocking_statuses`: [7](#0-6) [8](#0-7) [9](#0-8) 

A `failure` state on a context in `stack.blocking_statuses`/`required_statuses` flips `Commit#deployable?`/`#blocked?`, which is consumed by `Commit#schedule_continuous_delivery` and downstream `ContinuousDeliveryJob`: [10](#0-9) [11](#0-10) 

None of the listed guards prevent this: `verify_signature` only checks the signature is valid for *some* org (the attacker's own org, legitimately), not that the payload's SHA belongs to that org's repository; `ExplicitParameters` only validates types (`sha`, `state`, `context` are plain strings); there is no `Repository`/`stacks` scoping applied inside `StatusHandler` at all, in contrast to `PushHandler`.

### Impact Explanation
A single correctly-signed `status` webhook from an attacker-controlled repository writes a `Status` row into a victim stack's `Commit` that the attacker's repository never authenticated for. Because `blocking?`/`required?`/`deployable?` are derived directly from these `Status.context`/`state` values, this can flip a victim commit from deployable to blocked (or vice versa if the attacker sends a fabricated `success`), and on stacks with continuous deployment/auto-triggered deploys running under a configured bot identity, this can suppress or unblock an automatic deploy — a payload for one repository mutating another's stack/commit state, matching the "Critical: unauthorized deploy/rollback triggered by a payload for one repository mutating another's stack/commit" category. The attack is repeatable against any victim stack whose commit history overlaps with a repository the attacker controls (forks of public/open-source repos are the common case) and is not limited to one SHA — it works for every shared commit.

### Likelihood Explanation
Preconditions: the attacker needs a GitHub repository/org for which Shipit already has a valid GitHub App/webhook secret configured (i.e., any onboarded org/repo they control, including a fork of the victim's tracked repo, or their own repo in a multi-tenant Shipit install), and a victim stack whose `Commit` table contains a `Commit` row with the same SHA (achieved automatically whenever the victim stack has synced a commit that is also reachable from the attacker's repository, e.g. shared upstream history via fork, or multiple stacks/environments tracking the same physical repository). No Shipit session, API token, or GitHub secret is required beyond what the attacker already legitimately possesses for their own repo. This is low-cost and fully repeatable — every new shared SHA is a fresh opportunity, and no rate limiting or additional authorization is enforced by `StatusHandler`.

### Recommendation
Scope `StatusHandler#process` the same way `PushHandler` does: resolve `stacks` from `Repository.from_github_repo_name(repository_name)` (the `repository.full_name` in the payload) and restrict the `Commit` lookup to `Commit.where(sha: params.sha, stack_id: stacks.select(:id))` (or iterate `stacks` and query each stack's `commits.find_by(sha:)`), instead of an unscoped `Commit.where(sha:)` across the entire database.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`, using existing fixtures):

```ruby
test "status handler must not write a Status for a commit belonging to a different repository/stack" do
  attacker_repo_payload = { 'repository' => { 'full_name' => 'attacker/other-repo' } }
  victim_stack = shipit_stacks(:shipit) # or a fixture stack with bot_login/Shipit.user auto-deploy configured
  victim_commit = shipit_commits(:first) # belongs to victim_stack, sha shared with attacker's history

  before = victim_commit.reload.deployable?

  payload = attacker_repo_payload.merge(
    'sha' => victim_commit.sha,
    'state' => 'failure',
    'context' => 'codecov/project'
  )

  assert_no_difference -> { victim_commit.statuses.count } do
    Shipit::Webhooks::Handlers::StatusHandler.call(payload)
  end

  after = victim_commit.reload.deployable?
  assert_equal before, after # binding: Status.stack_id must equal attacker's authenticated stack, never victim_stack.id
end
```

Currently this assertion fails: `StatusHandler.call(payload)` creates a `Status` on `victim_commit` because `Commit.where(sha: params.sha)` matches it regardless of `payload['repository']['full_name']`, demonstrating the cross-stack write.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

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

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** app/models/shipit/commit.rb (L360-386)
```ruby
    private

    def message_parser
      @message_parser ||= CommitMessage.new(message)
    end

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

**File:** app/models/shipit/status/group.rb (L24-32)
```ruby
      def initialize(commit, statuses)
        @commit = commit

        visible_statuses = reject_hidden(statuses.to_a.uniq(&:context))
        missing_contexts = required_statuses - visible_statuses.map(&:context)
        visible_statuses += missing_contexts.map { |c| Status::Missing.new(commit, c) }

        @statuses = visible_statuses.sort_by!(&:context)
      end
```

**File:** app/models/shipit/status/common.rb (L46-52)
```ruby
      def blocking?
        !success? && commit.blocking_statuses.include?(context)
      end

      def required?
        commit.required_statuses.include?(context)
      end
```
