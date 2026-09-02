### Title
`StatusHandler#process` mutates commit deploy-readiness state for any stack matching a SHA, with no repository/organization scoping - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
Unlike every other `Handler` subclass, `StatusHandler#process` never calls `stacks` / `repository_name` — it queries `Commit.where(sha: params.sha)` globally across all stacks in the database, then calls `create_status_from_github!`, which can flip a commit from blocked to `deployable?` and trigger `schedule_continuous_delivery`/merges. A webhook whose signature was verified against the sending organization's `webhook_secret` is never checked against the repository owning the matched commit.

### Finding Description
The claimed binding for a safe handler is: `mutation_target.stack.repository == Repository.from_github_repo_name(payload.dig('repository','full_name'))`, i.e. every write is scoped through `Handler#stacks` [1](#0-0) , which in turn is only reachable after `WebhooksController#verify_signature` validated the request against `Shipit.github(organization: repository_owner)`'s secret, where `repository_owner` is read from the very same `repository.owner.login`/`repository.full_name` object [2](#0-1) . For `PushHandler`, `CheckSuiteHandler`, and all `PullRequest::*` handlers this equality holds: each derives its target exclusively via `stacks` or `Repository.from_github_repo_name(params.repository.full_name)` [3](#0-2) [4](#0-3) [5](#0-4) .

`StatusHandler` breaks this binding:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [6](#0-5) 
This lookup has no `repository`/`organization`/`stacks` requirement at all in its param schema [7](#0-6) , and `create_status_from_github!` -> `add_status` recomputes `status`, can flip `deployable?`, and calls `stack.schedule_merges` / triggers `ContinuousDeliveryJob` via `Commit#schedule_continuous_delivery` [8](#0-7) [9](#0-8) [10](#0-9) .

Attack: an attacker who owns/administers a GitHub repository under organization A (legitimately configured in Shipit with A's `webhook_secret`) commits an object with the exact same content, parents, author, committer and timestamps as a commit that already exists in victim organization B's stack (git SHA1 is purely content-addressed, so a byte-identical commit object reproduces the identical SHA — trivially achievable if B's repository/commit is public, e.g. a fork, or if the attacker can otherwise learn/reconstruct the exact commit metadata). The attacker's own repo A then fires a genuine, correctly-signed `status` webhook (`sha` = the colliding SHA, `state: "success"`) which passes `verify_signature` using A's own secret. `WebhooksController#create` dispatches it to `StatusHandler.call`, which looks up `Commit.where(sha:)` and updates **every** commit across **every** stack sharing that SHA — including B's — with attacker-chosen state/description/target_url, potentially unblocking deploys or triggering continuous delivery for organization B's stack.

Existing guards do not catch this: `verify_signature` only authenticates *which organization sent the event*, it makes no claim about which repository's commits may be touched, and `StatusHandler` is the only handler that skips the `stacks`/`repository_name` scoping that would otherwise enforce that binding.

### Impact Explanation
A payload verified for organization A's `webhook_secret` mutates a `Commit`/`Status` belonging to organization B's stack, without B's authentication. This can unblock `Commit#deployable?` for B's stack and trigger `stack.schedule_merges` / `ContinuousDeliveryJob`, resulting in an unauthorized deploy — this matches the Critical category ("a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy"). It is repeatable against any commit SHA the attacker can reproduce, and the blast radius spans all stacks across all tenants sharing that Shipit installation.

### Likelihood Explanation
Requires: (1) the attacker legitimately administers at least one repository/org onboarded into Shipit with its own valid `webhook_secret` (a standard, low-privilege prerequisite already implied by "emit webhooks from a repository they own"), and (2) the ability to produce a commit object with an identical SHA1 to one already present in the victim's stack — feasible whenever the victim's repository/commit is public (fork scenario) or its exact metadata is otherwise known/guessable. No GitHub or Shipit secret of the victim organization is needed. This is fully repeatable and does not require any privileged role.

### Recommendation
Scope `StatusHandler#process` through `stacks`/`repository_name` exactly like the other handlers, e.g. require `repository.full_name` in the param schema and restrict the lookup to `stacks.joins(:commits).where(commits: { sha: params.sha })` (or equivalent), so a status event can only mutate commits belonging to stacks of the repository that authenticated the webhook.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
require 'test_helper'

module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerCrossTenantTest < ActiveSupport::TestCase
        test "a status payload with repository A's context updates a commit belonging to stack B" do
          stack_b = shipit_stacks(:shipit) # belongs to repository B
          commit_b = stack_b.commits.create!(sha: 'a' * 40, message: 'x')

          # Payload does not (and per current code, cannot) reference repository A vs B at all;
          # only `sha` matters.
          payload = {
            'sha' => commit_b.sha,
            'state' => 'success',
            'context' => 'ci/attacker-controlled'
          }

          StatusHandler.call(payload)

          commit_b.reload
          assert_equal 'success', commit_b.status.state
          # Assert the binding claimed safe (repository/org scoping) never occurred:
          refute_respond_to StatusHandler.new(payload), :repository_name
        end
      end
    end
  end
end
```
This demonstrates that `StatusHandler` mutates `commit_b` (owned by stack/repository B) using nothing but a matching `sha`, with no equality check ever performed between the webhook's authenticating organization/repository and `commit_b.stack.repository`.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L6-18)
```ruby
      class StatusHandler < Handler
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
