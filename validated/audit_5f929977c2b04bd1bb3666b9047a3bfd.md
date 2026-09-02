### Title
StatusHandler#process resolves `Commit.where(sha:)` globally, so a webhook authenticated for one org can forge a status on any other tenant's commit - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` never calls the base `Handler#stacks`/`repository_name` scoping helper and instead does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`, which is unscoped by repository, stack, or organization. Because `WebhooksController#verify_signature` only checks that the request's `X-Hub-Signature` matches the GitHub App/`webhook_secret` for the organization named in the payload's `repository.owner.login` (or `organization.login`), and that organization value is fully attacker-controlled JSON independent of the SHA actually being updated, an attacker who legitimately controls one organization's registered app can supply a body naming their own org (to pass signature verification) while giving a `sha` value belonging to a commit in a completely different tenant's stack, causing a forged `Status` to be written against that foreign commit.

### Finding Description
The binding that should hold is: **organization whose `webhook_secret` verified the raw body == organization/repository owning the `Commit` row being mutated**. Trace:

1. `WebhooksController#verify_signature` computes `repository_owner` from `params.dig('repository','owner','login')` (or `organization.login`) and does `Shipit.github(organization: repository_owner).verify_webhook_signature(...)` [1](#0-0) . This authenticates only that the sender knows the secret configured for that named org - it says nothing about which `sha`/commit is inside the payload body being processed downstream.
2. `Shipit::Webhooks::Handlers::Handler` defines a `stacks`/`repository_name` helper meant to scope handler logic to `Repository.from_github_repo_name(payload.dig('repository','full_name'))&.stacks` [2](#0-1) , and other handlers (e.g. `PullRequest::OpenedHandler`, `ClosedHandler`, `LabeledHandler`) correctly resolve `Shipit::Repository.from_github_repo_name(params.repository.full_name)` before acting [3](#0-2) .
3. `StatusHandler#process`, however, does not use `repository_name`, `stacks`, or any repository/org check at all - it only requires `sha`, `state`, and optional fields, and resolves the target purely by `Commit.where(sha: params.sha)` [4](#0-3) .
4. `Commit#sha` is not a global unique/scoped-per-tenant guarantee enforced at this query - the lookup spans the entire `commits` table across all repositories/stacks. Since a commit SHA is public information for any repository the attacker can view on GitHub (commit pages, PR diffs, etc.), the attacker does not need any secret information about the victim to target a specific commit.
5. `commit.create_status_from_github!(params)` then creates a `Status` row on that (foreign) commit and runs `add_status`, which can flip `state`, fire `Hook.emit(:commit_status/:deployable_status, ...)`, and call `stack.schedule_merges` when the new status is `pending` or `success` [5](#0-4) . If the victim stack has `continuous_deployment` enabled, this status change is exactly the trigger that other tests show enqueues a new `Deploy` [6](#0-5) .

**Attacker's exact request**: attacker owns/controls an app/org "attacker-org" registered on the shared Shipit instance and knows its `webhook_secret`. They POST `/webhooks` with header `X-Github-Event: status`, a JSON body whose `repository.owner.login` (and/or `organization.login`) is `"attacker-org"` (so `verify_signature` succeeds using attacker-org's key), and `sha` set to a real commit SHA copied from the victim's public repository/stack, with `state: "success"`. The `repository.full_name` field can be anything (or even the attacker's own repo name) - it is read nowhere in `StatusHandler`.

**Why existing guards fail**: `verify_signature` binds trust to the *organization name declared in the payload*, not to any property of the SHA/commit being mutated; nothing cross-checks that the commit found by `Commit.where(sha:)` actually belongs to a stack whose repository maps to that same organization. `ExplicitParameters` schema for `StatusHandler` only validates types/presence of `sha`, `state`, etc. - it enforces no ownership relationship. `Handler#stacks` exists precisely to close this gap but is dead code from `StatusHandler`'s perspective.

### Impact Explanation
An attacker with a legitimately-registered app/org on the same Shipit instance can write forged `Status` rows onto commits belonging to any other tenant's stack merely by knowing a target SHA (public GitHub data), with no need to compromise the victim's `webhook_secret`, GitHub token, or session. This can flip CI status to `success`, triggering `stack.schedule_merges` and, on stacks with `continuous_deployment` enabled, an unauthorized `Deploy`. This matches the "Critical" category: a payload authenticated for one repository/organization mutating another tenant's `Commit`/stack, potentially causing an unauthorized deploy.

### Likelihood Explanation
Preconditions are modest and already granted by the question: the attacker needs any app/org registered on the shared Shipit host (their own tenant) so they can produce a validly-signed body, and knowledge of a target commit SHA in the victim repo (trivially public for any repo the attacker can view, e.g. via GitHub commit history or PR pages). No GitHub App private key, `secret_key_base`, or victim `webhook_secret` is required. The attack is a single unauthenticated-looking HTTP POST and is fully repeatable against arbitrary SHAs/stacks on the instance.

### Recommendation
In `StatusHandler`, require and validate `repository.full_name` (or `repository.owner.login`) in the `params` schema, resolve `Repository.from_github_repo_name(...)`, and scope the commit lookup through that repository's stacks (e.g. `stacks.joins(:commits... )` or filter `Commit.where(sha: params.sha, stack: Repository.from_github_repo_name(repository_name)&.stacks)`), mirroring the pattern already used in `PullRequest::*Handler` classes and the base `Handler#stacks` helper. Additionally, consider validating that `repository.owner.login` used for `verify_signature` matches `repository.full_name`'s owner segment before dispatch, so a single payload cannot declare two inconsistent organizations.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
require 'test_helper'

module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerCrossTenantTest < ActiveSupport::TestCase
        test "#process never scopes by repository and Repository.from_github_repo_name is not invoked" do
          victim_stack = shipit_stacks(:shipit) # belongs to org "shopify" in fixtures
          victim_commit = victim_stack.commits.first

          # Payload claims an unrelated / attacker-controlled repository
          payload = {
            'sha' => victim_commit.sha,
            'state' => 'success',
            'repository' => { 'full_name' => 'attacker-org/attacker-repo' }
          }

          Shipit::Repository.expects(:from_github_repo_name).never

          assert_difference -> { victim_commit.statuses.count }, 1 do
            StatusHandler.call(payload)
          end

          assert_equal 'success', victim_commit.reload.state
        end
      end
    end
  end
end
```
This demonstrates both sides of the binding are violated: the SQL executed by `#process` (`Commit.where(sha: params.sha)`) never joins or filters on `repository`/`stack`, and `Repository.from_github_repo_name` — the only mechanism that would enforce "authenticated org == owning org" — is never called, so a payload naming an unrelated `repository.full_name` still successfully mutates the victim's `Commit`.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L6-24)
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

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
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

**File:** test/models/commits_test.rb (L233-243)
```ruby
    test "updating state to success triggers new deploy when stack has continuous deployment" do
      @stack.reload.update(continuous_deployment: true)
      @stack.deploys.destroy_all

      assert_difference "Deploy.count" do
        assert_enqueued_with(job: ContinuousDeliveryJob, args: [@stack]) do
          @stack.commits.last.statuses.create!(stack_id: @stack.id, state: 'success', context: 'ci/travis')
        end
        ContinuousDeliveryJob.new.perform(@stack)
      end
    end
```
