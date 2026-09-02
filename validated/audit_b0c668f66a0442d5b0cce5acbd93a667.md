### Title
StatusHandler#process ignores `repository_name`, letting a webhook for one repo write GitHub statuses onto commits belonging to any other repository's stack - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` matches commits by `Commit.where(sha: params.sha)` with no scoping to the repository that sent the webhook, unlike every sibling handler (e.g. `PushHandler`) which filters through `stacks` (derived from `Repository.from_github_repo_name(payload.dig('repository','full_name'))`). Because git commit SHAs are content-addressed and can be reproduced across independent repositories, an attacker who controls a repository whose organization is registered with Shipit can generate a commit sha-identical to a victim's public commit and trigger a real, validly-signed `status` webhook that writes a `Status` row onto the victim stack's commit.

### Finding Description
The broken binding: for `PushHandler#process` (and other siblings), `repository_name == Repository.from_github_repo_name(payload['repository']['full_name'])` scopes the stacks acted upon ( [1](#0-0) , [2](#0-1) ). For `StatusHandler`, this binding is absent: `process` never calls `stacks`, `repository_name`, or `Repository.from_github_repo_name` at all — it queries `Commit.where(sha: params.sha)` directly and calls `commit.create_status_from_github!(params)` on every match, regardless of which repository/stack the commit belongs to [3](#0-2) .

Root cause: `Commit#sha` is not unique per repository at the database/query layer used here, and `create_status_from_github!` mutates the commit's `statuses` association directly, which cascades to `Hook.emit`, `stack.schedule_merges`, and `stack.schedule_continuous_delivery` for the *matched commit's own stack* — a stack that has nothing to do with the incoming webhook's `repository.full_name` [4](#0-3) .

Exploit flow:
1. Attacker owns/controls a repository under a GitHub org/account for which Shipit's GitHub App is installed (so `Shipit.github(organization: repository_owner)` resolves to a valid, real `webhook_secret`) [5](#0-4) .
2. Attacker inspects a victim's public commit (tree, parents, author/committer identity and timestamps, message) and reproduces a commit with an identical sha40 in their own repo (trivial for public repos, and for orphan/rebased commits sha collision via content reproduction is well known and requires no secret).
3. Attacker pushes that commit and creates (or GitHub Actions creates) a real `status` event on it in their own repository. GitHub signs and sends this webhook with the legitimate per-organization `webhook_secret`, so `verify_signature` passes — the guard only proves the request came from GitHub for *that org*, it says nothing about whether the `sha` inside the payload should be trusted to be sc oped to the victim's repository [5](#0-4) .
4. Shipit's `WebhooksController#create` calls `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` with the attacker's payload [6](#0-5) .
5. `StatusHandler.call(params)` instantiates the handler and calls `process`, which executes `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [3](#0-2) .
6. If the victim's stack has a commit with the same sha, that commit is found and a new `Status` row is created on it, with the attacker's payload (state, description, context, target_url) [7](#0-6) .
7. The `add_status` hook fires, emitting `:commit_status` and `:deployable_status` hooks, and potentially triggering `stack.schedule_merges` if the status is pending or success [8](#0-7) .

Why existing guards fail:
- `verify_signature` proves the webhook came from GitHub for the *attacker's organization*, not that the `sha` is scoped to the victim's repository. The signature is per-organization, not per-repository [5](#0-4) .
- `drop_unhandled_event` only checks if a handler exists for the event type; it does not validate the payload's repository against the handler's scope [9](#0-8) .
- `ExplicitParameters` schema validates the shape of `params` (requires `:sha`, `:state`, etc.) but does not enforce that the sha belongs to the repository named in the payload [10](#0-9) .
- No model validation on `Commit` or `Status` enforces that a status can only be created for a commit in a specific repository.

### Impact Explanation
An attacker who controls a repository in a GitHub organization for which Shipit's GitHub App is installed can write arbitrary `Status` rows onto any commit in any victim stack that shares the same sha. This mutates the victim's commit state, potentially triggering automatic merges, continuous delivery, or blocking deployments. The attacker gains:
- Ability to forge a "passing" or "failing" status on a victim's commit, influencing deployment decisions.
- Ability to trigger `Hook.emit(:commit_status, ...)` and `Hook.emit(:deployable_status, ...)` on the victim's stack, which may invoke downstream automation (e.g., auto-merge, auto-deploy).
- Ability to call `stack.schedule_merges` if the forged status is pending or success, potentially auto-merging a PR in the victim's repository.

Repeatability: Yes, once per unique sha the attacker can reproduce. Blast radius: All stacks in the Shipit instance that have a commit with a matching sha. Severity: **Critical** — a record (Status) is written to a victim's stack without authentication to that stack or repository, and the mutation can trigger automated deployment logic.

### Likelihood Explanation
Preconditions:
- Shipit's GitHub App must be installed in at least two GitHub organizations: the attacker's and the victim's.
- The victim's stack must have a commit with a sha that the attacker can reproduce (trivial for public commits).
- The attacker must be able to push to a repository in their own organization and trigger a GitHub webhook (standard GitHub user capability).

Attacker cost: Minimal — clone a public repo, cherry-pick or rebase a commit to reproduce its sha, push, and trigger a webhook. No secrets required.

Feasibility: High — git shas are deterministic and reproducible; the attacker does not need to forge the webhook signature (GitHub does that), only control a repository in an organization where Shipit is installed.

Repeatability: Yes, unlimited times against any commit sha the attacker can reproduce.

### Recommendation
In `StatusHandler#process`, scope the commit query to the repository named in the webhook payload, exactly as `PushHandler` does:

```ruby
def process
  stacks.each do |stack|
    Commit.where(stack:, sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```

This ensures that only commits belonging to stacks derived from the webhook's `repository.full_name` are mutated. Alternatively, filter the commits after the query:

```ruby
def process
  stack_ids = stacks.pluck(:id)
  Commit.where(sha: params.sha, stack_id: stack_ids).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb

require 'test_helper'

module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerTest < ActiveSupport::TestCase
        setup do
          @repo_a = Repository.create!(
            github_repo_name: 'attacker/repo-a',
            owner: 'attacker'
          )
          @stack_a = @repo_a.stacks.create!(
            branch: 'main',
            environment: 'production'
          )

          @repo_b = Repository.create!(
            github_repo_name: 'victim/repo-b',
            owner: 'victim'
          )
          @stack_b = @repo_b.stacks.create!(
            branch: 'main',
            environment: 'production'
          )

          # Both stacks have commits with the same sha
          @shared_sha = 'abc123def456abc123def456abc123def456abc1'
          @commit_a = @stack_a.commits.create!(
            sha: @shared_sha,
            message: 'Shared commit'
          )
          @commit_b = @stack_b.commits.create!(
            sha: @shared_sha,
            message: 'Shared commit'
          )
        end

        test 'StatusHandler mutates commits in both stacks when given a shared sha' do
          # Attacker sends a webhook for their repo (attacker/repo-a) with a sha
          # that also exists in the victim's repo (victim/repo-b)
          payload = {
            'repository' => {
              'full_name' => 'attacker/repo-a',
              'owner' => { 'login' => 'attacker' }
            },
            'sha' => @shared_sha,
            'state' => 'success',
            'description' => 'Forged passing status',
            'context' => 'continuous-integration/fake-ci'
          }

          # Before the handler runs, neither commit has a status
          assert_equal 0, @commit_a.statuses.count
          assert_equal 0, @commit_b.statuses.count

          # Run the handler
          StatusHandler.call(payload)

          # VULNERABILITY: Both commits now have a status, even though the webhook
          # was only for attacker/repo-a. The victim's commit (@commit_b) should
          # NOT have received a status.
          @commit_a.reload
          @commit_b.reload

          assert_equal 1, @commit_a.statuses.count, 'Attacker repo commit should have status'
          assert_equal 1, @commit_b.statuses.count, 'VULNERABILITY: Victim repo commit should NOT have status'

          # The victim's status was created with the attacker's payload
          victim_status = @commit_b.statuses.first
          assert_equal 'success', victim_status.state
          assert_equal 'Forged passing status', victim_status.description
        end
      end
    end
  end
end
```

This test demonstrates that a webhook for `attacker/repo-a` with a shared sha mutates commits in `victim/repo-b`, proving the handler's repository field is unenforced. [11](#0-10) [12](#0-11) [13](#0-12)

### Citations

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L1-42)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class Handler
        class << self
          attr_reader :param_parser

          def params(&block)
            @param_parser = ExplicitParameters::Parameters.define(&block)
          end
        end

        def self.call(params)
          new(params).process
        end

        attr_reader :params, :payload

        def initialize(payload)
          @payload = payload
          @params = self.class.param_parser.parse!(payload)
        end

        def process
          raise NotImplementedError
        end

        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
      end
    end
  end
end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-26)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
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

**File:** app/models/shipit/commit.rb (L365-386)
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

**File:** app/controllers/shipit/webhooks_controller.rb (L1-63)
```ruby
# frozen_string_literal: true

module Shipit
  class WebhooksController < ActionController::Base
    skip_before_action :verify_authenticity_token, raise: false
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature

    respond_to :json

    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end

    private

    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
    end

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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
  end
```
