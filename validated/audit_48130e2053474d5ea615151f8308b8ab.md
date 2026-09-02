### Title
StatusHandler never checks `params.repository`, letting a validly-signed webhook from any GitHub org create/overwrite commit statuses on stacks belonging to a different repository - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler`'s `params do ... end` block only requires `:sha` and `:state`, and its `#process` method resolves the target purely via `Commit.where(sha: params.sha)`, with no reference to `payload['repository']` at all. Because the index on `commits` is `(stack_id, sha)` rather than a global uniqueness constraint, the same `sha` can legitimately exist in multiple stacks (e.g. forks/mirrors sharing history), so a status webhook that is validly signed for organization A can mutate `Commit` rows belonging to a stack under organization B.

### Finding Description
**Binding claimed vs. actual code:**
- Claimed binding: `repository_owner` (`params.dig('repository','owner','login')`, used in `WebhooksController#verify_signature` at `app/controllers/shipit/webhooks_controller.rb:24-30,59-62`) == the repository whose data is mutated inside the handler.
- Actual code: `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`. It never reads `payload['repository']`, and the `params` block (`status_handler.rb:7-18`) never declares `requires :repository`, unlike every other handler (`ReopenedHandler`, `OpenedHandler`, `ClosedHandler`, `EditedHandler`, `LabelCapturingHandler`, `UnlabeledHandler`, `AssignedHandler`) which all declare `requires :repository { requires :full_name, String }` and use it via `Repository.from_github_repo_name(params.repository.full_name)` to scope `#process`.
- The base `Handler#stacks` helper (`app/models/shipit/webhooks/handlers/handler.rb:32-38`) does scope by `payload.dig('repository','full_name')`, but `StatusHandler` does not call `stacks` at all — it queries `Commit` directly and unscoped.

**Why `verify_signature` does not close the gap:** `WebhooksController#verify_signature` only decides *which webhook secret* to HMAC-verify the raw body against, by looking up `Shipit.github(organization: repository_owner)` (`lib/shipit.rb:170-181`). It proves the request came from a party who knows the secret for organization `repository_owner`; it says nothing about which `repository`/`stack`/`Commit` rows the payload is permitted to touch. `StatusHandler` receives the already-parsed `params` (from `WebhooksController#create`, `webhooks_controller.rb:11-12`) and independently decides what to mutate using only `sha`, ignoring the organization the signature was checked against.

**Attacker path:** An attacker who has legitimate ability to trigger a "status" webhook for *some* GitHub organization/repo that Shipit is configured to trust (e.g. they own or have CI access to a repo under an org configured in `secrets.github`, per the attacker model's "emit webhooks from a repository they own") can send/produce a `status` event whose `sha` matches a commit sha that also exists in a *different* stack/repository tracked by Shipit (git commit shas are content-derived, so shared history between a fork and its upstream, or between two mirrored repos, produces identical shas across distinct `Commit` rows in distinct stacks). Because `Commit.where(sha: ...)` is global and unscoped, `commit.create_status_from_github!(params)` (`status_handler.rb:22`, `app/models/shipit/commit.rb:165-169`) is invoked for every matching `Commit` row across every stack, writing a forged status (e.g. `state: 'success'`) onto a commit that belongs to a repository/stack the attacker never authenticated against.

### Impact Explanation
Commit statuses gate deployability in Shipit (`Commit#state`/`add_status`/`deployable_status` hooks, see `app/models/shipit/commit.rb` and `test/models/commits_test.rb:671-712`). A forged "success" status written to a foreign stack's commit can make an otherwise CI-failing or CI-pending commit appear deployable, directly matching the Critical impact category "a payload for one repository mutating another's stack, commit ... or an unauthorized deploy." This is repeatable per commit sha collision and is not limited to a single tenant — any two stacks that ever share commit history (forks, mirrors, vendored/subtree merges) are exposed to cross-tenant status forgery.

### Likelihood Explanation
Preconditions: (1) the attacker must be able to produce a `status` webhook that passes `verify_signature` for *some* organization Shipit trusts — this typically requires legitimate access to trigger CI/status events on a repo under a Shipit-configured org (consistent with the stated attacker capability of "emit webhooks from a repository they own"); (2) a `sha` collision across stacks, which is realistically achievable by forking or mirroring a tracked upstream repository and having a webhook fire for a commit shared with that upstream. No secrets, sessions, or privileged roles are required beyond ordinary GitHub repo ownership within a trusted org. This is fully repeatable and does not depend on any race condition or timing.

### Recommendation
Add `requires :repository { requires :full_name, String }` to `StatusHandler`'s params block, and scope `#process` through the handler's existing `stacks`/`Repository.from_github_repo_name` mechanism (e.g. `stacks.joins(:commits).where(commits: { sha: params.sha })` or filter `Commit.where(sha: params.sha)` down to `stack_id`s belonging to `Repository.from_github_repo_name(params.repository.full_name)`), matching the pattern already used by `PushHandler`/`CheckSuiteHandler`/the `PullRequest` handlers.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
require 'test_helper'

module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerTest < ActiveSupport::TestCase
        test "StatusHandler param schema excludes :repository unlike other handlers" do
          status_keys = StatusHandler.param_parser.instance_variable_get(:@parameters).keys
          reopened_keys = PullRequest::ReopenedHandler.param_parser.instance_variable_get(:@parameters).keys

          refute_includes status_keys, :repository
          assert_includes reopened_keys, :repository
        end

        test "StatusHandler.call succeeds and mutates a commit in a stack different from the signing org" do
          stack_a = shipit_stacks(:shipit)     # belongs to org "shopify" in fixtures
          stack_b = shipit_stacks(:cyclimse)   # belongs to a different org/repo in fixtures

          shared_sha = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
          commit_a = stack_a.commits.create!(sha: shared_sha, author: shipit_users(:shipit),
                                              authored_at: Time.now, committer: shipit_users(:shipit),
                                              committed_at: Time.now, message: 'shared history')
          commit_b = stack_b.commits.create!(sha: shared_sha, author: shipit_users(:shipit),
                                              authored_at: Time.now, committer: shipit_users(:shipit),
                                              committed_at: Time.now, message: 'shared history')

          # Payload has no 'repository' key at all, or names stack_a's repo, yet targets both stacks' commits
          payload = { 'sha' => shared_sha, 'state' => 'success' }

          assert_nothing_raised { StatusHandler.call(payload) }

          assert_equal 'success', commit_a.reload.state
          assert_equal 'success', commit_b.reload.state # cross-tenant mutation, no repository binding enforced
        end
      end
    end
  end
end
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-28)
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
  end
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

**File:** app/controllers/shipit/webhooks_controller.rb (L1-64)
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
end
```

**File:** lib/shipit.rb (L170-200)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L1-20)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      module PullRequest
        class ReopenedHandler < Shipit::Webhooks::Handlers::Handler
          params do
            requires :action, String
            requires :number, Integer
            requires :pull_request do
              requires :id, Integer
              requires :number, Integer
              requires :url, String
              requires :title, String
              requires :state, String
              requires :additions, Integer
              requires :deletions, Integer
              requires :head do
                requires :sha, String
```

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-27)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
    end
  end
end
```
