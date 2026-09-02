Confirmed: `Status` rows are scoped per-`stack_id` and `commit_id`, and `Commit#status`/`success?` only aggregates `statuses` belonging to that specific `Commit` row (`app/models/shipit/commit.rb:219`, `app/models/shipit/status.rb:11-12`). `StatusHandler#process` however resolves target commits by `sha` alone, with zero scoping to the webhook's own repository/organization:

```ruby
# app/models/shipit/webhooks/handlers/status_handler.rb:20-24
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```

`WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-38`) only authenticates that the payload was signed for the *organization* named in `payload["repository"]["owner"]["login"]` — it never constrains which `sha`s that webhook is allowed to touch, and `StatusHandler`'s `params` schema doesn't even declare/require a `repository` field, so nothing downstream re-checks it either.

### Title
Cross-stack CI status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` corrupts `Commit#deployable?` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` matches incoming GitHub `status` webhook events to `Commit` rows purely by `sha`, with no check that the commit's own stack/repository matches the webhook's originating repository. Because `Commit` rows for the same sha can exist under different `Stack`/`Repository` records (multiple stacks tracking the same repo, or a fork sharing pre-fork history), a legitimately-signed status webhook for repository/stack B writes a `Status` row against stack A's unrelated `Commit` record too, corrupting `Commit#deployable?` for stack A.

### Finding Description
The broken binding: `commit.deployable?` (consulted by `Api::DeploysController#create`, `app/controllers/shipit/api/deploys_controller.rb:22`) is supposed to equal *"stack A's own repository's CI truth for this sha"* — i.e. `commit.deployable? == CI_state(stack_A.repository, sha)`. In reality it equals `success?(any Status row attached to this specific Commit#id)`, and that `Commit#id` can receive `Status` rows created by a webhook whose payload named a *different* repository, because the lookup key is only `sha`.

Path: GitHub sends a `status` event for repository B → `WebhooksController#create` (`app/controllers/shipit/webhooks_controller.rb:10-15`) dispatches to `Webhooks.for_event('status')` → `Handlers::StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`. This query is **global across the entire `commits` table**, not scoped by `stack_id`, `repository_id`, or anything derived from `params['repository']`. If stack A also has a `Commit` row with the same `sha` (same repo tracked as two stacks/environments, or a fork/mirror sharing history with the upstream repo tracked as stack A), that row also receives a `Status` (`Commit#create_status_from_github!` → `add_status` → `statuses.replicate_from_github!(stack_id, github_status)`, `app/models/shipit/commit.rb:165-169`, `app/models/shipit/status.rb:24-33`), using `stack_id = commit.stack_id`, i.e. stack A's own id — so the forged record looks completely native to stack A.

`Commit#deployable?` (`app/models/shipit/commit.rb:227-229`) then evaluates `!locked? && (stack.ignore_ci? || (success? && !blocked?))`, where `success?` delegates to `status` which is derived solely from `statuses` (`has_many :statuses`, ordered desc) tied to that `Commit#id` (`app/models/shipit/commit.rb:12,219`). Since the forged `Status` was attached to stack A's `Commit` row, `commit.deployable?` becomes `true` for stack A even though no CI system belonging to stack A's actual repository ever reported success.

`Api::DeploysController#create`'s guard, `param_error!(:require_ci, "Commit is not deployable") if params.require_ci && !commit.deployable?` (`app/controllers/shipit/api/deploys_controller.rb:22`), then passes incorrectly, and `stack.trigger_deploy` proceeds — an authorized-but-narrowly-scoped API client for stack A obtains a deploy gated on CI it never earned.

Existing guards don't stop this: `verify_signature` only authenticates the *organization* named in the payload against that org's webhook secret — it says nothing about which `sha`/stack the event is allowed to affect (`app/controllers/shipit/webhooks_controller.rb:24-38`). `StatusHandler`'s `ExplicitParameters` schema doesn't require or use a `repository` field at all (`app/models/shipit/webhooks/handlers/status_handler.rb:7-18`). `ApiClient`/`require_permission :deploy, :stack` correctly scope the *API call* to stack A but do nothing about the *data* `commit.deployable?` reads, which is the compromised part per the question's own precondition.

### Impact Explanation
An API client legitimately scoped only to stack A can obtain a `require_ci: true`-gated deploy for stack A driven by CI data that never came from stack A's own repository. This is an unauthorized deploy decision — matches the "Critical: a payload for one repository mutating another's stack, commit, task ... an unauthorized deploy" category. It's repeatable against any pair of stacks/repositories that happen to share a `Commit#sha` (same repo tracked under two stacks/environments is the common real-world case in Shipit; forked repos with shared pre-fork history is another). Blast radius: any tenant/stack sharing sha history with another tracked repo in the same Shipit instance.

### Likelihood Explanation
Requires only that (a) the attacker (or any legitimately signed CI system) can post a `status` webhook event for *some* repository tracked by Shipit — no elevated Shipit privilege beyond normal GitHub CI integration on that repo — and (b) a `Commit#sha` collision exists between that repository/stack and the target stack A. The most likely real-world trigger is the very common Shipit pattern of tracking one GitHub repo under multiple `Stack`s (e.g., staging/production or multiple review environments) which by construction share commit SHAs; no cryptographic SHA-1 collision is needed. Attacker cost is low and the action is repeatable per shared commit.

### Recommendation
Scope the `Commit` lookup in `StatusHandler#process` to the webhook's originating repository (e.g., resolve `Stack`/`Repository` from `params['repository']['full_name']` and filter `Commit.where(sha:, stack: { repository_id: ... })`, or join through `stack.repository.github_repo_name` before writing any `Status`), so a status event can only affect commits that belong to the repository that actually generated it.

### Proof of Concept
minitest in `test/models/shipit/webhooks/handlers/status_handler_test.rb` style (or extend `test/controllers/webhooks_controller_test.rb`):
1. Create two stacks, `stack_a` (repository "org/app", environment production) and `stack_b` (repository "org/app-fork" or same repository different environment), each with a `Commit` row sharing the same `sha`.
2. Assert precondition: `commit_a.deployable?` is `false` (no success status yet) for stack A.
3. Fire a `status` webhook whose payload's `repository` field names stack B (`sha` matching, `state: 'success'`), signed correctly for stack B's org.
4. Assert `commit_a.reload.deployable?` becomes `true` even though the webhook never named stack A's repository — this is the broken equality.
5. As the API-level demonstration: with an `ApiClient` scoped only to stack A (`require_permission :deploy, :stack`), `POST /api/stacks/:stack_a_id/deploys?sha=<shared_sha>&require_ci=true` returns `:unprocessable_entity` before the forged webhook, and `:accepted` after it — proving the cross-repo status write flips the `require_ci` gate for a stack the forging webhook never targeted. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** app/controllers/shipit/api/deploys_controller.rb (L1-31)
```ruby
# frozen_string_literal: true

module Shipit
  module Api
    class DeploysController < BaseController
      require_permission :deploy, :stack

      def index
        render_resources(stack.deploys_and_rollbacks)
      end

      params do
        requires :sha, String, length: { in: 6..40 }
        accepts :force, Boolean, default: false
        accepts :allow_concurrency, Boolean
        accepts :require_ci, Boolean, default: false
        accepts :env, Hash, default: {}
      end
      def create
        commit = stack.commits.by_sha(params.sha) || param_error!(:sha, 'Unknown revision')
        param_error!(:force, "Can't deploy a locked stack") if !params.force && stack.locked?
        param_error!(:require_ci, "Commit is not deployable") if params.require_ci && !commit.deployable?

        allow_concurrency = params.allow_concurrency.nil? ? params.force : params.allow_concurrency
        deploy = stack.trigger_deploy(commit, current_user, env: params.env, force: params.force,
                                                            allow_concurrency:)
        render_resource(deploy, status: :accepted)
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

**File:** app/models/shipit/commit.rb (L219-229)
```ruby
    delegate :pending?, :success?, :error?, :failure?, :blocking?, :state, to: :status

    def active?
      return false unless stack.active_task?

      stack.active_task.includes_commit?(self)
    end

    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/status.rb (L1-34)
```ruby
# frozen_string_literal: true

module Shipit
  class Status < Record
    include Common
    include DeferredTouch

    STATES = %w[pending success failure error].freeze
    enum :state, STATES.zip(STATES).to_h

    belongs_to :stack, required: true
    belongs_to :commit, required: true

    deferred_touch commit: :updated_at

    validates :state, inclusion: { in: STATES, allow_blank: true }, presence: true

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
```
