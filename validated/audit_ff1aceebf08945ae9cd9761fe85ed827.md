This confirms the divergence: `CheckSuiteHandler#process` correctly scopes via `stacks` (which is derived from `Repository.from_github_repo_name(repository_name)` in the base `Handler` class), using `payload.dig('repository', 'full_name')`. `StatusHandler#process`, by contrast, does not require or use `repository` in its params schema at all, and queries `Commit.where(sha: params.sha)` globally across every stack in the database.### Title
`StatusHandler#process` matches `status` webhook payloads to `Commit` rows globally without repository scoping, letting any org's `status` event mutate another stack's `Hook.emit` payload - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
Unlike every other webhook handler in this engine, `StatusHandler#process` never checks `payload.dig('repository', 'full_name')` or the base `Handler#stacks` scope before acting; it resolves the target purely via `Commit.where(sha: params.sha)`, which is a global query across every stack in the database. Any `status` webhook whose signature verifies (i.e. its `repository.owner.login` maps to a configured GitHub App/org) can attribute an attacker-chosen `description`/`target_url` to a commit belonging to a completely different, unrelated stack, and that stack's `Hook.emit(:commit_status, stack, ...)` will fire with the forged data.

### Finding Description
The broken binding, stated as an equality that should hold but doesn't: `stack_that_authenticated_the_webhook (derived from payload['repository']['full_name'] via GithubApp verification scope) == stack passed to Hook.emit in Commit#add_status`. In this code path that equality is never enforced.

Trace:
- `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) validates the HMAC signature using `Shipit.github(organization: repository_owner)`, where `repository_owner = params.dig('repository','owner','login')`. This only proves the payload was signed with the webhook secret belonging to *some org/app configured in Shipit* — it says nothing about which specific repository/stack in that org (or in any org, in single-app mode) the `sha`/`target_url`/`description` fields should be attributed to.
- `StatusHandler` params schema (`app/models/shipit/webhooks/handlers/status_handler.rb:7-18`) requires only `sha`, `state`, and accepts `description`, `target_url`, `context`, `created_at`, `branches` — notably it does **not** require `repository`, unlike `PullRequest` handlers (`requires :repository do requires :full_name, String end`) or the base `Handler#stacks` helper (`app/models/shipit/webhooks/handlers/handler.rb:32-38`) which scopes lookups via `Repository.from_github_repo_name(repository_name)`.
- `StatusHandler#process` (lines 20-24): `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — this is a bare, cross-stack, cross-repository lookup by sha alone.
- `Commit#create_status_from_github!` → `Commit#add_status` (`app/models/shipit/commit.rb:165-169, 366-386`) computes `payload = { commit: self, stack:, status: new_status.state }` using `self.stack` (the stack that owns the matched `Commit` row) and calls `Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status))`.

Contrast with `CheckSuiteHandler#process` (`app/models/shipit/webhooks/handlers/check_suite_handler.rb:13-16`), which correctly scopes: `stacks.where(branch: ...).each { |stack| stack.commits.where(sha: ...) }`, ensuring the sha lookup happens only within the repository/stack that the payload's `repository.full_name` names. `StatusHandler` has no analogous scoping.

Exploit flow: GitHub's status API (`POST /repos/{owner}/{repo}/statuses/{sha}`) accepts any sha string regardless of whether it exists in that repository. An attacker with push/write access to *any* repository whose owning organization/app shares a webhook secret with the Shipit instance (either the single global app config, or the same org in multi-org config) can:
1. Learn a victim commit's sha (shas are not secret — visible in Shipit's UI, GitHub PRs, public repos, etc.).
2. Call the GitHub Statuses API on their own repo with `sha=<victim_sha>`, `target_url=<attacker string>`, `description=<attacker string>`.
3. GitHub relays a validly-signed `status` webhook to Shipit's `/webhooks` endpoint; `verify_signature` passes because the signature is computed from the shared secret, not tied to a specific repo.
4. `StatusHandler#process` finds the victim `Commit` row purely by `sha` and calls `add_status`, which fires `Hook.emit(:commit_status, victim_stack, ...)` carrying the attacker's `target_url`/`description`.

Existing guards do not stop this: `verify_signature` only authenticates the org/app, not the specific repository-to-stack binding; `drop_unhandled_event` only checks whether a handler exists for the event type; the `ExplicitParameters` schema for `StatusHandler` doesn't require or validate `repository` at all; there is no `force_github_authentication`, `require_permission!`, or model validation anywhere in this path that ties the matched `Commit`'s stack back to the webhook's originating repository.

### Impact Explanation
The attacker injects attacker-controlled `target_url`/`description` strings into a victim stack's outbound `Hook.emit(:commit_status, ...)` payload — a payload for one repository mutating another's commit/stack data, matching the "Critical" category explicitly listed in scope ("a payload for one repository mutating another's stack, commit, task or team"). Concretely this reaches: (a) any external Hook (Slack, CI dashboards, etc.) subscribed to `commit_status`/`deployable_status` on the victim stack, receiving forged notification content attributed to that stack; (b) `Status` rows created on the victim's `Commit` (`statuses.replicate_from_github!`), corrupting the CI status shown for that commit, which can also influence `deployable?`/blocking logic and the merge queue (`stack.schedule_merges`) for the victim stack. This is repeatable against arbitrary victim stacks/shas as long as the attacker can discover a target sha and has write access to any in-scope repository.

### Likelihood Explanation
Preconditions: (1) The Shipit instance's webhook secret verification must actually be enforced (a `webhook_secret` configured) — if unset, this becomes moot since `verify_webhook_signature` trivially returns true for anyone, a separate, out-of-scope misconfiguration issue. (2) The attacker must control (own, or have push access to) at least one repository whose GitHub App/webhook-secret scope is shared with the victim's stack — in single-github-app mode (the default/most common config per `config/secrets.development.example.yml`), this means *any* repository the App is installed on, i.e. potentially the whole org/instance; in multi-org mode (`docs/setup.md:182-209`), it's constrained to repos within the same org as the victim. (3) The attacker needs the victim commit's sha, which is not secret. Given typical single-app Shipit deployments manage many repos/stacks under one shared webhook secret, this is a realistic, low-cost, repeatable attack for any user who can push a commit status to one in-scope repo.

### Recommendation
Scope `StatusHandler` the same way `CheckSuiteHandler`/`PushHandler` do: require `repository.full_name` in the params schema, resolve `stacks` via `Repository.from_github_repo_name`, and restrict the `Commit` lookup to `stacks.flat_map(&:commits).where(sha: params.sha)` (or equivalently join through `stack_id in stacks.select(:id)`) instead of a bare global `Commit.where(sha: ...)`.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`, new/extended):
```ruby
test "process does not attribute a forged status to a commit belonging to a different repository/stack" do
  victim_stack = shipit_stacks(:shipit)                 # owns repository A
  victim_commit = shipit_commits(:first)                # sha shared/known
  assert_equal victim_stack, victim_commit.stack

  # forged payload: repository field (if present) points to attacker's repo, not victim's
  forged_payload = {
    'sha' => victim_commit.sha,
    'state' => 'failure',
    'description' => 'ATTACKER CONTROLLED',
    'target_url' => 'https://attacker.example.com/pwn',
    'repository' => { 'full_name' => 'attacker/unrelated-repo' }
  }

  expect_no_hook(:commit_status, victim_stack) do
    Shipit::Webhooks::Handlers::StatusHandler.call(forged_payload)
  end

  victim_commit.reload
  refute_equal 'ATTACKER CONTROLLED', victim_commit.statuses.last&.description
end
```
Assert both sides of the binding explicitly: `payload['repository']['full_name'] != victim_stack.repository.full_name` (attacker's declared repo) while `Commit.where(sha: forged_payload['sha']).first.stack == victim_stack` (the row actually mutated) — proving the two are not required to match by current code, and that `Hook.emit`/`Status` creation still occurs against `victim_stack` despite the mismatch. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7)

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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L1-21)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class CheckSuiteHandler < Handler
        params do
          requires :check_suite do
            requires :head_sha, String
            requires :head_branch, String
          end
        end
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
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

**File:** lib/shipit/github_app.rb (L44-83)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]

      oauth = (@config[:oauth] || {}).with_indifferent_access
      @oauth_id = oauth[:id]
      @oauth_secret = oauth[:secret]
      @oauth_teams = Array.wrap(oauth[:teams])
    end

    def login
      raise NotImplementedError, 'Handle App login / user'
    end

    def api
      client = (Thread.current[:github_client] ||= new_client(access_token: token))
      client.access_token = token if client.access_token != token
      client
    end

    def api_status
      conn = Faraday.new(url: 'https://www.githubstatus.com')
      response = conn.get('/api/v2/components.json')
      parsed = JSON.parse(response.body, symbolize_names: true)
      parsed[:components].find { |c| c[:id] == API_STATUS_ID }
    end

    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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
