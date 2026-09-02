### Title
Cross-repository status webhook forgery causes `Hook.emit(:commit_status, ...)` to fire for a stack whose repository never authenticated the event - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` resolves the commit(s) to update purely by SHA (`Commit.where(sha: params.sha)`), with no check that the payload's `repository` matches the `Stack`'s repository that owns that commit. Because GitHub Apps are installed and signed at the organization level (one `webhook_secret` per org, one webhook URL receiving events for every repository the App is installed on), a valid signature only proves "this came from GitHub for organization X," not "this came from the specific repository that owns this commit." Any repository within that org can therefore emit a genuinely-signed status event carrying a SHA that also exists in a different, unrelated stack's commit history, and `Hook.emit(:commit_status, stack, ...)` will fire for that victim stack.

### Finding Description
The broken binding, stated as an equality that the code never enforces:
`commit.stack.github_repo_name == params.dig('repository', 'full_name')`

Trace:
1. `Shipit::WebhooksController#verify_signature` (app/controllers/shipit/webhooks_controller.rb:24-30) picks the GitHub App config by `repository_owner` (`params.dig('repository','owner','login')`, attacker/payload-controlled) and calls `Shipit.github(organization: repository_owner).verify_webhook_signature`. This only proves the request is a legitimately-signed delivery *for that organization's single App/secret* (see `lib/shipit/github_app.rb:76-83` and `docs/setup.md:20-49`, `docs/setup.md:182-209` — one webhook secret per org, shared by every repo the App is installed on).
2. `StatusHandler#process` (app/models/shipit/webhooks/handlers/status_handler.rb:20-24):
   ```
   Commit.where(sha: params.sha).each do |commit|
     commit.create_status_from_github!(params)
   end
   ```
   This performs a **global** lookup by SHA across the entire database, with no filter on `commit.stack.repository`, `commit.stack_id` matching the payload's `repository`, or any other repository binding.
3. `Commit#create_status_from_github!` → `add_status { statuses.replicate_from_github!(stack_id, github_status) }` (app/models/shipit/commit.rb:165-169), which ultimately fires `Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status))` — confirmed by the existing test suite asserting this exact call for every state transition (test/models/commits_test.rb:683-711).

Root cause: signature verification authenticates *an organization*, not *a repository*, while the commit-lookup/status-creation path never re-checks which repository actually owns the target commit. Any repository inside the same GitHub App installation (same org) that the attacker can push commits/statuses to — including a personal fork that has been added to the App's installation scope, or any low-privilege sandbox repo the attacker was granted access to in that org — can trigger a genuinely GitHub-signed `status` event whose `sha` happens to also exist in a completely different stack's commit history (shared fork history, cherry-picked commits, mirrored/vendored code, monorepo splits, etc.). None of `drop_unhandled_event`, `verify_signature`, or the `ExplicitParameters` schema in `StatusHandler` (which only validates types, not repository identity) close this gap.

### Impact Explanation
A victim stack's `Hook` (e.g. a chatops/status webhook configured with `commit_status` in `Shipit::Hook::EVENTS`, app/models/shipit/hook.rb:70-82) fires with attacker-influenced `state`/`description`/`context`/`target_url` for a commit the attacker never authenticated for that repository. This is a cross-tenant write: a record (`Status`) is created and an outbound `Hook` delivery is triggered for a repository/stack that did not originate the request. Depending on what the victim's Hook target does with `commit_status`/`target_url`/`description` (e.g. surfacing them in chat, dashboards, or automation gated on CI status), this ranges from unauthorized state mutation of a victim stack (deployability gating via `deployable?`/`blocked?`, app/models/shipit/commit.rb:227-237) to information disclosure of the victim's Hook target/secrets if the Hook implementation reflects payload content back out. This matches the High impact category (unauthenticated write of stack/commit state for a repository that did not authenticate it), and can rise to Critical if the outbound Hook target itself embeds secrets/URLs that get exercised as a result.

### Likelihood Explanation
Requires: (a) Shipit configured with a GitHub App installed across multiple repositories/stacks sharing one `webhook_secret` (the documented, default multi-repo setup — see `docs/setup.md`), and (b) the attacker controlling some repository within that same App's installation scope with the ability to create/push a commit and post a status against it (via GitHub UI/API on a repo they own or have collaborator access to). No Shipit secrets, session, or API token are needed — the "signature" is a real GitHub-generated one for the attacker's own repo. The main constraining factor is that the attacker's triggering repository must fall inside the App's installation, which typically implies some org membership or collaborator grant on at least one repository — a fork under the attacker's personal namespace would not itself receive App coverage, but forks/collaborator repos added to an "all repositories" installation, or any other repo within scope, do. This is realistic in shared-org, multi-stack Shipit deployments (Shipit's primary use case). It is repeatable per-SHA-collision opportunity, and any org repository/collaborator relationship in scope can be reused indefinitely.

### Recommendation
In `StatusHandler#process` (and analogously `CheckSuiteHandler`), scope the commit lookup to commits whose `stack.github_repo_name`/repository matches `params.dig('repository', 'full_name')` (or the numeric GitHub repo id) before calling `create_status_from_github!`. E.g. `Commit.where(sha: params.sha).select { |c| c.stack.github_repo_name.casecmp?(params.dig('repository','full_name')) }`. More robustly, verify signatures per-repository (store/validate a per-repo webhook secret) rather than only per-organization, so authentication itself is repository-scoped.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
require 'test_helper'

module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerCrossRepoTest < ActiveSupport::TestCase
        test "a status delivered for repo A fires Hook.emit for an unrelated stack B whose commit shares the same sha" do
          attacker_repo_full_name = "acme/attacker-owned-repo" # different repo than victim stack
          victim_commit = shipit_commits(:first)
          victim_stack = victim_commit.stack

          assert_not_equal attacker_repo_full_name, victim_stack.github_repo_name

          forged_payload = {
            'sha' => victim_commit.sha,       # SHA collision via shared history/fork
            'state' => 'success',
            'context' => 'attacker/ci',
            'repository' => { 'full_name' => attacker_repo_full_name, 'owner' => { 'login' => 'acme' } }
          }

          Shipit::Hook.expects(:emit).with(:commit_status, victim_stack, has_entries(commit_status: instance_of(Status))).at_least_once

          StatusHandler.new.call(forged_payload)

          # Equality that should hold but does not:
          # forged_payload['repository']['full_name'] != victim_stack.github_repo_name
          # yet Hook.emit fired for victim_stack anyway.
        end
      end
    end
  end
end
```
This demonstrates that `StatusHandler#process` (via `Commit.where(sha: params.sha)`) resolves and mutates `victim_stack`'s commit and triggers its `Hook.emit(:commit_status, ...)` even though the payload's `repository.full_name` never matches `victim_stack.github_repo_name`, proving the binding is unenforced. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/hook.rb (L70-107)
```ruby
    EVENTS = %w[
      stack
      review_stack
      task
      deploy
      rollback
      lock
      commit_status
      deployable_status
      merge_status
      merge
      pull_request
    ].freeze

    belongs_to :stack, required: false
    has_many :deliveries

    validates :delivery_url, presence: true, url: { no_local: true, allow_blank: true }
    validates :content_type, presence: true, inclusion: { in: CONTENT_TYPES.keys }
    validates :events, presence: true, subset: { of: EVENTS }

    serialize :events, coder: Shipit::CSVSerializer

    scope :global, -> { where(stack_id: nil) }
    scope :scoped_to, ->(stack) { where(stack_id: stack.id) }
    scope :for_stack, ->(stack_id) { where(stack_id: [nil, stack_id]) }

    class << self
      def emit(event, stack, payload)
        raise "#{event} is not declared in Shipit::Hook::EVENTS" unless EVENTS.include?(event.to_s)

        Shipit::EmitEventJob.perform_later(
          event: event.to_s,
          stack_id: stack&.id,
          payload: coerce_payload(payload)
        )
        deliver_internal_hooks(event, stack, payload)
      end
```

**File:** test/models/commits_test.rb (L678-712)
```ruby
    expected_webhook_transitions.each do |initial_state, firing_states|
      initial_status_attributes = { state: initial_state, description: 'abc', context: 'ci/travis' }
      (expected_webhook_transitions.keys - %w[unknown]).each do |new_state|
        should_fire = firing_states.include?(new_state)
        action = should_fire ? 'fires' : 'does not fire'
        test "#add_status #{action} for status from #{initial_state} to #{new_state}" do
          commit = shipit_commits(:cyclimse_first)
          assert commit.stack.hooks.where(events: ['deploy_status']).size >= 1
          refute commit.stack.ignore_ci
          commit.statuses.destroy_all
          commit.reload
          unless initial_state == 'unknown'
            attrs = initial_status_attributes.merge(
              stack_id: commit.stack_id,
              created_at: 10.days.ago.to_formatted_s(:db)
            )
            commit.statuses.create!(attrs)
          end
          assert_equal initial_state, commit.state

          expected_status_attributes = { state: new_state, description: initial_state, context: 'ci/travis' }
          add_status = lambda do
            attrs = expected_status_attributes.merge(created_at: 1.day.ago.to_formatted_s(:db))
            commit.create_status_from_github!(OpenStruct.new(attrs))
          end
          expect_hook_emit(commit, :commit_status, expected_status_attributes) do
            if should_fire
              expect_hook_emit(commit, :deployable_status, expected_status_attributes, &add_status)
            else
              expect_no_hook(:deployable_status, &add_status)
            end
          end
        end
      end
    end
```

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
```
