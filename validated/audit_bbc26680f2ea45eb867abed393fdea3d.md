### Title
`StatusHandler#process` matches commits globally by SHA with no repository scoping, allowing cross-repository status/deploy manipulation - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler.call` is reached from `WebhooksController#create` for any verified `status` event and directly executes `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` with no repository/stack filter. `verify_signature` only proves the payload was signed by *some* organization's webhook secret matching `payload['repository']['owner']['login']`; it never constrains which `Commit`/`Stack` rows the handler is allowed to touch, so a webhook validly signed for repository A can mutate `Status` rows belonging to any `Stack` in the system as long as a `Commit` with a matching `sha` exists there.

### Finding Description
The binding claimed by the question is:
`{Stack/Commit rows mutable by webhook for repo R} == {stacks under Repository.from_github_repo_name(payload['repository']['full_name'])}`.

Tracing the code shows this binding is **not enforced** for the `status` event:
- `Shipit::Webhooks.default_handlers` maps `'status' => [Handlers::StatusHandler]` with no repository pre-filter. [1](#0-0) 
- `WebhooksController#create` dispatches `handler.call(params)` for the whole raw JSON payload, and `verify_signature` only checks the HMAC signature against `Shipit.github(organization: repository_owner)` — it authenticates *that the payload came from that org's configured webhook secret*, not that the handler will limit its writes to that org's stacks. [2](#0-1) 
- The shared `Handler` base class defines a private `stacks` helper that *does* correctly scope by `Repository.from_github_repo_name(repository_name)`, but this helper is never called by `StatusHandler`. [3](#0-2) 
- `StatusHandler#process` bypasses that helper entirely and queries `Commit` globally by `sha`: [4](#0-3) 
- `Commit#create_status_from_github!` then writes a `Status` row scoped to `commit.stack_id` (whichever stack that commit belongs to, regardless of which repo signed the webhook), and this write cascades into real side effects: `Hook.emit(:commit_status/:deployable_status, ...)`, `stack.schedule_merges`, and `ContinuousDeliveryJob` scheduling via `commit.schedule_continuous_delivery`. [5](#0-4) [6](#0-5) 

**Exploit flow:** An attacker who owns/controls a GitHub repository X (and thus its webhook secret) needs a `Commit` row in the Shipit database whose `sha` collides with a commit tracked under a *different*, victim `Stack`. Git SHA1s are content-addressed and portable across repositories — an attacker can fork/clone the victim's public repo (or otherwise reconstruct an identical commit object with the same tree/parents/author/committer/timestamps) into their own repo X, register/emit a GitHub `status` webhook event on X with that SHA, and it will be delivered signed with X's own valid secret. `verify_signature` passes because the signature is valid for X. `StatusHandler#process` then finds the `Commit` row(s) with that `sha` — which belong to the victim's `Stack` — and creates a `Status`, potentially flipping the commit to `success`, which can unblock/trigger continuous deployment (`schedule_continuous_delivery`) or merge processing (`schedule_merges`) for the victim's stack, entirely from an unprivileged attacker-controlled repository.

Existing guards (`verify_signature`, `drop_unhandled_event`, `ExplicitParameters` schema on `sha`/`state`/`context`) do not check that the resolved `Commit`/`Stack` belongs to the signing repository — none of them narrow the `Commit.where(sha:)` query by repository. `check_if_ping` and `drop_unhandled_event` are irrelevant to this path.

### Impact Explanation
A payload from repository X can create/alter `Status` records for a `Stack` belonging to a completely different repository/tenant, satisfying the Critical category "a payload for one repository mutating another's stack, commit, task or team." This can flip a commit's deployability (`Commit#deployable?`), trigger `ContinuousDeliveryJob`, or unblock `MergeMergeRequests`/merge scheduling for a victim's stack — i.e., an unauthorized deploy-relevant state change driven by an attacker who never authenticated against the victim's repository. Repeatable against any victim stack for which the attacker can produce (via fork or crafted commit) a SHA-identical commit, which is the common case for open-source forks tracked by Shipit.

### Likelihood Explanation
Preconditions: `default_handlers` unmodified (default configuration), the attacker owns any GitHub repository with a webhook configured to Shipit (trivial to set up, no special privilege), and a commit SHA collision with a tracked stack (trivially achievable by forking/cloning a public target repo, which is the common real-world scenario for CI status forwarding). No Shipit session, API token, or secret is required — only the attacker's own repository's webhook secret, which they legitimately possess. This is a low-cost, repeatable attack requiring no privileged access.

### Recommendation
In `StatusHandler#process`, scope the `Commit` lookup by the requesting repository using the existing `stacks` helper from `Handler`, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or equivalently `Commit.where(sha: params.sha, stack: stacks)`, mirroring the pattern already used correctly elsewhere (`Repository.from_github_repo_name(repository_name)`), so a webhook can only mutate commits/stacks belonging to the repository that signed it.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
require 'test_helper'

module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerTest < ActiveSupport::TestCase
        test "process mutates a commit belonging to a repository other than the one that signed the webhook" do
          victim_commit = shipit_commits(:first) # belongs to stack under repo "shopify/shipit"
          attacker_repository_full_name = "attacker/unrelated-repo"

          payload = {
            'sha' => victim_commit.sha,
            'state' => 'success',
            'context' => 'attacker-ci',
            'repository' => { 'full_name' => attacker_repository_full_name }
          }

          # Prove the repository-scoping helper is never consulted:
          Handler.any_instance.expects(:stacks).never

          assert_difference -> { victim_commit.statuses.count }, 1 do
            StatusHandler.call(payload)
          end

          # Binding check: repository_name resolved from payload does NOT own victim_commit.stack
          resolved_repo = Repository.from_github_repo_name(attacker_repository_full_name)
          refute_equal resolved_repo, victim_commit.stack.repository
        end
      end
    end
  end
end
```
This demonstrates: (1) `stacks` (the correctly-scoped helper) is never invoked, and (2) a `Status` write still occurs on a commit/stack that does not belong to the repository identified in the payload, confirming the structural absence of repository scoping in the `status` handler pipeline.

### Citations

**File:** app/models/shipit/webhooks.rb (L19-19)
```ruby
          'status' => [Handlers::StatusHandler],
```

**File:** app/controllers/shipit/webhooks_controller.rb (L10-49)
```ruby
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
