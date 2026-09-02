### Title
`StatusHandler#process` applies GitHub status webhooks to commits by SHA globally, without scoping to the authenticating repository, allowing one repository's status webhook to mutate another stack's commit and trigger `Stack#continuous_delivery_delayed!` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits solely by `Commit.where(sha: params.sha)` and calls `commit.create_status_from_github!(params)` on every match, with no filter tying the match to `params.repository.full_name` (the repository that the webhook's HMAC signature actually authenticated). Every other webhook handler (`PullRequest::OpenedHandler`, `ClosedHandler`, `LabeledHandler`, etc.) explicitly resolves `repository = Shipit::Repository.from_github_repo_name(params.repository.full_name)` and scopes all lookups through it, but `StatusHandler` does not, breaking the intended binding `commit.stack.repository == webhook.repository`.

### Finding Description
The intended binding is: `commit.stack.repository.full_name == payload['repository']['full_name']` — a status webhook should only mutate `Commit` rows that belong to the stack(s) of the repository that produced (and cryptographically signed) that webhook.

Trace:
- `app/controllers/shipit/webhooks_controller.rb:24-49` (`verify_signature`) validates the HMAC using `Shipit.github(organization: repository_owner)`, i.e., the *organization/App installation* that owns the payload's `repository.owner.login`. This proves the payload is a genuine webhook from that org/repo, but it says nothing about which `Commit` rows in the database are allowed to be touched.
- `app/models/shipit/webhooks/handlers/status_handler.rb:20-24`: [1](#0-0) 
does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`. This is a raw, unscoped query across the entire `commits` table of the whole Shipit installation — it never consults `stacks` or `Repository.from_github_repo_name`, unlike the base class's own `stacks` helper defined at `app/models/shipit/webhooks/handlers/handler.rb:32-34` (which every PR handler uses, but `StatusHandler` bypasses entirely).
- `Commit#create_status_from_github!` (`app/models/shipit/commit.rb:165-169`) then calls `statuses.replicate_from_github!(stack_id, github_status)`, writing a `Status` row tied to that commit's own `stack_id` — i.e., whatever stack the matched `Commit` belongs to, regardless of which repository's webhook triggered it.
- Because Git commit SHAs are content-addressed, any two Shipit stacks that track repositories sharing commit history (a public repo and any fork of it, or two stacks tracking the same underlying repo) will contain `Commit` rows with identical `sha` values but different `stack_id`/`repository_id`. An attacker who owns an org/repo legitimately registered with Shipit (so `verify_webhook_signature` succeeds for *their own* payload) can fork the victim's public repository, ensuring shared commits keep identical SHAs, then post an authentic (self-signed, self-authenticated) `status` event referencing that shared SHA with `state: failure`. That event is 100% valid for the attacker's own repo, but `Commit.where(sha: ...)` also picks up the victim's `Commit` row for the same SHA under the victim's stack.
- Downstream: `Commit#create_status_from_github!` flips the commit's computed state to failing; `Stack#trigger_continuous_delivery` (`app/models/shipit/stack.rb:210-229`) calls `should_delay_continuous_delivery?(commit)` (`app/models/shipit/stack.rb:708-713`), which returns true via `commit.deploy_failed?`/status-derived checks, causing `continuous_delivery_delayed!` (`app/models/shipit/stack.rb:206-208`) to fire and set `continuous_delivery_delayed_since` on the **victim's** stack — despite no CI event ever occurring inside the victim's own webhook channel.

None of the existing guards catch this: `verify_signature` only authenticates the org/owner named in the payload, not which `Commit` rows may be mutated; `drop_unhandled_event` only checks the event type is registered; the `ExplicitParameters` schema for `StatusHandler` only validates shape (`sha`, `state`, etc.), not repository scoping; there is no `stacks`/`repository` filter applied in `process` at all.

### Impact Explanation
A payload correctly authenticated for repository/org A (attacker-controlled) writes a `Status` record and mutates `deployable?`/`success?`/`continuous_delivery_delayed_since` state for a `Commit`/`Stack` belonging to a completely different, unrelated tenant B, purely because they share a commit SHA (fork/shared-history collision, not a cryptographic collision). This is a cross-tenant write: a payload for one repository mutates another repository's stack/commit state, matching the "Critical" impact category ("a payload for one repository mutating another's stack, commit, task or team"). It silently halts/delays the victim's continuous-delivery pipeline (`continuous_delivery_delayed_since` set), and is repeatable against any victim stack whose repository is public/forkable and shares commit history with a repo the attacker controls in Shipit.

### Likelihood Explanation
Preconditions: the attacker must own/administer a Shipit-registered organization/repo (so their own webhook passes `verify_webhook_signature`), and that repo must share commit SHAs with the victim's tracked repository (trivially achieved by forking a public repo the victim also tracks, or by the victim's repo being mirrored/tracked under multiple stacks). No victim secrets, sessions, or GitHub App keys are needed — only a legitimate webhook from the attacker's own, independently-registered repository. This is fully attacker-cost-feasible and repeatable per request against any colliding SHA.

### Recommendation
In `app/models/shipit/webhooks/handlers/status_handler.rb`, scope the commit lookup to the authenticating repository, mirroring the pattern used by other handlers and the base class's `stacks` helper, e.g. `stacks.commits.where(sha: params.sha)` instead of the bare `Commit.where(sha: params.sha)`, so only commits belonging to stacks of `Repository.from_github_repo_name(params.repository.full_name)` can be updated by that webhook.

### Proof of Concept
Minitest plan (model/controller level, no live GitHub):
1. Create two `Repository`/`Stack` fixtures, `victim_stack` (repo `victim/app`) and `attacker_stack` (repo `attacker/app-fork`), each with a `Commit` sharing the identical `sha` value (simulating forked shared history).
2. Set `victim_stack.update!(continuous_deployment: true)`; ensure it is otherwise deployable and mid-pipeline awaiting that commit (`next_commit_to_deploy` returns it).
3. Stub `GithubHook.any_instance.stubs(:verify_signature).returns(true)` (as existing webhook tests do) to simulate a legitimately signed webhook for `attacker/app-fork`.
4. `POST /webhooks` with `X-Github-Event: status`, body `{ sha: <shared_sha>, state: "failure", repository: { full_name: "attacker/app-fork" }, branches: [...] }`.
5. Assert: `victim_commit.reload.state == 'failure'` even though the payload's `repository.full_name` is `attacker/app-fork`, proving cross-tenant write.
6. Call `victim_stack.trigger_continuous_delivery` (or enqueue `ContinuousDeliveryJob`) and assert `victim_stack.reload.continuous_delivery_delayed_since` is present, proving the victim's pipeline was delayed by a webhook that only authenticated for the attacker's own repository. [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/stack.rb (L202-229)
```ruby
    def continuous_delivery_delayed?
      continuous_delivery_delayed_since? && continuous_deployment? && (checks? || deployment_checks?)
    end

    def continuous_delivery_delayed!
      touch(:continuous_delivery_delayed_since) unless continuous_delivery_delayed?
    end

    def trigger_continuous_delivery
      return if cached_deploy_spec.blank?

      commit = next_commit_to_deploy

      if should_resume_continuous_delivery?(commit)
        continuous_delivery_resumed!
        return
      end

      if should_delay_continuous_delivery?(commit)
        continuous_delivery_delayed!
        return
      end

      begin
        trigger_deploy(commit, Shipit.user, env: cached_deploy_spec.default_deploy_env)
      rescue Task::ConcurrentTaskRunning
      end
    end
```

**File:** app/models/shipit/stack.rb (L708-713)
```ruby
    def should_delay_continuous_delivery?(commit)
      commit.deploy_failed? ||
        (checks? && !EphemeralCommitChecks.new(commit).run.success?) ||
        !deployment_checks_passed? ||
        commit.recently_pushed?
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
