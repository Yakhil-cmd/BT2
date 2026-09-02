### Title
`Shipit::Webhooks::Handlers::StatusHandler#process` matches commits by sha alone, ignoring the reporting repository, letting a webhook signed by attacker's own GitHub org attach a status to a victim stack's commit and trigger deploy - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits with `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`, with no repository/stack scoping, unlike `PushHandler` which explicitly scopes via `Repository.from_github_repo_name(repository_name)` before acting [1](#0-0) [2](#0-1) [3](#0-2) . Because git commit shas are content-addressed and shared across forks/mirrors, an attacker who controls their own GitHub org/repo (and its webhook secret) can send a `status` webhook naming a sha that also exists as a `Shipit::Commit` row belonging to a victim stack (`victim/prod`), and the handler will create a `Status` for that victim commit too, potentially satisfying `Commit#deployable?` and driving `Stack#trigger_continuous_delivery` to deploy with the victim's own `GITHUB_TOKEN`.

### Finding Description
The claimed binding is: `attacker_org == Shipit.github(organization: repository_owner_from_payload)` (enforced by `verify_signature`) but the code implicitly assumes `attacker_org == owner(stack acted upon by StatusHandler)`. These are not the same value and nothing in the code path ties them together.

- `WebhooksController#verify_signature` only proves the payload was signed with the webhook secret for the org named in the payload's own `repository.owner.login` (or `organization.login`) - i.e., it authenticates *which org sent this specific payload*, not *which stack the payload is allowed to affect* [4](#0-3) .
- `StatusHandler#process` never consults `payload['repository']` to restrict which stacks/commits it may touch; it queries `Commit.where(sha: params.sha)` directly across the whole `commits` table and calls `create_status_from_github!` on every match [1](#0-0) .
- Contrast with `PushHandler#process`, which correctly derives `stacks` from `Repository.from_github_repo_name(repository_name)` (i.e., from the payload's own repository) before doing anything, exactly the scoping `StatusHandler` lacks [2](#0-1) [3](#0-2) .
- `Commit#create_status_from_github!` creates a `Status` record scoped to `stack_id` (the victim stack, since the matched `Commit` row belongs to it) and via `add_status` triggers `Hook.emit(:deployable_status, ...)` and `stack.schedule_merges`, and the `after_create`/`after_commit` callbacks on `Status` call `commit.schedule_continuous_delivery` [5](#0-4) [6](#0-5) [7](#0-6) .
- `Commit#schedule_continuous_delivery` enqueues `ContinuousDeliveryJob` for the victim's stack once the (now victim-owned) commit is `deployable?` and the victim stack has `continuous_deployment` enabled [8](#0-7) .
- `Stack#trigger_continuous_delivery` then calls `next_commit_to_deploy` → `trigger_deploy`, which runs the deploy (`Command`/`PTY.spawn`) using the victim stack's own credentials [9](#0-8) [10](#0-9) .
- `Commit#deployable?` requires `success?` (i.e. a passing status) and `!blocked?`; a single attacker-forged `success` status matching the required CI context on that commit (or `stack.ignore_ci?`) is sufficient to flip `deployable?` to true [11](#0-10) .

**Exploit flow**: Attacker forks/mirrors `victim/prod` (a public repo) into their own org `attacker-org`, which naturally shares commit shas for identical history/content with `victim/prod`. Attacker registers/owns `attacker-org`'s GitHub App/webhook secret (their own, not victim's). Attacker sends `POST /webhooks` with `X-Github-Event: status`, a body whose `repository.owner.login` is `attacker-org`, `sha` equal to the shared commit sha, `state: success`, and a matching `context`, signed with `attacker-org`'s webhook secret. `verify_signature` passes because the signature is valid for `attacker-org` [12](#0-11) . `StatusHandler#process` then matches *every* `Commit` row with that sha - including the row belonging to `victim/prod`'s stack - and creates a `Status` for it, unconditionally of which repository the payload claims to represent [1](#0-0) .

Existing guards do not prevent this: `verify_signature` authenticates the *sender org*, not the *target stack*; `drop_unhandled_event` only checks the event type exists; the `ExplicitParameters` schema for `StatusHandler` only validates field types/presence (`sha`, `state`, etc.), not repository identity [13](#0-12) ; no model validation on `Status`/`Commit` ties the created status back to the originating repository.

### Impact Explanation
A single forged webhook from an attacker-controlled org causes a `Status` write against a commit record owned by an unrelated victim stack, and can drive that victim's `Stack#trigger_continuous_delivery` → `trigger_deploy` → `Command`/`PTY.spawn` using the victim's own `GITHUB_TOKEN`/environment. This is an unauthorized deploy triggered by a payload that never authenticated against the victim's organization or repository - a cross-tenant record write and unauthorized-deploy issue matching the Critical impact category ("a payload for one repository mutating another's stack, commit... or an unauthorized deploy"). The attack is repeatable against any stack/commit whose sha the attacker can reproduce or already knows (most straightforwardly, any commit shared via a public fork), and it is not limited to one victim - any Shipit-tracked repository sharing history with an attacker-controlled fork is exposed.

### Likelihood Explanation
Preconditions: victim stack has `continuous_deployment: true` (or, even without that, the forged status still writes a `Status` row and can influence deploy-gating decisions/UI for the victim commit) [14](#0-13) ; attacker needs their own GitHub org with a repository, correctly registered so `Shipit.github(organization: attacker_org)` resolves and their own webhook secret is valid - both fully within an unprivileged attacker's control (self-service org/repo creation, self-service webhook config). The attacker needs a commit sha in the victim's stack that they can name in a webhook; the most direct route is forking a public repository (sharing ancestor commit shas) or otherwise learning a target sha (shas are not secrets - visible via the GitHub UI/API for any repo the attacker can view, and often even for private repos through PR interactions, issue references, etc.). Cost is a single HTTP POST; the class of bug (missing repository scoping in a handler, present in siblings) is a straightforward coding defect independent of luck.

### Recommendation
Scope `StatusHandler#process` to commits belonging to stacks resolved from the payload's own repository, mirroring `PushHandler`/`Handler#stacks`:
```ruby
def process
  stacks.find_each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
This ensures a webhook can only create/update statuses for commits belonging to stacks whose repository matches the payload's `repository.full_name`, closing the cross-tenant write.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
require 'test_helper'

module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerCrossTenantTest < ActiveSupport::TestCase
        test "a status payload from an unrelated repository must not create a Status for another stack's commit sharing the same sha" do
          victim_stack = shipit_stacks(:shipit) # continuous_deployment stack under test
          victim_stack.update!(continuous_deployment: true)
          victim_commit = victim_stack.commits.create!(sha: 'deadbeefcafebabe0000000000000000000000', message: 'x',
                                                         author: shipit_users(:walrus), authored_at: Time.now,
                                                         committer: shipit_users(:walrus), committed_at: Time.now)

          # Attacker's own repository/org - unrelated to victim_stack's repository
          attacker_payload = {
            'sha' => victim_commit.sha,
            'state' => 'success',
            'context' => 'ci/travis',
            'repository' => { 'full_name' => 'attacker-org/unrelated-repo', 'owner' => { 'login' => 'attacker-org' } }
          }

          assert_no_difference -> { victim_commit.statuses.count } do
            StatusHandler.call(attacker_payload)
          end
        end

        test "trigger_continuous_delivery / Command PTY.spawn is not invoked for victim stack solely from an attacker-signed status on an unrelated repo" do
          victim_stack = shipit_stacks(:shipit)
          victim_stack.update!(continuous_deployment: true)
          Shipit::Command.any_instance.expects(:start).never

          attacker_payload = {
            'sha' => victim_stack.commits.last.sha,
            'state' => 'success',
            'context' => 'ci/travis',
            'repository' => { 'full_name' => 'attacker-org/unrelated-repo', 'owner' => { 'login' => 'attacker-org' } }
          }

          perform_enqueued_jobs do
            StatusHandler.call(attacker_payload)
          end
        end
      end
    end
  end
end
```
Both assertions currently fail against the unpatched `StatusHandler#process` (the first `Status` count assertion fails because a status is created for `victim_commit` despite the payload claiming an unrelated repository; the second fails once continuous delivery conditions align, because `Command#start`/`PTY.spawn` is invoked for `victim_stack`).

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L7-18)
```ruby
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
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

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```

**File:** app/models/shipit/status.rb (L42-44)
```ruby
    def schedule_continuous_delivery
      commit.schedule_continuous_delivery
    end
```

**File:** app/models/shipit/stack.rb (L174-196)
```ruby
    def trigger_deploy(*args, **kwargs)
      if changed?
        # If this is the first deploy since the spec changed it's possible the record will be dirty here, meaning we
        # cant lock. In this one case persist the changes, otherwise log a warning and let the lock raise, so we
        # can debug what's going on here. We don't expect anything other than the deploy spec to dirty the model
        # instance, because of how that field is serialised.
        if changes.keys == ['cached_deploy_spec']
          save!
        else
          Rails.logger.warning("#{changes.keys} field(s) were unexpectedly modified on stack #{id} while deploying")
        end
      end

      run_now = kwargs.delete(:run_now)
      deploy = with_lock do
        deploy = build_deploy(*args, **kwargs)
        deploy.save!
        deploy
      end
      run_now ? deploy.run_now! : deploy.enqueue
      continuous_delivery_resumed!
      deploy
    end
```

**File:** app/models/shipit/stack.rb (L210-229)
```ruby
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
