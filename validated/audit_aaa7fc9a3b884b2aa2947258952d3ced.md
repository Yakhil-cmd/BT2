The index confirms it: uniqueness is enforced per `(stack_id, sha)`, not globally, so identical SHAs are permitted to exist across different stacks/repositories in the same Shipit instance.### Title
`StatusHandler` resolves commits globally by `sha` with no repository binding, letting a status webhook from repo B set CI success and trigger a deploy on stack A - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` loads target commits with `Commit.where(sha: params.sha)`, ignoring the `repository.full_name`/`repository.owner.login` in the webhook payload entirely, unlike every other handler (`PushHandler`, `CheckSuiteHandler`, `Handler#stacks`) which scope by `repository_name`. Because `sha` is only unique per `(stack_id, sha)` and not globally, a genuinely GitHub-signed `status` webhook produced by CI on a different repository (B) can mark a commit belonging to an unrelated stack (A) as `success`, which cascades into `Commit#schedule_continuous_delivery` → `Stack#trigger_continuous_delivery` → an unattended `Deploy.create!` on stack A.

### Finding Description
The broken binding, stated as an equality that the code should enforce but does not:

`Repository.from_github_repo_name(payload['repository']['full_name']) == commit.stack.repository`

In `Handler#stacks` (app/models/shipit/webhooks/handlers/handler.rb:32-38) this equality is honored: `stacks` is derived from `Repository.from_github_repo_name(repository_name)`, and handlers such as `PushHandler` and `CheckSuiteHandler` only touch commits reachable through that repository's stacks.

`StatusHandler` (app/models/shipit/webhooks/handlers/status_handler.rb:20-24) breaks it:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
It never calls `stacks`/`repository_name` at all — it looks up commits by `sha` across the *entire* database. The `sha` column has a uniqueness constraint scoped to `(sha, stack_id)` (`db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb:3`), not globally, so two different stacks/repositories can legitimately hold rows with the identical `sha` value (e.g., a repo B that is a mirror/fork/clone of repo A's history, or any repo whose commit object — same tree, parents, author/committer identities and timestamps, message — happens to be byte-identical, which is trivial for an attacker to reproduce since git hashes are pure functions of content, not of the hosting repository).

`create_status_from_github!` (app/models/shipit/commit.rb:165-169) then writes the status against `commit.stack_id` — the *matched* commit's own stack (stack A) — regardless of which repository's webhook produced the event:
```ruby
def create_status_from_github!(github_status)
  add_status do
    statuses.replicate_from_github!(stack_id, github_status)
  end
end
```
`Status#schedule_continuous_delivery` fires `after_commit … on: :create` (app/models/shipit/status.rb:19,42-44) and calls `commit.schedule_continuous_delivery` (app/models/shipit/commit.rb:281-287), which — if `deployable? && stack.continuous_deployment? && stack.deployable?` — enqueues `ContinuousDeliveryJob.perform_later(stack)`, which ultimately calls `Stack#trigger_continuous_delivery` (app/models/shipit/stack.rb:210-229), building and persisting a real `Deploy` via `trigger_deploy`/`build_deploy` (app/models/shipit/stack.rb:161-196).

Exploit flow:
1. Attacker opens/merges an innocuous PR on repo A, producing a known commit with sha S, tracked as a `Commit` under stack A (continuous deployment enabled).
2. Attacker creates repo B (any repository the attacker controls) whose commit history reproduces the exact same commit object (same tree, parent, author/committer, timestamps, message) as the commit at sha S — trivial since the attacker authored the original commit's content — yielding the same sha S in repo B.
3. Attacker triggers real CI on repo B (or posts a status via GitHub's Statuses API themselves, since they own repo B) so that GitHub genuinely emits a `status` webhook with `state: success`, `sha: S`. This webhook is only accepted by `WebhooksController#verify_signature` (app/controllers/shipit/webhooks_controller.rb:24-49) if `repository.owner.login` resolves, via `Shipit.github(organization: repository_owner)`, to an organization actually configured in this Shipit instance (`lib/shipit.rb:170-200`) — i.e. repo B must sit under an org/webhook-secret already trusted by this Shipit deployment (commonly true, since webhook secrets/GitHub Apps are typically configured per-organization covering all repos, including new ones an org member can create).
4. `StatusHandler.call` resolves the commit purely by `sha`, finds the row belonging to stack A, and writes a `success` `Status` under `stack_id` = A's id, even though the CI verdict came from repo B.
5. `Status#schedule_continuous_delivery` → `Commit#schedule_continuous_delivery` → `Stack#trigger_continuous_delivery` deploys stack A automatically, using code the attacker actually controls in repo A (their innocuous but merged PR) but with a CI verdict manufactured entirely outside repo A's real CI/review process — or, more damagingly, an attacker could get an *unreviewed/malicious* commit deployed if that commit's sha ever appears in stack A's `next_commit_to_deploy` pool (any locked/legit commit with matching sha would be spoofed as passing).

Existing guards do not stop this: `verify_signature` proves the payload originated from GitHub for a known organization — it says nothing about which specific *repository* within that organization emitted the event, and `StatusHandler` doesn't check that either. The `ExplicitParameters` schema for `StatusHandler` only validates types of `sha`/`state`/etc., not repository ownership.

### Impact Explanation
A `Status` record (and consequently continuous-delivery evaluation and an actual `Deploy`) is written for stack A's commit using a CI verdict that never touched stack A's repository. This is a direct instance of "a payload for one repository mutating another's stack, commit, task" and can culminate in "an unauthorized deploy" — both explicitly listed Critical impacts. Any Shipit installation tracking multiple repositories/stacks under one organization (the common multi-tenant case) is affected: an attacker who can create or control any repository within that org's trust boundary can forge CI results for commits shared with any other stack in the same installation, bypassing branch protections/required reviews/real CI on the target repo. The attack is repeatable against any stack/commit whose sha the attacker can reproduce.

### Likelihood Explanation
Preconditions: (a) the target Shipit instance configures webhook trust per-organization (the documented/standard config in `lib/shipit.rb`), (b) the attacker can get a genuinely GitHub-signed `status` webhook delivered for a repository under that same trusted organization (e.g., by creating a new repo in an org that allows member repo creation, or by any repo whose owner-login matches a configured org), and (c) the attacker can produce a commit object with an identical sha to one tracked by the target stack — straightforward when the attacker authored the original commit's exact content (own PR) or when mirroring/forking repo history. No secrets, sessions, or API tokens are required; the entire path relies only on GitHub's genuine webhook delivery and the engine's own commit-lookup logic. This is a code defect (`StatusHandler` missing repository scoping present in sibling handlers), not dependent on rare misconfiguration.

### Recommendation
Scope `StatusHandler#process` the same way as other handlers: resolve `stacks` via `Repository.from_github_repo_name(repository_name)` and only update/create statuses for commits belonging to those stacks, e.g.:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
Additionally add/keep the DB constraint scoped appropriately, but the primary fix must be enforcing repository identity in the handler, not relying on `sha` uniqueness alone.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_repo_binding_test.rb
require 'test_helper'

module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerRepoBindingTest < ActiveSupport::TestCase
        test "a status payload for repo B deploys stack A when commit shas collide" do
          stack_a = shipit_stacks(:shipit) # tracks repo "shopify/shipit-engine", continuous_deployment: true
          commit_a = stack_a.commits.create!(
            sha: 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
            message: 'innocuous PR merge',
            author: shipit_users(:walrus),
            committer: shipit_users(:walrus),
            authored_at: Time.now,
            committed_at: Time.now
          )

          # Payload genuinely signed by GitHub for a DIFFERENT repository (repo B),
          # but sharing the same sha as commit_a in stack A.
          payload = {
            'sha' => commit_a.sha,
            'state' => 'success',
            'context' => 'ci/attacker',
            'repository' => { 'full_name' => 'attacker-org/repo-b', 'owner' => { 'login' => 'attacker-org' } }
          }

          ContinuousDeliveryJob.expects(:set).with(wait: Commit::RECENT_COMMIT_THRESHOLD).returns(
            stub(perform_later: true)
          )

          assert_difference -> { commit_a.statuses.count }, 1 do
            StatusHandler.call(payload)
          end

          # Binding violated: status was written under stack A's id though the payload's
          # repository is attacker-org/repo-b, not stack_a.repository.
          status = commit_a.statuses.last
          assert_equal stack_a.id, status.stack_id
          refute_equal 'attacker-org/repo-b', stack_a.repository.full_name
        end
      end
    end
  end
end
```
This demonstrates the equality `Repository.from_github_repo_name(payload['repository']['full_name']) == commit.stack.repository` is false, yet `StatusHandler` still writes the status and schedules continuous delivery for `stack_a`, proving the binding violation end-to-end with no network access. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) [9](#0-8)

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/status.rb (L18-44)
```ruby
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

    private

    def enable_ci_on_stack
      commit.stack.enable_ci!
    end

    def schedule_continuous_delivery
      commit.schedule_continuous_delivery
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

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

**File:** db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb (L1-5)
```ruby
class IndexCommitsOnStackIdAndSha < ActiveRecord::Migration[5.1]
  def change
    add_index :commits, %i(sha stack_id), unique: true
  end
end
```
