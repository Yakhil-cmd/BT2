Confirmed: `Commit` has an index on `["stack_id", "sha"]` (`db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb`), not a global uniqueness constraint on `sha` alone. Multiple `Stack` records (any repository, any GitHub organization onboarded into this Shipit instance) can therefore hold `Commit` rows with the identical `sha` value (e.g. forks, mirrors, cherry-picked/rebased commits, or a repository intentionally created by an attacker whose git history is engineered to collide with a sha already present in a victim stack). `StatusHandler` exploits exactly this gap.

### Title
Webhook status handler writes commit CI status without repository scoping, letting a signature valid for one GitHub organization forge CI state for commits in another organization's stack - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/secret to validate a webhook against based on the `repository.owner.login` (or `organization.login`) found in the payload [1](#0-0) . Every other webhook handler re-derives the target `Stack`/`Repository` from that same `repository.full_name` payload field before mutating anything [2](#0-1) . `StatusHandler`, however, ignores the repository entirely and looks up commits purely by `sha` across the whole database: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [3](#0-2) .

### Finding Description
The binding that should hold is: *organization whose webhook secret verified the request* == *repository/stack whose commit state is written*. `StatusHandler` breaks this equality because `sha` is only unique per-stack, not globally — the schema only indexes `["stack_id", "sha"]` [4](#0-3) , and `Commit#sha` has no uniqueness validation. If two different stacks (belonging to two different GitHub organizations/apps, each with its own `webhook_secret`) happen to contain a `Commit` row with the same `sha` (e.g., a forked/mirrored repo, a rebased branch, or a repository an attacker deliberately seeds so its history reuses a known victim sha), a `status` webhook that is legitimately signed for organization A can update the CI status of the identically-shaed commit belonging to organization B's stack as well, since `StatusHandler.process` never filters by `repository_name`/`stacks` the way `PushHandler` and the `pull_request/*` handlers do [5](#0-4) .

`Commit#create_status_from_github!` directly persists the forged status: [6](#0-5) , which flows into `add_status`, which fires `Hook.emit(:deployable_status, ...)`, calls `stack.schedule_merges` and `commit.schedule_continuous_delivery` whenever the reported state becomes `success`/`pending` [7](#0-6) . `schedule_continuous_delivery` enqueues `ContinuousDeliveryJob`, which triggers `stack.trigger_continuous_delivery` and ultimately `trigger_deploy` if the victim stack has `continuous_deployment` enabled [8](#0-7) [9](#0-8) . Independently, `stack.schedule_merges` runs `ProcessMergeRequestsJob`, and merge-readiness checks such as `MergeRequest#all_status_checks_passed?` rely on `head.statuses_and_check_runs` [10](#0-9)  — exactly the table the forged status writes into.

### Impact Explanation
An attacker who controls (or is the maintainer of) any GitHub organization/repository already onboarded onto the same Shipit instance can send a legitimately-signed `status` webhook for their own repo whose `sha` value coincidentally or deliberately matches a commit sha tracked by a different, victim organization's stack. This lets them mark that victim commit as `success`, which can arm continuous deployment or unblock the merge queue on the victim's stack — this is an unauthorized deploy/merge triggered without ever compromising the victim's own GitHub App credentials, satisfying the "Critical: unauthorized deploy, rollback, or merge" bar.

### Likelihood Explanation
Requires the attacker to control an onboarded GitHub organization (their own, legitimately installed) and to arrange a matching sha in a commit visible to a stack in that org (achievable by forking/mirroring a victim's public repository into their own org and having Shipit track it, or by force-pushing a rebase producing a colliding hash for a private commit they know). No compromise of the victim's webhook secret, `GITHUB_TOKEN`, or Shipit session is required — only ordinary use of the attacker's own onboarded GitHub App to send a webhook, so this is exploitable by an unprivileged-relative-to-the-victim external organization owner.

### Recommendation
Scope `StatusHandler#process` to the repository named in the payload, exactly like `PushHandler` and the `pull_request/*` handlers: restrict the `Commit` lookup to `stacks` derived from `Repository.from_github_repo_name(params.dig('repository','full_name'))` (or join through `stack: :repository`) before matching by `sha`, so a status update can only ever mutate commits that belong to the same repository the verified webhook signature was issued for.

### Proof of Concept
1. Attacker owns/administers GitHub org `attacker-org`, which has its own Shipit-managed stack and its own `webhook_secret` (`Shipit.github(organization: 'attacker-org')`).
2. Attacker forks or otherwise arranges a repository under `attacker-org` containing a commit whose sha is identical to a commit already tracked by `victim-org`'s Shipit stack (e.g., by mirroring the victim's public branch, or by constructing an equivalent rebase).
3. Attacker pushes to that commit in their own repo, and GitHub sends Shipit a `status` webhook for `attacker-org/repo`, correctly signed with `attacker-org`'s `webhook_secret`.
4. `WebhooksController#verify_signature` succeeds because it validates against `attacker-org`'s app [11](#0-10) .
5. `StatusHandler.process` runs `Commit.where(sha: params.sha)`, which returns commit rows for *both* `attacker-org`'s stack and `victim-org`'s stack because the sha collides, and calls `create_status_from_github!(params)` on all of them [3](#0-2) .
6. The victim's commit now has a forged `success` status, potentially firing `ContinuousDeliveryJob`/`ProcessMergeRequestsJob` on `victim-org`'s stack.

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

**File:** db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb (L1-10)
```ruby
class IndexCommitsOnStackIdAndSha < ActiveRecord::Migration[5.1]
  def change
    add_index :commits, %i(sha stack_id), unique: true
  end
end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
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

**File:** app/models/shipit/merge_request.rb (L193-197)
```ruby
    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end
```
