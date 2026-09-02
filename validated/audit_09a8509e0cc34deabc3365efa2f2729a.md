## Title
Cross-repository `status` webhook mutates a foreign stack's `MergeRequest` state via unscoped sha lookup - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves the target `Commit` purely by `sha`, with no scoping to the repository named in the webhook payload or authenticated via `verify_signature`. Because the DB schema explicitly allows the same `sha` to exist across many different `stack_id`s (only unique per `[sha, stack_id]`), an org-authenticated but otherwise unrelated repository can post a `status: failure` event that silently mutates a victim `MergeRequest` belonging to a completely different stack/repository, forcing `reject!('ci_failing')`.

### Finding Description
The intended binding is: `repository_owner`/`repository.full_name` used to authenticate the webhook (via `verify_signature`) MUST equal the `repository.full_name` of the `Stack` owning any `Commit`/`MergeRequest` that gets mutated as a result. It does not.

`WebhooksController#verify_signature` only checks the payload against the webhook secret configured for the organization derived from `repository_owner`: [1](#0-0) 
Since `Shipit.github(organization:)`/`webhook_secret` is configured per-organization (not per-repository, see `config/secrets.development.example.yml`), this proves only "some repository in this org sent it", not "this specific repository owns the target record."

`StatusHandler#process` then resolves the target purely by `sha`, with zero repository/stack scoping: [2](#0-1) 

The `commits` table only enforces uniqueness of `sha` scoped to `stack_id`, explicitly permitting the same `sha` to exist in unrelated stacks/repositories: [3](#0-2) 

`Commit#create_status_from_github!`/`add_status` then persists the (attacker-controlled) status and, on a meaningful state transition, schedules merges for that commit's own stack — not the attacker's: [4](#0-3) 

`Stack#schedule_merges` enqueues `ProcessMergeRequestsJob` for that stack: [5](#0-4) 

`ProcessMergeRequestsJob#perform` re-fetches (`refresh!`, which is additive/append-only for statuses) and then calls `reject_unless_mergeable!`: [6](#0-5) [7](#0-6) 

`any_status_checks_failed?` evaluates `head.statuses_and_check_runs`, which includes the injected status row (statuses are never deleted, only appended), so an attacker-chosen bogus `context` name persists as a failing check unless it happens to match `merge_request_ignored_statuses`: [8](#0-7) 

**Exploit flow:** attacker forks or otherwise obtains write access to any repository within the same GitHub organization/App installation as the victim (a normal, unprivileged contributor action). They fetch the victim's pending PR head ref into their own repo (`git fetch upstream pull/<n>/head`), which yields an identical git object with the identical `sha` (git objects are content-addressed, shared history is byte-identical regardless of repository). The attacker then triggers a real, org-signed `status` webhook (e.g., by posting a commit status via the GitHub API on their own repo/commit, which they are authorized to do as its owner) with `state: failure` and an arbitrary `context`. Shipit's `verify_signature` passes because it only checks the org-level secret. `StatusHandler#process` matches the victim's `Commit` row purely by shared `sha`, ignoring which repository actually owns it, and the rejection cascades through the victim's `MergeRequest` state machine.

None of the existing guards prevent this: `verify_signature` checks organization-level authenticity only, not per-repository ownership; `drop_unhandled_event`/`ExplicitParameters` only validate payload shape (`sha`, `state`, etc.), not repository binding; there is no `Repository`/`Stack` join or `full_name` comparison anywhere in `StatusHandler#process` or `Commit.create_status_from_github!`.

### Impact Explanation
An unprivileged contributor to any single repository within a shared GitHub organization/App installation can force rejection (or forge success — bypassing CI requirements) of another team's pending merges by targeting shared-history shas. This is a cross-repository/cross-tenant state mutation of `MergeRequest#merge_status` via a payload that was never authenticated for the target repository, matching the "payload for one repository mutating another's stack/commit" Critical category. The technique is repeatable against any stack sharing commit history (forks, shared upstream commits, monorepo splits, or multiple environment-stacks of the same repository) and generalizes both to false rejections (`ci_failing`) and, symmetrically, to false `success` statuses that could enable an unauthorized merge of a PR that hasn't actually passed CI.

### Likelihood Explanation
Preconditions: Shipit deployed with one GitHub App/webhook secret shared across multiple repositories/stacks in an organization (the documented, standard deployment model — see `docs/setup.md`), attacker has ordinary contributor/fork access to at least one repository in that same org, and a shared-sha commit exists between attacker's and victim's repository (trivially achievable by fetching the victim's open PR ref into an attacker-controlled repo, since git commit objects are content-addressed). No Shipit session, API token, or webhook secret is required beyond what GitHub itself issues to any repository owner in that org. This is cheap, deterministic, and repeatable per PR/commit.

### Recommendation
Scope `StatusHandler#process` (and `Commit#create_status_from_github!`/`refresh_statuses!`) so that a `status`/`check_suite` webhook can only affect `Commit` rows whose `stack.repository.full_name` (and ideally `owner`) matches `params.dig('repository', 'full_name')` from the verified payload, e.g. `Commit.joins(stack: :repository).where(sha: params.sha, shipit_repositories: { full_name: payload_repo_full_name })`. Additionally consider making `webhook_secret` verification repository-aware rather than organization-wide where feasible.

### Proof of Concept
```ruby
# test/models/webhooks/handlers/status_handler_cross_repo_test.rb
require 'test_helper'

module Shipit
  class StatusHandlerCrossRepoTest < ActiveSupport::TestCase
    test "a status webhook for repository A cannot reject a MergeRequest belonging to repository B sharing the same commit sha" do
      shared_sha = 'a' * 40

      victim_repo  = Repository.create!(owner: 'victim-org', name: 'victim-repo')
      victim_stack = Stack.create!(repository: victim_repo, environment: 'production')
      victim_head  = victim_stack.commits.create!(sha: shared_sha, message: 'shared commit', author: shipit_users(:shipit), authored_at: Time.now, committer: shipit_users(:shipit), committed_at: Time.now)
      victim_mr    = victim_stack.merge_requests.create!(number: 1, head: victim_head)
      victim_mr.update_column(:merge_status, 'pending')

      attacker_repo  = Repository.create!(owner: 'victim-org', name: 'attacker-fork')
      attacker_stack = Stack.create!(repository: attacker_repo, environment: 'production')
      attacker_stack.commits.create!(sha: shared_sha, message: 'shared commit', author: shipit_users(:shipit), authored_at: Time.now, committer: shipit_users(:shipit), committed_at: Time.now)

      # Attacker-controlled, org-authenticated payload naming ONLY the shared sha, not the victim repo
      params = ActionController::Parameters.new(
        'sha' => shared_sha,
        'state' => 'failure',
        'context' => 'attacker/bogus-check',
        'created_at' => Time.now.to_s
      )

      # Equality claimed by the binding, BEFORE:
      assert_not_equal victim_repo.full_name, attacker_repo.full_name
      assert_predicate victim_mr.reload, :pending?

      Shipit::Webhooks::Handlers::StatusHandler.new.call(params)

      # Equality AFTER: victim MergeRequest was mutated by a payload only ever
      # authenticated for attacker_repo/attacker_stack, never for victim_repo.
      assert_predicate victim_mr.reload, :rejected?
      assert_equal 'ci_failing', victim_mr.rejection_reason
    end
  end
end
```

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/stack.rb (L231-233)
```ruby
    def schedule_merges
      ProcessMergeRequestsJob.perform_later(self)
    end
```

**File:** app/jobs/shipit/process_merge_requests_job.rb (L10-17)
```ruby
    def perform(stack)
      merge_requests = stack.merge_requests.to_be_merged.to_a
      merge_requests.each do |merge_request|
        merge_request.refresh!
        merge_request.reject_unless_mergeable!
        merge_request.cancel! if merge_request.closed?
        merge_request.revalidate! if merge_request.need_revalidation?
      end
```

**File:** app/models/shipit/merge_request.rb (L155-162)
```ruby
    def reject_unless_mergeable!
      return reject!('merge_conflict') if merge_conflict?
      return reject!('ci_missing') if any_status_checks_missing?
      return reject!('ci_failing') if any_status_checks_failed?
      return reject!('requires_rebase') if stale?

      false
    end
```

**File:** app/models/shipit/merge_request.rb (L199-202)
```ruby
    def any_status_checks_failed?
      status = StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec)
      status.failure? || status.error?
    end
```
