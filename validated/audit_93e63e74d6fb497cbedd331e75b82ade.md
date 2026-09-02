### Title
Cross-repository status write via unscoped `Commit.where(sha:)` lookup enables blocking-status manipulation on unrelated stacks - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` writes a GitHub `status` webhook payload to every `Commit` record matching a bare SHA, with no check that the commit's `stack`/`repository` corresponds to the repository that authenticated the webhook. Combined with `blocking_statuses` configuration (via `deploy.yml`/`DeploySpec`), an attacker who controls a repository that shares (or can produce) a `Commit` row with the same SHA as a commit tracked by an unrelated "victim" stack can inject or clear a `codecov/project` status for that victim commit, altering `blocked?`/deploy gating there.

### Finding Description
The broken binding is: `commit.stack.repository == repository_owner_of(request)` should hold for every commit a webhook is allowed to mutate — but `StatusHandler#process` never checks it.

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [1](#0-0) 

`WebhooksController#verify_signature` only validates that the payload's `repository.owner.login` corresponds to a *configured* `Shipit.github(organization:)` app and that its HMAC secret matches — it does not verify that the `sha` in the payload actually belongs to a commit under that same repository/organization: [2](#0-1) 

Because `Commit` rows are keyed by `sha` globally (with `belongs_to :stack`), and the `StatusHandler` query is `Commit.where(sha: params.sha)` with no `stack_id`/`repository` scoping, any commit sharing that SHA across every stack in the installation receives the forced status via `commit.create_status_from_github!(params)`, which calls `add_status` and can change `commit.status`, potentially flipping `blocked?`/deployability and triggering `stack.schedule_merges`: [3](#0-2) [4](#0-3) 

`blocking_statuses` is delegated from `Commit` to `stack` (i.e., driven by that stack's own `deploy.yml`), so a stack that requires `codecov/project` as a blocking status is vulnerable regardless of which repository the SHA-colliding commit came from: [5](#0-4) 

**Exploit flow:** An attacker who owns/controls a GitHub repository (in any org onboarded to Shipit, or an org with no `webhook_secret` configured, since `verify_webhook_signature` returns `true` unconditionally when `webhook_secret` is blank) sends `POST /webhooks` with `X-Github-Event: status` and a JSON body `{sha: <shared/victim SHA>, state: "success", context: "codecov/project", repository: {owner: {login: attacker_org}}}`. This passes signature verification for the attacker's own org, and `StatusHandler` writes a new `codecov/project` status against **every** `Commit` row with that SHA — including one belonging to a victim's stack — regardless of which org/repo actually owns it.

**Why the SHA can coincide across repos:** SHA collision here does not require a cryptographic break — it requires the same commit object to legitimately exist in two Shipit-tracked stacks. This is common: forks, repos with shared history/cherry-picks, or the case where the *same* GitHub repository is registered as multiple Shipit stacks (e.g., staging/production stacks for one repo), or the attacker knows/observes a victim's public commit SHA (commit SHAs are not secrets) and has any repo commit that Shipit will accept a status webhook for with a matching SHA is not directly forgeable for an arbitrary victim SHA unless the attacker actually controls a commit with that exact SHA, which is only feasible when the victim repo/commit is public and the attacker's own tracked stack also contains that same public commit (e.g., a fork of the victim repo, or multiple stacks tracking the same repository).

Existing guards do not stop this: `verify_signature` only checks org-level HMAC/authenticity, not sha-to-repo binding; `drop_unhandled_event` only filters unknown event types; there is no `ExplicitParameters` validation tying `params.sha` to `params.repository`; and `StatusHandler` performs no `stack.repository` or `github_repo_name` filter at all.

### Impact Explanation
A payload authenticated for one repository/organization can write a `Status` record onto a `Commit` belonging to a different stack/repository, altering that stack's `blocked?`/deployability state (via `blocking_statuses` gating) and potentially triggering `stack.schedule_merges` and deploy eligibility changes — this is cross-tenant state mutation for a repository that did not authenticate the request, matching the Critical category ("a payload for one repository mutating another's stack, commit, task or team"). The blast radius is any Shipit installation where two stacks can end up sharing a `Commit.sha` (multiple stacks on the same repo, forks, or shared commit history), which is a realistic and common Shipit configuration pattern (e.g., staging + production stacks tracking the same repository).

### Likelihood Explanation
Preconditions: (1) the victim stack must have `blocking_statuses` configured requiring `codecov/project` (or similar) in its `deploy.yml`; (2) a `Commit` row with the same SHA must exist under both the attacker-controlled repository/stack and the victim's stack — most straightforwardly achieved when the same GitHub repository backs two Shipit stacks (owned/observable by the attacker if they can push to a branch that Shipit tracks in one stack while a protected stack tracks the same repo), or via a fork sharing pre-fork history. Attacker cost is a single unauthenticated HTTP POST; no secrets, tokens, or privileged roles are required. The action is fully repeatable and requires no live GitHub interaction, satisfying the minitest reproducibility requirement.

### Recommendation
Scope `StatusHandler#process` (and mirror this in `CheckSuiteHandler`/other handlers using bare-SHA lookups) to only touch commits whose `stack.repository` matches the authenticated payload's `repository.full_name`/owner, e.g.:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    next unless commit.stack.repository.full_name.casecmp?(params.dig('repository', 'full_name'))
    commit.create_status_from_github!(params)
  end
end
```
Additionally consider adding a uniqueness constraint or explicit repository-aware lookup path (`Commit.where(sha: params.sha, stack_id: Stack.where(repository: matching_repo).select(:id))`) to avoid relying on `belongs_to :stack` traversal.

### Proof of Concept
```ruby
# test/models/webhooks/status_handler_cross_repo_test.rb
require 'test_helper'

module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerCrossRepoTest < ActiveSupport::TestCase
        test "a status for one repo must not affect a commit in another stack's repository sharing the same sha" do
          victim_stack = shipit_stacks(:shipit) # configure blocking_statuses to require 'codecov/project'
          victim_commit = shipit_commits(:first)
          shared_sha = victim_commit.sha

          attacker_stack = Stack.create!(repository: Repository.create!(owner: 'attacker', name: 'attacker-repo'), environment: 'production')
          attacker_commit = attacker_stack.commits.create!(sha: shared_sha, author: AnonymousUser.new, committer: AnonymousUser.new)

          # Binding under test: commit.stack.repository == params.repository (attacker's)
          assert_not_equal victim_commit.stack.repository, attacker_stack.repository

          params = Handler::Params.new(
            'sha' => shared_sha,
            'state' => 'success',
            'context' => 'codecov/project',
            'repository' => { 'full_name' => attacker_stack.repository.full_name }
          )

          assert_difference -> { victim_commit.statuses.count }, 0 do
            StatusHandler.new(params).process
          end
        end
      end
    end
  end
end
```
This test asserts the invariant that a status authenticated for `attacker_stack.repository` must not create a `Status` on `victim_commit` (which belongs to a different repository) despite sharing the same SHA. Given the current `StatusHandler#process` implementation, this assertion fails, demonstrating the cross-repository write.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/commit.rb (L57-58)
```ruby
    delegate :broadcast_update, :github_repo_name, :hidden_statuses, :required_statuses, :blocking_statuses,
             :soft_failing_statuses, to: :stack
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
