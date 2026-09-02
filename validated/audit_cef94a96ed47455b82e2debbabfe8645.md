### Title
Unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` lets any repository's status webhook write commit status / trigger merges for an unrelated stack sharing the same commit sha - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits purely by `sha` across the entire `commits` table, with no check that the webhook's `repository.full_name` matches the `Stack`/`Repository` that owns that commit. Any GitHub repository whose commit history happens to contain a sha that also exists as a `Commit` row in another (victim) stack — including non-HEAD, shared/templated ancestor commits — can drive `add_status`/`stack.schedule_merges` for that victim stack via a legitimately-signed status webhook from the attacker's own repo.

### Finding Description
The broken binding: `payload.dig('repository', 'full_name')` (the repository that actually emitted the webhook and whose signature was verified) is never checked to equal `commit.stack.repository.full_name` (the repository that owns the matched `Commit` row), i.e. the binding `repository_name == commit.stack.repository.full_name` is assumed but never enforced for this handler.

Code path:
- `Shipit::WebhooksController#create` calls `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` after `verify_signature`, which only validates that the payload signature matches the GitHub App/org secret for `repository_owner` — it says nothing about which specific repository/stack the sha belongs to. [1](#0-0) 
- `StatusHandler#process` does:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
This is a global, unscoped query by `sha` only — it does not use the `stacks` helper (which scopes by `Repository.from_github_repo_name(repository_name)`) the way `PushHandler` does. [2](#0-1) 
- Contrast with `PushHandler#process`, which correctly scopes stacks through `stacks.not_archived.where(branch:)`, itself derived from `Repository.from_github_repo_name(repository_name)`. [3](#0-2) [4](#0-3) 
- `create_status_from_github!` -> `add_status`, which creates a `Status`, reloads, and if the state transitions meaningfully calls `Hook.emit(:commit_status/:deployable_status, stack, ...)` and `stack.schedule_merges if new_status.pending? || new_status.success?` — all keyed off `commit.stack`, i.e. the victim stack, not the attacker's. [5](#0-4) 

Exploit flow: an attacker owns/controls a GitHub repository (their own fork or a freely creatable repo) that is registered as a Shipit stack under an organization Shipit trusts (webhook signature validates for `repository_owner` == attacker's org), or more simply the attacker's repo is any repo under an org whose GitHub App/webhook secret Shipit already has configured (this is required — see Likelihood). The attacker's repo's commit history happens to share a commit sha with a victim stack's `Commit` table (e.g., a common bootstrapped/templated initial commit, or any ancestor commit copied via fork/template with identical tree+parents+author+committer+timestamps, which produces an identical SHA-1 commit object independent of collision attacks). The attacker's own CI (which they fully control) posts a GitHub commit status API call (`state: success`) for that shared sha on their own repository. GitHub delivers a validly-signed `status` webhook to Shipit. `verify_signature` passes because the signature is genuinely valid for the attacker's own org/repo. `StatusHandler#process` then matches the `Commit` row by sha only, ignoring which repository the webhook came from, and fires `add_status` for the victim's `Stack`, which can call `Hook.emit` (arbitrary external HTTP hooks configured on the victim stack) and `stack.schedule_merges` (which can enqueue merge processing for the victim stack's queued merge requests) — this is an unauthorized cross-repository write/state transition and a real merge-scheduling side effect triggered without ever authenticating against the victim's repository.

Why existing guards fail: `verify_signature` only authenticates that a webhook payload came from a legitimate GitHub organization/app installation known to Shipit — it validates the sender, not the sha-to-repository binding. `drop_unhandled_event` and `ExplicitParameters` schema (`requires :sha, :state`) only validate presence/type of fields, not repository ownership of the sha. There is no `Repository`/`Stack` scoping step in `StatusHandler`, unlike every other handler that touches `stacks`.

### Impact Explanation
An attacker who controls any repository whose webhooks Shipit accepts (their own project/fork under an org already onboarded to Shipit) can, without any Shipit credentials, cause `Hook.emit(:commit_status, ...)` and `Hook.emit(:deployable_status, ...)` to fire for an arbitrary victim stack they don't own, and can cause `stack.schedule_merges` to run for that victim stack. This is a payload for one repository mutating another's stack/commit state — matching the "Critical: a payload for one repository mutating another's stack, commit, task or team" category. The blast radius extends to any victim stack whose `Commit` table contains a sha also reachable in some attacker-controlled repo's history (templated/forked repos with shared initial commits are common), not just victims of deliberately engineered SHA-1 collisions.

### Likelihood Explanation
Preconditions: (1) the attacker's repository must belong to an organization Shipit already trusts (i.e., Shipit has `Shipit.github(organization: repository_owner)` configured with a webhook secret — this is the one binding still enforced), and (2) a `Commit` row with a matching sha must already exist in the victim stack (e.g., via a shared template/bootstrap commit, common in scaffolded repos, or historical ancestor shared through forking) — this does not require finding a SHA-1 collision, only a naturally shared commit object, which is significantly more feasible than the classic full-collision variant discussed in a related question. Attacker cost is low: create a commit status via the GitHub API on a commit they control within a trusted org, no Shipit session, API token, or secret required. Repeatable against any victim stack sharing an ancestor commit, though scoped to attacker-controlled repos within organizations already onboarded to Shipit (this narrows real-world exploitability to environments with multi-tenant orgs/multiple repos under the same GitHub App installation, but does not require the attacker to be a Shipit operator/maintainer).

### Recommendation
Scope `StatusHandler#process` by repository before matching by sha, e.g., restrict to commits belonging to stacks derived from `stacks` (as `PushHandler` does):
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
This enforces `repository_name (from payload) == commit.stack.repository.full_name` before any `add_status`/hook/`schedule_merges` side effects occur.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
require 'test_helper'

module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerCrossRepoTest < ActiveSupport::TestCase
        test "status webhook from repo A must not update commits belonging to repo B's stack" do
          victim_stack = shipit_stacks(:shipit) # repository e.g. "shopify/shipit-engine"
          attacker_repo_full_name = "attacker/unrelated-repo"

          shared_sha = "deadbeef" * 5
          victim_commit = victim_stack.commits.create!(
            author: shipit_users(:walrus),
            committer: shipit_users(:walrus),
            sha: shared_sha,
            authored_at: Time.now,
            committed_at: Time.now,
            message: "shared templated commit"
          )

          payload = {
            'sha' => shared_sha,
            'state' => 'success',
            'context' => 'ci/attacker',
            'branches' => [],
            'repository' => { 'full_name' => attacker_repo_full_name }
          }

          assert_no_difference -> { victim_commit.reload.statuses.count } do
            StatusHandler.call(payload)
          end
        end
      end
    end
  end
end
```
Binding under test: `payload['repository']['full_name'] (attacker_repo_full_name)` must equal `victim_commit.stack.repository.full_name` before `add_status`/`schedule_merges` fire for `victim_stack`. With the current `Commit.where(sha:)` implementation this test fails (a `Status` row is created and `schedule_merges` fires for `victim_stack` despite the mismatched repository), confirming the vulnerability; after applying the recommended `stacks`-scoped fix, the test passes.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-30)
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
