### Title
Cross-repository commit-status injection via unscoped `Commit.where(sha: ...)` lookup - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` resolves the target commit purely by `sha` (`Commit.where(sha: params.sha)`), with no filter tying the lookup to the repository that the webhook signature actually authenticated. Any GitHub organization/repo owner who can get Shipit's GitHub App installed on their own repo (a normal, unprivileged setup step) can trigger a legitimately-signed `status` webhook from their own repo carrying an arbitrary `sha` string equal to a victim commit's SHA in a completely different stack, causing Shipit to write a forged `Status` and fire deploy-affecting hooks for the victim's stack.

### Finding Description
The intended binding is: `status webhook signature verified for org O` implies `status writes are scoped to commits belonging to repositories owned by O`, i.e. `verified_org(payload) == commit.stack.repository.owner`. This binding is broken because the lookup ignores the payload's own `repository` field entirely.

Code path:
- `app/controllers/shipit/webhooks_controller.rb:24-30` verifies the HMAC signature using `Shipit.github(organization: repository_owner)`, where `repository_owner` is read from the payload's own `repository.owner.login` [1](#0-0) [2](#0-1) . This only proves the payload was genuinely sent by GitHub for *some* organization the attacker controls (their own) — it says nothing about which commit the `sha` field refers to.
- `Shipit::Webhooks::Handlers::StatusHandler#process` then does:
```
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [3](#0-2) 
This query is global across the entire `commits` table — it is not scoped to the repository/stack derived from `payload['repository']['full_name']`, unlike the base `Handler#stacks` helper (which does use `Repository.from_github_repo_name(repository_name)`) that this handler never calls [4](#0-3) .
- `Commit#create_status_from_github!` → `add_status` creates the `Status` row, then emits `Hook.emit(:commit_status, ...)` and, on a simple-state transition, `Hook.emit(:deployable_status, ...)` plus `stack.schedule_merges` for whatever stack the matched commit actually belongs to [5](#0-4) .

Exploit flow: attacker registers/owns any GitHub repo, gets Shipit's GitHub App installed on it (a legitimate, unprivileged onboarding action), then uses the GitHub Status API on their own repo to set a commit status with `sha` equal to a victim stack's known commit SHA (commit SHAs are public/observable on GitHub). GitHub sends a correctly-signed `status` webhook for the attacker's org; `verify_signature` passes because it validates against the attacker's own org secret, not the target commit's owner. `StatusHandler` then finds the victim's `Commit` row purely by SHA match and forges a `Status` for it, firing `deployable_status`/`commit_status` hooks and merge/deploy scheduling logic scoped to the victim's stack — entirely from a request the attacker fully controls the cadence and content of (`state`, `description`, `context`, `created_at`).

None of the listed guards prevent this: `verify_signature` authenticates the org, not the commit-to-repo relationship; `drop_unhandled_event` only checks the event type exists; `ExplicitParameters` only validates field types/presence, not repository ownership; there is no `Stack`/`Repository` scoping applied to the `Commit.where(sha:)` query.

### Impact Explanation
A forged `Status` record is written for a commit belonging to a stack/repository that never authenticated the payload — this is "a payload for one repository mutating another's stack, commit ... or an unauthorized deploy". The attacker can drive `commit_status`/`deployable_status` hook payloads (potentially notifying external systems with fabricated CI state for the victim) and influence merge-queue scheduling (`stack.schedule_merges`) for the victim's stack, purely by controlling status transitions on their own unrelated repository. Because the lookup is global and keyed only by `sha`, this is repeatable against any commit in any stack in the Shipit instance as long as the attacker knows/guesses the target SHA (which is typically public). This matches Critical: "a payload for one repository mutating another's stack, commit, task or team."

### Likelihood Explanation
Preconditions are minimal and within the stated attacker capability: own a GitHub repo, have Shipit's GitHub App installed on it (standard onboarding, not privileged within Shipit), and know a victim commit's SHA (public on GitHub via commits/PRs). No Shipit session, API token, or secret is required — signature verification succeeds using the attacker's own legitimately-issued webhook signature. Cost is a single GitHub Status API call per forged transition; fully repeatable and scriptable against arbitrary target SHAs.

### Recommendation
Scope the commit lookup in `StatusHandler#process` to the stacks resolved from the payload's own `repository.full_name` (reusing `Handler#stacks`), e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or equivalently join through `Stack`/`Repository` so a matched `Commit` must belong to a stack whose repository matches the authenticated payload's repository, before calling `create_status_from_github!`.

### Proof of Concept
```ruby
# test/models/webhooks/handlers/status_handler_cross_repo_test.rb
require 'test_helper'

module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerCrossRepoTest < ActiveSupport::TestCase
        test "status webhook for attacker repo cannot forge status on victim commit from another repo" do
          victim_stack = shipit_stacks(:shipit) # belongs to repo "shopify/shipit-engine"-like fixture
          victim_commit = shipit_commits(:first)
          attacker_repo_full_name = "attacker/unrelated-repo"

          payload = {
            'sha' => victim_commit.sha,
            'state' => 'success',
            'context' => 'ci/attacker',
            'created_at' => Time.now.utc.iso8601,
            'repository' => { 'full_name' => attacker_repo_full_name, 'owner' => { 'login' => 'attacker' } }
          }

          assert_no_difference -> { victim_commit.statuses.count } do
            StatusHandler.new(payload).process
          end
        end
      end
    end
  end
end
```
This test currently FAILS (the difference is +1, not 0) because `StatusHandler#process` matches `victim_commit` purely by `sha`, proving the unscoped cross-repo write. A companion test can additionally wrap the call in `assert_enqueued_with`/hook-emission expectations (as in `expect_hook_emit(:deployable_status, ...)` used elsewhere in `test/models/commits_test.rb:703-711`) to demonstrate `deployable_status`/`commit_status` firing for `victim_stack` from the attacker-controlled payload.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
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
