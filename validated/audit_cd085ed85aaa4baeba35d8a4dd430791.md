### Title
`StatusHandler#process` looks up commits globally by `sha`, letting any Shipit-registered organization forge status transitions on another org's stack - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` resolves target commits with `Commit.where(sha: params.sha)` without scoping the query to the repository that owns the incoming webhook. Unlike `PushHandler` and `CheckSuiteHandler`, which both restrict their side effects to `stacks` derived from `Repository.from_github_repo_name(repository_name)` (the `repository.full_name` in the payload), `StatusHandler` never consults `repository_name`/`stacks` at all, so a correctly-signed `status` webhook from organization A can mutate `Status` records - and trigger `stack.schedule_merges` / `ProcessMergeRequestsJob.perform_later(stack)` - for any stack B that happens to track a commit with the same SHA.

### Finding Description
The binding the system is supposed to enforce is: `repository_owner used to verify the webhook signature == repository that legitimately owns the sha being reported`. Concretely: `Shipit.github(organization: repository_owner).verify_webhook_signature(...)` in `WebhooksController#verify_signature` [1](#0-0)  only proves the payload was signed with the secret configured for `repository_owner` (taken straight from the attacker-supplied `payload.dig('repository','owner','login')` [2](#0-1) ). It never ties that verified organization to the specific commit/stack the payload subsequently mutates.

`StatusHandler#process` breaks that binding:
```
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [3](#0-2) 

This query is completely unscoped by repository. Compare with `PushHandler`, which restricts to `stacks.not_archived.where(branch:)` where `stacks` is derived from the payload's own `repository.full_name` [4](#0-3) , and `CheckSuiteHandler`, which does `stacks.where(branch: ...).each { |stack| stack.commits.where(sha: ...) }` [5](#0-4) . Both of those use the base `Handler#stacks` helper, which resolves `Repository.from_github_repo_name(repository_name)` [6](#0-5) . `StatusHandler` never calls `stacks` or `repository_name` - it is the only status-affecting handler that skips repository scoping.

`Commit#create_status_from_github!` calls `add_status`, and `add_status` unconditionally calls `stack.schedule_merges if new_status.pending? || new_status.success?` whenever the "simple state" changes [7](#0-6) ; `stack.schedule_merges` is what enqueues `ProcessMergeRequestsJob.perform_later(stack)` for that commit's actual `stack` (`commit.stack`, not the org that sent the webhook).

Exploit flow:
1. Attacker owns/administers an organization `attacker-org` that is a legitimately configured GitHub App/organization in this Shipit instance (with its own `webhook_secret` they know, e.g. because they set up the corresponding GitHub App installation or repo webhook themselves).
2. Attacker identifies a `sha` that is tracked by `Commit` rows belonging to a victim stack (e.g., a shared upstream commit that also exists, byte-identical, in a fork or mirror the attacker controls - forks initially share identical commit objects/SHAs with upstream until they diverge).
3. Attacker POSTs to `POST /webhooks` with `X-Github-Event: status`, `repository.owner.login = attacker-org`, and `sha` = the shared/victim sha, `state: pending` or `success`, signed with the secret for `attacker-org`.
4. `verify_signature` passes because the signature is valid for `attacker-org` - the check never verifies that `attacker-org` actually owns a repository containing that sha.
5. `StatusHandler#process` finds the victim's `Commit` row purely by `sha` (ignoring which org sent the webhook) and calls `commit.create_status_from_github!(params)`, which flips the commit's `state` and calls `stack.schedule_merges`, enqueuing `ProcessMergeRequestsJob.perform_later(victim_stack)`.
6. The victim's real merge queue (queued `MergeRequest`s waiting on CI) is then processed by `ProcessMergeRequestsJob`, using the forged status as the CI signal - potentially causing premature merges.

None of the existing guards catch this: `verify_signature` only authenticates "some org's secret was used," not "this org owns this sha/stack"; `ExplicitParameters` (`params do requires :sha ... end`) only validates types, not ownership; there is no `Stack`/`Repository` scoping anywhere in `StatusHandler`.

### Impact Explanation
An attacker who controls any single organization/repo already onboarded into a multi-tenant Shipit instance can, with zero additional privilege, forge CI status transitions for **any other tenant's stack**, as long as they can produce a matching commit `sha` (trivially achievable via forking/mirroring public upstream history, since git SHAs are content-addressed and identical across forks until divergence). This directly triggers `Shipit::ProcessMergeRequestsJob.perform_later(stack)` for a stack the attacker does not own, causing unauthorized processing - and potentially premature merging - of the victim's merge queue. This is a payload from one repository mutating another's stack/commit state and triggering an unauthorized merge action, matching the Critical severity category.

### Likelihood Explanation
Preconditions: (1) the Shipit instance hosts multiple tenants/organizations (multi-tenant deployments are the documented use case), (2) the attacker legitimately controls at least one onboarded organization with a known webhook secret, (3) the victim stack has a commit whose sha the attacker can also produce (realistic via forking public repos, mirrors, or vendored/shared commit histories), and (4) the victim stack has merge requests queued waiting on CI. Attacker cost is low: no Shipit session, API token, or victim secrets are needed - only the attacker's own legitimate webhook credentials and knowledge of a shared sha. The attack is repeatable against any stack tracking that sha.

### Recommendation
Scope `StatusHandler#process` (and any other handler that resolves records purely by `sha`/`ref` without repository context) to the repository indicated by the verified webhook payload, mirroring `PushHandler`/`CheckSuiteHandler`: resolve `stacks` via `Repository.from_github_repo_name(repository_name)` first, then look up commits only within `stack.commits.where(sha: params.sha)` instead of the global `Commit.where(sha: params.sha)`.

### Proof of Concept
```ruby
# test/models/webhooks/status_handler_cross_stack_test.rb (conceptual)
require 'test_helper'

module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerCrossStackTest < ActiveSupport::TestCase
        test "status webhook scoped to org A cannot enqueue ProcessMergeRequestsJob for org B's stack via shared sha" do
          victim_stack = shipit_stacks(:shipit) # belongs to "shopify" repo
          shared_sha = shipit_commits(:second).sha
          # commit with `shared_sha` also exists tracked under victim_stack

          attacker_payload = {
            'sha' => shared_sha,
            'state' => 'success',
            'context' => 'ci/attacker',
            'repository' => { 'owner' => { 'login' => 'attacker-org' }, 'full_name' => 'attacker-org/some-fork' }
          }

          # Binding under test: repository_owner used for signature ('attacker-org')
          # MUST equal the org owning victim_stack's repository ('shopify') for the
          # job to legitimately target victim_stack. It does not.
          assert_not_equal 'attacker-org', victim_stack.repository.owner

          assert_enqueued_with(job: ProcessMergeRequestsJob, args: [victim_stack]) do
            Shipit::Webhooks::Handlers::StatusHandler.call(attacker_payload)
          end
          # Demonstrates job enqueued for victim_stack despite signature only proving attacker-org authenticity.
        end
      end
    end
  end
end
```
This test does not require any live GitHub connection; it directly exercises `StatusHandler.call` with a payload whose `repository.owner.login` differs from the victim stack's repository owner, and asserts `ProcessMergeRequestsJob` is nonetheless enqueued for the victim stack, proving the broken binding.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
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

**File:** app/models/shipit/commit.rb (L379-384)
```ruby
      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
```
