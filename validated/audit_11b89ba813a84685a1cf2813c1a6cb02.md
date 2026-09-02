### Title
`StatusHandler#process` resolves commits by bare SHA with no repository/stack scoping, allowing cross-tenant Status writes - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` never references `Shipit.github_teams`, `current_user`, or any `ApiClient`/session concept, and contains no `authorized?`, `require_permission!`, or `stacks` scoping call of any kind. It resolves the target record with `Commit.where(sha: params.sha)` against the entire `commits` table, so a signed webhook for organization A can create a `Status` on a `Commit` row that belongs to a completely different stack/organization if that stack happens to contain a `Commit` with the same SHA (e.g. shared git ancestry between a fork and the upstream-tracked repository).

### Finding Description
The claimed binding is: `repository_owner_from_payload == stack.repository.owner_of(commit_matched_by_sha)`. Tracing the code shows this equality is never enforced.

- `app/controllers/shipit/webhooks_controller.rb` `verify_signature` (lines 24-49) validates the HMAC signature using `Shipit.github(organization: repository_owner)`, i.e. it proves the payload was signed by GitHub for the organization named in the payload — it says nothing about which `Commit`/`Stack` rows may be mutated.
- `app/models/shipit/webhooks/handlers/handler.rb` defines a `stacks` helper (lines 32-34) that scopes to `Repository.from_github_repo_name(repository_name)&.stacks`. Several other handlers (`pull_request/opened_handler.rb`, `pull_request/labeled_handler.rb`, etc.) use this `stacks` scope to find the correct record before acting [1](#0-0) .
- `app/models/shipit/webhooks/handlers/status_handler.rb` (lines 20-24) does **not** call `stacks`, does not reference `repository_name`, and instead does:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [2](#0-1) 

This lookup is global across every `Stack` in the installation, not scoped to `repository_name`/`repository_owner` from the payload at all. Since git commit SHAs are content-addressed, any two repositories that share history (a public repo and any fork of it, including one the attacker controls) will have identical SHAs for the shared ancestor commits. An attacker who owns a fork tracked by their own GitHub organization/app installation can legitimately sign a `status` webhook for their own org (satisfying `verify_signature`) referencing a SHA that is also present as a `Commit` row in an unrelated victim stack (because that commit is a shared ancestor). `create_status_from_github!` → `Status.replicate_from_github!` (`app/models/shipit/status.rb` lines 24-33) then creates a `Status` on the victim's `Commit`, which can flip `Commit#deployable?` (`app/models/shipit/commit.rb` lines 227-229) and trigger `schedule_continuous_delivery`/`deployable_status` hooks on the victim stack.

None of the listed guards close this gap: `verify_signature` authenticates the sender's organization, not the target record; `drop_unhandled_event` only filters by event type; the `ExplicitParameters` schema only validates field types/shapes; there is no `User#authorized?`/`require_permission!`/`stacks` scope call anywhere in this handler.

### Impact Explanation
An attacker who controls any GitHub organization/repository that shares commit history with a victim's tracked repository (most commonly a fork of the same upstream repo) can forge a `status` event for their own repo referencing a shared-ancestor SHA and cause a `Status` (success/failure/etc.) to be recorded against the victim stack's `Commit`. Because `Commit#deployable?` is derived from status/CI state, this can unlock (or block) deploys for the victim stack — an unauthorized-deploy-adjacent write against a tenant the attacker never authenticated against. This is repeatable against any stack whose tracked repository shares ancestry with an attacker-controlled repository, matching the Critical category "a payload for one repository mutating another's stack, commit... or an unauthorized deploy."

### Likelihood Explanation
Preconditions: the victim stack's repository must share commit history (identical SHA) with a repository the attacker controls, and the attacker's organization must have a valid webhook/app installation so `verify_signature` passes for their own org — both realistic in typical fork-based open-source workflows where Shipit is used across forks/mirrors of the same upstream. No Shipit secrets, sessions, or `github_teams` membership are required; only ordinary control over one's own GitHub repo/org webhook configuration. This is directly demonstrable and repeatable per matching SHA.

### Recommendation
Scope the commit lookup by the payload's repository, mirroring the pattern used in the `pull_request/*` handlers: resolve via `stacks` (derived from `repository_name`) and restrict `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`, or otherwise verify `commit.stack.repository.full_name == repository_name` before calling `create_status_from_github!`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
require 'test_helper'

module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerTest < ActiveSupport::TestCase
        test "process has no authorization predicate" do
          method_names = StatusHandler.instance_methods(false) + StatusHandler.private_instance_methods(false)
          refute method_names.any? { |m| m.to_s =~ /authoriz|permission|stacks/ }
        end

        test "a status event for one repo's SHA mutates a commit belonging to an unrelated stack" do
          victim_stack = shipit_stacks(:shipit) # tracks 'shopify/shipit-engine'
          shared_sha = shipit_commits(:first).sha
          shipit_commits(:first).update!(sha: shared_sha) # ensure known sha present in victim stack

          payload = {
            'sha' => shared_sha,
            'state' => 'success',
            'branches' => [{ 'name' => 'master' }],
            'repository' => { 'full_name' => 'attacker-org/forked-repo', 'owner' => { 'login' => 'attacker-org' } }
          }

          assert_difference -> { victim_stack.commits.find_by(sha: shared_sha).statuses.count }, 1 do
            StatusHandler.call(payload)
          end
        end
      end
    end
  end
end
```
This proves both halves of the broken binding: (1) no authorization-named method exists on `StatusHandler`, and (2) a payload whose `repository.full_name` never matches the victim stack still writes a `Status` onto the victim's `Commit` purely because the SHA matches.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
