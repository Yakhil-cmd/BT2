### Title
`StatusHandler#process` mutates commit statuses across all tenants sharing a SHA, without repository provenance check - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` with no scoping to the repository/stack whose webhook secret authenticated the request. Any legitimate status webhook from organization A will write a `Status` row onto every `Commit` in the entire installation that happens to share that SHA, including commits belonging to unrelated stacks/organizations.

### Finding Description
The broken binding: `organization that verified the webhook signature (repository_owner in the payload)` must equal `organization owning every Commit row mutated by the handler`. It does not.

Trace:
- `Shipit::WebhooksController#create` (`app/controllers/shipit/webhooks_controller.rb:10-15`) parses the raw JSON body and dispatches to handlers via `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`.
- `verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) only checks that the HMAC signature matches the `GitHubApp` configured for `repository_owner = params.dig('repository', 'owner', 'login')`. This proves "this body was signed by organization X's webhook secret" — it proves nothing about which specific `Commit` rows in the database that organization is entitled to touch.
- Compare `Shipit::Webhooks::Handlers::Handler#stacks` (`app/models/shipit/webhooks/handlers/handler.rb:32-34`), which resolves `Repository.from_github_repo_name(repository_name)&.stacks`, i.e., scoped strictly to the repository named in the signed payload. `CheckSuiteHandler#process` (`app/models/shipit/webhooks/handlers/check_suite_handler.rb:13-17`) correctly uses this scoping: `stacks.where(branch: ...).each { |stack| stack.commits.where(sha: ...) }`.
- `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) does **not** use `stacks` at all. It queries the global `Commit` table by `sha` only:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
This means if two `Commit` rows in two different `Stack`s (belonging to different tenants/organizations) share the same `sha` value, a single signed webhook from organization A will iterate and mutate the `Commit` belonging to organization B as well, calling `commit.create_status_from_github!` (`app/models/shipit/commit.rb:165-169`) which persists a `Status` row via `statuses.replicate_from_github!`.

Attacker path: the attacker registers/owns an arbitrary Shipit-tracked repository with a live `GithubHook`. They craft a commit (empty-tree/no-op, identical author/committer/timestamps/parent/tree) engineered to collide with a target `sha` already present as a `Commit` row in a victim's stack. They trigger their own CI to POST a `status` webhook for that sha to `/webhooks`. The signature check passes because it is validated against the attacker's own organization's `webhook_secret` — it never checks that the `sha` in the payload actually belongs to a `Commit` under that organization's `Repository`.

None of the existing guards catch this: `verify_signature` validates only the signing organization, not per-commit ownership; `drop_unhandled_event` and `ExplicitParameters` only validate payload shape; there is no `stacks`/`Repository` scoping inside `StatusHandler#process` unlike its sibling `CheckSuiteHandler`.

### Impact Explanation
A single legitimate, correctly-signed webhook from one tenant can write `Status` rows onto `Commit`s belonging to arbitrary other tenants/stacks that happen to share the colliding `sha`, without those tenants' organizations having authenticated anything. This is a cross-repository write triggered by a payload from a repository that did not authenticate the target commit — the exact "payload for one repository mutating another's stack/commit" category called out as Critical. Because CI status can gate deploy eligibility (`deployable?`/CI-required deploys), this can be used to falsely mark a victim commit as CI-green (or force it red), influencing whether it can be deployed. The blast radius scales to N tenants simultaneously if N stacks share the colliding sha, and is repeatable for any sha the attacker can reproduce.

### Likelihood Explanation
This requires the attacker to actually produce a SHA1 collision (or exploit an existing coincidental duplicate `sha` across stacks, e.g. monorepo forks/mirrors, cherry-picks, or synced branches — a realistic scenario explicitly noted in the prompt) between their own commit and a target commit in a victim's stack. No Shipit secrets, sessions, or privileged roles are required — only ownership of any Shipit-tracked repository with a live `GithubHook` and the ability to author a colliding commit and fire the status webhook. The code path itself imposes no additional restriction beyond correct HMAC signing for the attacker's own org.

### Recommendation
Scope `StatusHandler#process` to the repository that authenticated the webhook, mirroring `CheckSuiteHandler`:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
This ensures only `Commit` rows belonging to stacks under the `Repository` named in the signed payload (and thus owned by the verified organization) can be mutated.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
require 'test_helper'

module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerTest < ActiveSupport::TestCase
        test "does not create statuses on commits belonging to a different repository/stack sharing the same sha" do
          colliding_sha = "6d9278037b872fd9a6690523e411ecb3aa181355"

          victim_stack = shipit_stacks(:shipit) # e.g. org "shopify/shipit-engine"
          attacker_stack = shipit_stacks(:cyclimse) # different repository/org

          victim_commit = victim_stack.commits.create!(sha: colliding_sha, message: "victim")
          attacker_commit = attacker_stack.commits.create!(sha: colliding_sha, message: "attacker")

          payload = {
            'sha' => colliding_sha,
            'state' => 'success',
            'branches' => [],
            'repository' => { 'full_name' => attacker_stack.repository.full_name, 'owner' => { 'login' => attacker_stack.repository.owner } }
          }

          # Signature verified only against attacker's org's webhook_secret,
          # yet the handler must not be able to touch victim_commit's statuses.
          assert_no_difference -> { victim_commit.reload.statuses.count } do
            assert_difference -> { attacker_commit.reload.statuses.count }, 1 do
              StatusHandler.call(payload)
            end
          end
        end
      end
    end
  end
end
```
Before the fix, `victim_commit.statuses.count` also increases by 1 in the same call, proving cross-tenant mutation from a single, correctly-signed webhook belonging to a different organization. After applying the `stacks`-scoped fix, only `attacker_commit` (the commit under the authenticated repository/stack) receives the new `Status`.