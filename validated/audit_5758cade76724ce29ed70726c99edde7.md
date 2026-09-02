This confirms the finding. `PushHandler#process` and `CheckSuiteHandler#process` both scope their work through `stacks` (derived from `payload.dig('repository', 'full_name')` via `Repository.from_github_repo_name`), so a push/check_suite webhook can only affect stacks belonging to the repository named in that specific payload. `StatusHandler#process`, however, does not use `stacks` at all — it queries `Commit.where(sha: params.sha)` globally, with no repository/stack scoping whatsoever.### Title
`StatusHandler#process` resolves `Commit.where(sha:)` globally, letting an attacker-authenticated status payload for one repository fire `Hook.emit(:commit_status/:deployable_status, ...)` for an unrelated victim stack that happens to share a commit SHA - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` looks up commits purely by `sha`, with no scoping to the repository named in the authenticated webhook payload, unlike sibling handlers (`PushHandler`, `CheckSuiteHandler`) which always scope through `stacks` (derived from `payload.dig('repository', 'full_name')`). Because `commits` are only uniquely indexed on `(stack_id, sha)` and not globally unique on `sha`, any commit SHA that exists in more than one stack's commit table (e.g. via a fork sharing git history, a cherry-pick, or any coincidental match) can be targeted by an attacker who only controls a repository in an org whose webhook secret Shipit already trusts, causing `Commit#add_status` to run against the victim's `Commit`/`Stack` and to call `Hook.emit(:commit_status, victim_stack, ...)` / `Hook.emit(:deployable_status, victim_stack, ...)`.

### Finding Description
The broken binding is:
`repository_owner (used only to select the org whose webhook secret verifies the request)` ≠ `stack.repository (the repository whose Hook receives the emitted payload)`.

Code path:
- `WebhooksController#verify_signature` verifies the HMAC signature using `Shipit.github(organization: repository_owner)` [1](#0-0) . This only proves the payload came from GitHub for *some org* Shipit trusts — it says nothing about which specific repository's data the payload is allowed to touch.
- `StatusHandler#process` then does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [2](#0-1) 
This never calls the `stacks` helper (`Repository.from_github_repo_name(repository_name)&.stacks`) that the base `Handler` class provides and that other handlers rely on for scoping [3](#0-2) . In contrast, `PushHandler#process` scopes via `stacks.not_archived.where(branch:)` [4](#0-3)  and `CheckSuiteHandler#process` scopes via `stacks.where(branch: ...)` before touching `stack.commits` [5](#0-4) . `StatusHandler` is the outlier that skips repository scoping entirely.
- `Commit#create_status_from_github!` calls `add_status`, which after replicating the (attacker-supplied) status calls `Hook.emit(:commit_status, stack, ...)` and conditionally `Hook.emit(:deployable_status, stack, ...)` using `self.stack` — i.e. the **victim's** stack, resolved purely from the matching `Commit` row, not from the payload's repository [6](#0-5) .
- The `commits` table is only indexed/expected unique on `(stack_id, sha)`, not globally unique on `sha` alone (per migration `20170524104615_index_commits_on_stack_id_and_sha.rb`), and there is no model validation enforcing SHA uniqueness across stacks. This means multiple stacks/repositories (e.g. a fork and its upstream, or any two stacks that independently ingested a commit with the same SHA) can legitimately hold `Commit` rows with identical `sha`.

Exploit flow: the attacker owns/controls a repository belonging to a GitHub org whose webhook secret is configured in Shipit (satisfying `verify_signature`), or one for which no `webhook_secret` is configured at all (in which case `GithubApp#verify_webhook_signature` returns `true` unconditionally) [7](#0-6) . The attacker sends (or triggers GitHub to send) a `status` event whose `sha` matches a commit SHA that also exists in the victim's stack (trivially achievable if the attacker's repo is a fork sharing history with the victim's tracked repo, or the attacker discovers/guesses a public commit SHA). `StatusHandler#process` finds the victim's `Commit` (in addition to, or instead of, any commit of the attacker's own stack) purely by SHA match and creates a `Status` on it, which fires `Hook.emit(:commit_status/:deployable_status, victim_stack, ...)`, which is delivered via `EmitEventJob` → `Hook.deliver` → `hook.deliver!` → `DeliverHookJob.perform_later` → `DeliverHookJob#perform` → `Hook::DeliverySpec#send!`, sending the victim stack's commit/status payload to whatever receiver URL the victim configured on their `Hook`.

None of the listed guards prevent this: `verify_signature` only authenticates "some trusted GitHub org sent this", not "this payload may only affect this repository's stacks"; `drop_unhandled_event` only checks the event type is registered; the `ExplicitParameters` schema for `StatusHandler` only requires `sha`/`state`/etc. syntactically, it does not require or validate `repository.full_name` at all (unlike `PushHandler`'s/`CheckSuiteHandler`'s implicit dependency on `stacks`); there is no `require_permission!`, `User#authorized?`, or repository-ownership check in this webhook path since it is unauthenticated-user-agnostic (GitHub-to-server webhook, not session-based).

### Impact Explanation
An attacker who authenticates only as "some repository under a trusted org" (or any repository if no webhook secret is configured for that org) can cause a write (`Status` creation) against a `Commit`/`Stack` record that did not authenticate that payload, and can force that victim stack's configured `Hook` to fire and deliver the victim's commit/stack data to the hook's `delivery_url`. This matches the "payload for one repository mutating another's stack, commit ... " Critical category, and also the "unauthenticated read of stack state" / cross-tenant disclosure High category, since the emitted `Hook.deliver!` payload includes the victim's `commit`, `stack`, and status details [8](#0-7) . The blast radius spans any stack in the Shipit instance whose commit SHA space overlaps with a repository the attacker controls — repeatable for every future status the attacker's repo emits against a shared SHA.

### Likelihood Explanation
Preconditions: (1) the victim stack must have a `Hook` registered on `commit_status` or `deployable_status`; (2) a commit SHA must exist in both the attacker's own repository/stack (so a `status` webhook naturally fires for it, or the attacker manually crafts and sends the POST) and the victim's stack's `commits` table; (3) the org owning the attacker's repository must pass `verify_signature` (either it's the same/trusted org as the victim, or no `webhook_secret` is configured for that org). SHA collision across stacks is realistic in practice (forks sharing git history, mirrored repos, cherry-picks/backports, or simply the attacker manually crafting the JSON body if they can determine a victim commit SHA and post directly to `/webhooks` with a spoofable `repository.owner.login` matching a trusted/unsecured org). No Shipit session, API token, or GitHub secret is required beyond controlling one webhook-emitting repository. This is a low-cost, repeatable attack given the precondition is met.

### Recommendation
Scope `StatusHandler#process` the same way as `PushHandler`/`CheckSuiteHandler`: restrict the lookup to commits belonging to `stacks` derived from `payload.dig('repository', 'full_name')`, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or equivalently join `Commit` through the resolved `Repository`'s stacks before calling `create_status_from_github!`. Additionally, consider enforcing `(sha)` uniqueness scoped by repository at the model layer if cross-repo SHA reuse must be prevented from causing any incidental cross-stack effects elsewhere.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
require 'test_helper'

module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerCrossRepoTest < ActiveSupport::TestCase
        test "a status payload for repo A does not update commits/stacks belonging to repo B with the same sha" do
          victim_stack = shipit_stacks(:shipit)          # repository = "shopify/shipit-engine"
          attacker_stack = shipit_stacks(:cyclimse)       # a different repository/org, e.g. "attacker/evil-fork"

          shared_sha = "deadbeef" * 5
          victim_commit = victim_stack.commits.create!(sha: shared_sha, message: "victim commit", author: shipit_users(:walrus), committer: shipit_users(:walrus), authored_at: Time.now, committed_at: Time.now)

          Hook.create!(stack: victim_stack, url: "https://victim-receiver.example.com/hook", events: ["commit_status"])

          payload = {
            "sha" => shared_sha,
            "state" => "success",
            "branches" => [{ "name" => attacker_stack.branch }],
            "repository" => { "full_name" => attacker_stack.repository.full_name, "owner" => { "login" => attacker_stack.repository.owner } }
          }

          assert_enqueued_with(job: DeliverHookJob) do
            Shipit::Webhooks::Handlers::StatusHandler.call(payload)
          end

          # Binding check: the delivery must NOT reference the victim stack/commit,
          # since the payload only authenticated attacker_stack's repository.
          delivered_hook_id = enqueued_jobs.find { |j| j[:job] == DeliverHookJob }[:args].first["hook_id"]
          refute_equal victim_stack.hooks.first.id, delivered_hook_id,
            "status payload authenticated for #{attacker_stack.repository.full_name} must not trigger victim stack's (#{victim_stack.repository.full_name}) hook"

          assert_no_difference -> { victim_commit.reload.statuses.count } do
            # currently FAILS: StatusHandler#process matches Commit.where(sha: shared_sha) globally
            # and creates a Status on victim_commit, firing Hook.emit(:commit_status, victim_stack, ...)
          end
        end
      end
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/commit.rb (L366-384)
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
```

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```
