Migration `20170524104615_index_commits_on_stack_id_and_sha.rb` confirms the index is on `(stack_id, sha)`, not a unique index on `sha` alone — meaning multiple `Commit` rows across different stacks legitimately share the same `sha` (this is expected, since the same git commit object can exist in multiple repositories/forks with an identical SHA). This confirms the vulnerability: `StatusHandler#process` queries only by `sha` with no `stack_id`/`repository` scoping, so it will match and mutate every stack across every tenant that happens to have a commit with that SHA.

### Title
Cross-tenant status forgery via unscoped SHA lookup in `StatusHandler#process` - (`app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits solely by `Commit.where(sha: params.sha)`, without filtering by the repository that actually sent the webhook, unlike every other handler in `app/models/shipit/webhooks/handlers/**` which resolves `repository = Repository.from_github_repo_name(params.repository.full_name)` before touching any records. Since git commit SHAs are content-addressed and repository-independent, an attacker who owns/controls repository R1 (with a legitimate, signature-verified webhook subscription) can send a `status` event whose `sha` matches a commit that also exists in victim stack S2 (e.g. a shared history/fork commit), causing Shipit to write a forged `Status` onto S2's commit and fire `Hook.emit(:commit_status/:deployable_status, stack, ...)` with S2 as the target and attacker-controlled `state`/`description`/`context`/`target_url`.

### Finding Description
The broken binding: `Hook.emit` target stack `== commit.stack` (S2), which the code implicitly assumes is the same stack/repository that produced `params` — but `params.repository.full_name` is **never read** by `StatusHandler`, so the actual origin repository R1 is invisible to the trust decision.

Code path:
1. `WebhooksController#verify_signature` [1](#0-0)  only verifies that the HMAC signature is valid for the organization named in `params.dig('repository','owner','login')` — i.e., it proves "this request genuinely came from GitHub org O", not "this request's `sha` belongs to a commit owned by org O".
2. `WebhooksController#create` dispatches to handlers generically: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [2](#0-1) .
3. `StatusHandler#process` does: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [3](#0-2) . Note the base `Handler` class exposes helper methods `repository_name`/`stacks` scoped by `payload.dig('repository','full_name')` [4](#0-3)  but `StatusHandler` never calls them.
4. `Commit#create_status_from_github!` calls `add_status { statuses.replicate_from_github!(stack_id, github_status) }` where `stack_id` is the **matched commit's own** `stack_id` [5](#0-4) .
5. `add_status` computes the new status and, if it changed, calls `Hook.emit(:commit_status, stack, payload...)` and potentially `Hook.emit(:deployable_status, stack, payload...)`, using `commit.stack` — the victim's stack S2 — as the emit target [6](#0-5) .
6. The DB schema permits this: the index on `commits` is `(stack_id, sha)` (migration `20170524104615_index_commits_on_stack_id_and_sha.rb`), not a unique index on `sha` alone, confirming that identical SHAs across different stacks/repos are an expected, supported data state (forks, shared history, cherry-picks, mirrored repos).

Attacker exploit flow: attacker registers/owns repository R1 whose GitHub org is a legitimately onboarded Shipit tenant (so `verify_signature` passes). Attacker (or GitHub, automatically, since attacker can trigger CI on R1) sends a `status` webhook to `POST /webhooks` with `sha` set to a commit SHA that is publicly known to also exist in victim stack S2 (e.g., a shared upstream commit, a fork point, or any commit whose SHA the attacker can discover from S2's public repo/GitHub history) and arbitrary `state`/`description`/`context`/`target_url`. Because `repository.full_name` is never checked against the matched `Commit`'s stack, Shipit writes the forged status onto S2's commit and fires `Hook.emit` with S2 as the target, causing S2's configured `Shipit::Hook` to POST the forged payload to the victim's outbound hook endpoint using the victim's `Hook` (its own `delivery_url`/signing).

Existing guards fail because:
- `verify_signature` authenticates *sender org*, not *sha ownership*.
- `drop_unhandled_event` only checks the event type is registered, not scope.
- `ExplicitParameters` schema for `StatusHandler` requires `sha`/`state` but does not require or use `repository.full_name` for scoping (unlike sibling `PullRequest::*Handler`s which all resolve and filter by `repository`).
- There is no `stack`/`repository` ownership check anywhere in `StatusHandler` or `Commit#create_status_from_github!`.

### Impact Explanation
Per malicious request, the attacker can: (a) write an arbitrary forged `Status` row (`state`, `description`, `context`, `target_url`) onto any commit belonging to any other tenant's stack whose SHA they can guess/know, and (b) trigger `Hook.emit(:commit_status, ...)`/`Hook.emit(:deployable_status, ...)` targeting that victim stack, causing the victim's own configured webhook subscriber(s) to fire with attacker-controlled content, and (c) since `deployable_status`/`commit_status` transitions feed `stack.schedule_merges` in `add_status`, this can also trigger `ProcessMergeRequestsJob` for the victim's stack, potentially causing an **unauthorized merge/deploy** if the forged status flips the commit into a "success" state satisfying merge-queue requirements. This is a cross-tenant write to a repository/stack that never authenticated it and directly matches the "Critical" bucket ("a payload for one repository mutating another's stack, commit, task or team," "unauthorized deploy, rollback or merge"). The attack is repeatable against any stack whose commits share a discoverable SHA with a repo the attacker controls (trivial via forking a public victim repo, since fork commits retain identical SHAs to the upstream).

### Likelihood Explanation
Preconditions: attacker needs (1) a repository whose GitHub organization is already legitimately connected to the target Shipit instance (so `verify_signature` succeeds for their own webhook deliveries — a low bar, e.g. any developer at a company using the same self-hosted Shipit instance across many teams/repos, or any onboarded org in a multi-tenant deployment), and (2) knowledge of a target commit SHA that also exists in the victim's Shipit-tracked stack (trivially obtained if the victim repo is public, or via forking it). No secrets, sessions, or privileged roles are required beyond standing webhook delivery for R1. Cost is a single crafted HTTP POST; fully repeatable and scriptable against any number of target stacks/SHAs.

### Recommendation
Scope `StatusHandler#process` the same way as the sibling handlers: resolve `repository = Repository.from_github_repo_name(params.repository.full_name)` and restrict the commit lookup to `repository.stacks`/that repository's commits (e.g., `Commit.where(sha: params.sha, stack_id: repository.stacks.select(:id))`), rejecting or ignoring matches outside the sending repository's own stacks. Add a `requires :repository { requires :full_name, String }` to the `StatusHandler` params schema to enforce this at the schema level, matching the pattern already used by `PullRequest::*Handler`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
require 'test_helper'

module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerCrossTenantTest < ActiveSupport::TestCase
        test "a status webhook for repo R1 must not emit Hook events for stack S2 (a different repository)" do
          victim_stack = shipit_stacks(:shipit) # belongs to repository "shopify/shipit-engine" (S2)
          attacker_repo_full_name = "attacker/unrelated-repo" # R1, distinct repository, but shares SHA history

          shared_sha = shipit_commits(:first).sha
          victim_commit = shipit_commits(:first)
          assert_equal victim_stack, victim_commit.stack

          payload = {
            'sha' => shared_sha,
            'state' => 'success',
            'description' => 'forged',
            'context' => 'attacker-forged-ci',
            'created_at' => Time.now.to_s,
            'repository' => { 'full_name' => attacker_repo_full_name }, # R1, NOT S2's repo
          }

          # Binding under test: Hook.emit target stack must equal a stack whose
          # repository actually matches params['repository']['full_name'] (R1),
          # never S2 (victim_stack), since R1 != S2's repository.
          Hook.expects(:emit).with(:commit_status, victim_stack, anything).never
          Hook.expects(:emit).with(:deployable_status, victim_stack, anything).never

          StatusHandler.call(payload)
        end
      end
    end
  end
end
```
Running this against current code fails (the `.never` expectations are violated) because `StatusHandler#process` ignores `params['repository']` entirely and matches purely on `sha`, firing `Hook.emit` for `victim_stack` despite the payload's declared origin being `attacker/unrelated-repo`. [3](#0-2) [6](#0-5)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
