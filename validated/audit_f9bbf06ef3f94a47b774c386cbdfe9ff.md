### Title
`StatusHandler#process` performs a global, unscoped `Commit.where(sha:)` lookup with no repository/stack binding check - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits purely by `sha` across the entire `commits` table with no constraint tying the match back to the repository that the incoming webhook claims to originate from. Every other stack-scoped handler (e.g. `PushHandler`) uses the `stacks` helper (`Repository.from_github_repo_name(repository_name).stacks`) to constrain writes to the calling repository, but `StatusHandler` does not, so a validly-signed webhook for one repository can write a `Status` on a `Commit`/`Stack` belonging to a completely different repository/org, including an archived one, and fire that victim stack's side effects.

### Finding Description
The implicit (and broken) binding is:

`commit.stack.repository.full_name == params.repository.full_name`

but the code never checks this. `StatusHandler#process` is: [1](#0-0) 

which does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` with **no repository/stack filter at all**. Contrast this with `PushHandler#process`, which explicitly scopes through `stacks` (built from `Repository.from_github_repo_name(repository_name)`) before touching anything: [2](#0-1) 

The base `Handler` class even provides this exact scoping primitive that `StatusHandler` simply doesn't use: [3](#0-2) 

`commit.create_status_from_github!` then writes a `Status` row stamped with the **commit's own** `stack_id` (not derived from the webhook's claimed repository at all): [4](#0-3) 

`Status` fires `after_commit :broadcast_update` (delegated to `commit`, i.e. `stack.broadcast_update`), publishing to the victim's Pubsubstub channel: [5](#0-4) [6](#0-5) 

and `Commit#add_status` additionally emits `Hook.emit(:commit_status, stack, ...)` / `:deployable_status` (fanning out to any external hooks configured on the *victim's* stack) and calls `stack.schedule_merges` when the new status is `pending`/`success`: [7](#0-6) 

None of this is gated on the stack's `archived_since` state, and archiving a stack (`not_archived` scope) never deletes its `Commit`/`Status` rows, so an archived victim stack remains a fully valid target.

**Exploit path**: The attacker needs a webhook that will pass `WebhooksController#verify_signature`. That check resolves the HMAC secret purely from attacker-controlled JSON (`payload.dig('repository','owner','login')`): [8](#0-7) 

So the attacker must be able to produce a validly-signed `status` event for *some* organization/app-installation that this Shipit instance trusts (e.g. their own repo under an org that is a legitimate, separately-configured GitHub App tenant of this Shipit instance — Shipit explicitly supports "Using Multiple Github Applications", each with its own `webhook_secret`). Once they can fire *any* legitimately-signed `status` webhook, the `sha` field is fully attacker-controlled text (a git SHA is public, non-secret information — visible on any public commit/PR page, or literally identical across forks of a public repo). The handler then matches that `sha` against `Commit` rows **globally**, irrespective of which repository/org sent the webhook, and writes a `Status` + fires hooks/broadcast for whatever stack owns that commit — even if that stack belongs to a different tenant/org than the one that authenticated the webhook.

Existing guards do not stop this:
- `verify_signature` only proves the request came from *some* trusted org/app installation, not that it's authorized for the *target* commit's stack.
- `drop_unhandled_event` / `ExplicitParameters` (`params do requires :sha, String ... end`) only validate shape, not ownership.
- `Stack.not_archived` is never applied by `StatusHandler`.
- There is no `stack ==` / `repository ==` equality check anywhere in the `process` method or in `Commit#create_status_from_github!`.

### Impact Explanation
A caller who is authenticated only for their own repository/org can, in a single request, force a `Status` write and stack-scoped side effects (`Pubsubstub.publish("stack.#{id}", ...)`, `Hook.emit(:commit_status/:deployable_status, stack, ...)`, and potentially `stack.schedule_merges` → `ProcessMergeRequestsJob`) against a completely unrelated stack/repository/tenant, including one that has been archived by its rightful owner. This is "a payload for one repository mutating another's stack, commit ... or an unauthorized deploy/rollback/merge" — squarely the Critical impact category, since a `pending`/`success` status transition can trigger merge-queue processing (`stack.schedule_merges`) on a foreign stack. It is repeatable against any commit sha the attacker can learn (public git shas are not secret), and is not limited to a single victim — any tracked `Commit` row in the whole installation is reachable this way, so the blast radius spans every tenant sharing the Shipit instance.

### Likelihood Explanation
Preconditions: the attacker must be able to produce one validly HMAC-signed `status` webhook for *any* org/app-installation configured in this Shipit deployment (i.e., control of a repo in a legitimate tenant org, or a misconfigured org with `webhook_secret` unset, which trivially bypasses `verify_webhook_signature`). Given that, the attacker's cost is a single crafted HTTP POST with an arbitrary `sha` value they've read off a public GitHub page. No GitHub App private key, `secret_key_base`, or `api_clients_secret` is needed. This is highly feasible in any multi-tenant Shipit deployment and fully repeatable per commit.

### Recommendation
In `StatusHandler#process`, scope the `Commit` lookup through the same `stacks` helper other handlers use, e.g. `stacks.joins(:commits).where(commits: { sha: params.sha })` (or filter `commit.stack.repository.full_name == repository_name` before calling `create_status_from_github!`), so a status event can only mutate commits/stacks belonging to the repository asserted in — and cryptographically bound to — the webhook payload.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
require 'test_helper'

module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerCrossRepoTest < ActiveSupport::TestCase
        test "status webhook from foreign repository must not update a victim stack's commit/status" do
          victim_stack = shipit_stacks(:shipit)
          victim_commit = shipit_commits(:first) # belongs to victim_stack
          victim_stack.update!(archived_since: Time.now) # simulate archived/pending-deletion victim

          # Binding under test: commit.stack.repository.full_name == params.repository.full_name
          assert_not_equal victim_commit.stack.repository.full_name, "attacker/unrelated-repo"

          foreign_payload = {
            "sha" => victim_commit.sha,
            "state" => "success",
            "context" => "ci/attacker",
            "target_url" => "http://evil.example",
            "created_at" => Time.now.iso8601,
            "repository" => { "full_name" => "attacker/unrelated-repo", "owner" => { "login" => "attacker" } }
          }

          Pubsubstub.expects(:publish).with("stack.#{victim_stack.id}", anything, anything).never

          assert_no_difference "victim_commit.statuses.count" do
            Shipit::Webhooks::Handlers::StatusHandler.new(foreign_payload).process
          end
        end
      end
    end
  end
end
```

Running this against the current code demonstrates the opposite of the assertions: `victim_commit.statuses.count` increases by 1 and `Pubsubstub.publish("stack.#{victim_stack.id}", ...)` **is** called, proving the foreign-repository payload mutated the archived victim stack purely because `StatusHandler#process` never checks `params.repository.full_name` against `commit.stack.repository.full_name`.

### Citations

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

**File:** app/models/shipit/status.rb (L18-21)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

    delegate :broadcast_update, to: :commit
```

**File:** app/models/shipit/stack.rb (L561-567)
```ruby
    def broadcast_update
      Pubsubstub.publish(
        "stack.#{id}",
        { id:, updated_at: }.to_json,
        name: 'update'
      )
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
