### Title
`StatusHandler#process` resolves commits by SHA with no repository scoping, letting a webhook for one repository write a `Status` and broadcast a `Pubsubstub` update for an unrelated victim stack - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` looks up commits with `Commit.where(sha: params.sha)` across the entire `commits` table instead of scoping to the repository named in the webhook payload. `Status#after_commit -> broadcast_update` (delegated to `Commit#broadcast_update` -> `Stack#broadcast_update`) then publishes to `Pubsubstub` on `"stack.#{id}"` for whatever stack owns the matching commit, regardless of which repository actually sent the webhook.

### Finding Description
The broken binding is: `commit.stack == Repository.from_github_repo_name(payload.dig('repository','full_name')).stacks` — this is **not enforced**. `Handler` (the base class) exposes exactly this scoping helper: [1](#0-0) 
but `StatusHandler#process` never uses it: [2](#0-1) 

`WebhooksController#verify_signature` only proves that the request was signed by the GitHub App/organization identified by `repository_owner` in the payload — it says nothing about which commit SHA the payload may reference: [3](#0-2) 

So an attacker who legitimately owns/administers *any* GitHub organization/repo wired into this Shipit instance (their own installation, their own webhook secret) can produce a validly-signed `status` event whose `sha` field is copied from a public commit belonging to a completely unrelated victim repository/stack. `StatusHandler#process` finds *all* `Commit` rows in the DB with that SHA — including the victim's — and calls `commit.create_status_from_github!(params)` on each: [4](#0-3) 

That creates a `Status` record tied to the victim's `stack_id`: [5](#0-4) 
whose `after_commit :broadcast_update` delegates through `Commit#broadcast_update` to `Stack#broadcast_update`, publishing on the victim's public channel: [6](#0-5) 

That channel is exactly the one any browser subscribes to on the victim's stack page (`stack.#{id}` via SSE), so anyone monitoring/guessing that channel learns the victim stack exists and is receiving a CI update, without ever having access to the victim's Shipit stack: [7](#0-6) 

None of the existing guards stop this: `verify_signature` authenticates the *sender's own org*, not the SHA's owning repository; `drop_unhandled_event` only checks the event type is registered; the `ExplicitParameters` schema in `StatusHandler` only validates `sha`/`state` types, not repository ownership; there is no `stacks`/`Repository.from_github_repo_name` filter applied at all in this handler.

### Impact Explanation
An attacker who controls webhooks for any repository already onboarded into the Shipit instance can, per request, create a real `Status` row against an arbitrary victim commit/stack (as long as they know or can reuse that commit's 40-character SHA, e.g. from the victim's public GitHub history) and force a `Pubsubstub.publish("stack.#{victim_stack.id}", ...)` broadcast. This is repeatable against any stack whose commits' SHAs the attacker can learn, and is not limited to a single tenant — it works across all repositories hosted on the same Shipit instance. This matches the High category: unauthenticated read/inference of a victim stack's CI/deploy state triggered purely by an attacker-controlled webhook on an unrelated repository. (Note: because `create_status_from_github!` also drives `schedule_continuous_delivery`/`Hook.emit(:commit_status, ...)`, the same missing scoping could push this into the Critical "cross-repository mutation"/"unauthorized deploy" category if the victim stack has continuous deployment enabled — that broader consequence is out of this question's stated scope but worth flagging.)

### Likelihood Explanation
Preconditions are low-cost for the attacker: they only need one Shipit-registered GitHub org/repo of their own (to get a validly-signed webhook) and the target's commit SHA, which is typically public (GitHub commit pages, PRs, CI logs). No Shipit session, API token, or secrets are required. The attack is trivially repeatable — one crafted `status` webhook per target commit.

### Recommendation
Scope the commit lookup in `StatusHandler#process` to the repository asserted by the payload, using the existing `stacks` helper from `Handler`, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or equivalent `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`, mirroring how other handlers already scope via `stacks`.

### Proof of Concept
```ruby
# test/models/webhooks/handlers/status_handler_test.rb
module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerCrossStackTest < ActiveSupport::TestCase
        test "a status webhook for repo A does not create a Status/broadcast for a commit belonging to unrelated stack B" do
          victim_stack = shipit_stacks(:shipit)
          victim_commit = victim_stack.commits.create!(sha: 'deadbeef' * 5, message: 'victim commit')

          attacker_payload = {
            'repository' => { 'full_name' => 'attacker-org/attacker-repo' },
            'sha' => victim_commit.sha,
            'state' => 'success',
            'context' => 'ci/attacker'
          }

          Pubsubstub.expects(:publish).with("stack.#{victim_stack.id}", anything, anything).never

          assert_no_difference -> { victim_commit.statuses.count } do
            StatusHandler.call(attacker_payload)
          end
        end
      end
    end
  end
end
```
Given the current implementation (`Commit.where(sha: params.sha)` with no repository filter), this test fails: `victim_commit.statuses.count` increases and `Pubsubstub.publish("stack.#{victim_stack.id}", ...)` is called, proving the cross-repository write/broadcast.

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/status.rb (L17-21)
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

**File:** app/views/shipit/stacks/show.html.erb (L1-1)
```erb
<% subscribe events_path(channels: ["stack.#{@stack.id}"]), '#layout-content' %>
```
