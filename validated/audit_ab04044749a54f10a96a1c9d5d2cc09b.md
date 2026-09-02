### Title
Cross-repository Commit/Status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` triggers victim `Stack`'s `Hook.emit` with attacker-controlled data - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves target commits solely by `Commit.where(sha: params.sha)`, without ever checking that the commit's owning `Stack`/`Repository` matches the `repository.full_name` in the signed webhook payload. Because `Commit#add_status` derives `stack` from the mutated `Commit`'s own `belongs_to :stack` association rather than from the payload, an attacker who can get *any* validly-signed 'status' webhook accepted by Shipit (for a repo/org they control) can target a victim's `Commit` by SHA and cause `Hook.emit(:commit_status/:deployable_status, victim_stack, ...)` to fire with attacker-supplied `description`/`target_url`.

### Finding Description
The claimed binding is: `Stack whose Hook.emit fires == Stack named in the attacker-signed payload's repository.full_name`. Tracing the code shows this binding is broken.

`WebhooksController#create` dispatches the parsed JSON body to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` after `verify_signature`, which only checks that the signature is valid for `Shipit.github(organization: repository_owner)` where `repository_owner = params.dig('repository','owner','login')` [1](#0-0) .
This proves the payload is authentic *for the organization/repo the attacker controls*, not that the `sha` inside it belongs to that same repository.

`Webhooks::Handlers::Handler` provides a `stacks`/`repository_name` helper explicitly meant to scope lookups to `Repository.from_github_repo_name(payload.dig('repository','full_name'))` [2](#0-1) ,
but `StatusHandler#process` never uses it:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [3](#0-2) 

This queries `Commit` globally across every `Stack`/`Repository` in the Shipit instance by `sha` alone. `sha` is an attacker-controlled parameter (`requires :sha, String`) and commit SHAs are not secrets — they are public, visible on GitHub UI/API for any repo.

`create_status_from_github!` then calls `add_status`, which resolves `stack` from the matched (victim) `Commit`'s own association, not from the payload:
```ruby
def create_status_from_github!(github_status)
  add_status do
    statuses.replicate_from_github!(stack_id, github_status)
  end
end
...
payload = { commit: self, stack:, status: new_status.state }
Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
...
Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
``` [4](#0-3) [5](#0-4) 

`description`/`target_url` flow straight from the attacker's `params` into the `Status` record (`Status.replicate_from_github!` reads `github_status.description`/`target_url`) [6](#0-5) ,
and are exposed in the `payload.merge(commit_status: new_status)`/`deployable_status: new_status` object passed to `Hook.emit`, which is what fires the victim's configured outbound Slack/webhook `Hook`s.

**Exploit flow**: attacker owns/controls a repository/org that has the Shipit GitHub App installed (satisfying `verify_signature`). They obtain a target victim commit SHA (public information from GitHub). They emit (or directly POST, since signature verification only checks the org named in the JSON, which is under attacker control) a `status` event with `repository.full_name` = attacker's own repo, `sha` = victim's commit SHA, and arbitrary `state`/`description`/`target_url`. `verify_signature` passes because it validates against the attacker's own org. `StatusHandler#process` matches the victim's `Commit` row purely by `sha`, ignoring `repository_name`, and fires `Hook.emit` against the victim's `Stack`.

None of the listed guards prevent this: `verify_signature` authenticates the *sender's own org*, not that the `sha` belongs to that org's repo; the `ExplicitParameters` schema only validates types, not ownership; `drop_unhandled_event` only checks the event is registered; there is no `stacks`/`Repository.from_github_repo_name` scoping in `StatusHandler` at all (unlike the helper `Handler` provides for this exact purpose).

### Impact Explanation
This is a payload authenticated for repository A mutating a `Commit`/`Stack` belonging to unrelated repository/tenant B: a `Status` row is written under the victim's `stack_id`, and `Hook.emit(:commit_status, ...)`/`Hook.emit(:deployable_status, ...)` fire against the victim `Stack`'s configured `Hook`s (e.g., Slack/webhook URLs configured by the victim's operator), carrying attacker-controlled `description`/`target_url` strings. It also can influence `stack.schedule_merges` (queued `ProcessMergeRequestsJob`) since `new_status.pending?`/`success?` changes stack merge-processing state for the victim stack. This matches the Critical category "a payload for one repository mutating another's stack, commit, task or team," is repeatable against any commit SHA the attacker can learn (all public), and is not limited to one victim — any Stack/Repository configured on the same Shipit instance is reachable as long as the attacker knows a commit SHA that exists in that stack's `commits` table.

### Likelihood Explanation
Preconditions: the attacker needs a repository/org registered with Shipit's GitHub App configuration (`Shipit.github(organization: repository_owner)` must resolve, i.e., not raise `GithubOrganizationUnknown`) so that `verify_signature` succeeds for *some* org — this is satisfied by any org/repo the attacker legitimately owns and has connected to this Shipit instance (a normal, unprivileged setup step available to "any GitHub user who can... push to a fork"/"emit webhooks from a repository they own"). No Shipit session, API token, or GitHub App private key is required — only a validly-signed webhook for the attacker's own registered repo, which GitHub itself will sign automatically when the attacker performs ordinary actions (e.g., posting a commit status via GitHub's API on their own repo). Target commit SHAs are public. This makes the attack low-cost and fully repeatable.

### Recommendation
In `StatusHandler#process`, scope the `Commit` lookup to the repository named in the payload, mirroring the `Handler#stacks` helper, e.g.:
```ruby
def process
  Commit.where(sha: params.sha, stack: stacks).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
so a webhook signed for repository/org A can never write to or fire hooks for a `Stack` belonging to a different `Repository`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
require 'test_helper'

module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerTest < ActiveSupport::TestCase
        test "a status payload for repo A cannot fire Hook.emit for repo B's stack" do
          victim_stack = shipit_stacks(:shipit) # belongs to repo "shopify/shipit-engine" e.g.
          victim_commit = shipit_commits(:first)
          assert_equal victim_stack, victim_commit.stack

          attacker_payload = {
            'sha' => victim_commit.sha,
            'state' => 'failure',
            'description' => 'ATTACKER CONTROLLED',
            'target_url' => 'https://evil.example.com/payload',
            'repository' => { 'full_name' => 'attacker/unrelated-repo', 'owner' => { 'login' => 'attacker' } }
          }

          Hook.expects(:emit).with(:commit_status, victim_stack, has_entries(
            commit: victim_commit
          ))

          StatusHandler.call(attacker_payload)

          status = victim_commit.reload.statuses.last
          assert_equal 'ATTACKER CONTROLLED', status.description
          assert_equal 'https://evil.example.com/payload', status.target_url
          assert_equal victim_stack.id, status.stack_id
        end
      end
    end
  end
end
```
Both sides of the binding differ: `params['repository']['full_name']` = `"attacker/unrelated-repo"` while `Hook.emit`'s `stack` = `victim_stack` (belonging to a different repository) — proving the payload's declared repository does not match the stack whose hooks were invoked.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-49)
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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
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

**File:** app/models/shipit/status.rb (L23-33)
```ruby
    class << self
      def replicate_from_github!(stack_id, github_status)
        find_or_create_by!(
          stack_id:,
          state: github_status.state,
          description: github_status.description,
          target_url: github_status.target_url,
          context: github_status.context,
          created_at: github_status.created_at
        )
      end
```
