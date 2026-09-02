### Title
Cross-repository status forgery via unscoped `Commit.where(sha:)` lookup allows attackers to satisfy a victim stack's `required_statuses` gate - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves the target commit(s) for an inbound `status` webhook purely by `sha`, with no constraint tying the webhook's `repository` to the `Commit`'s owning `Stack`/repository. An attacker who can generate a legitimately-signed webhook for a commit they control (e.g. by pushing to their own repo under an organization Shipit also monitors, or by forking a victim repo so early commits share identical SHA1s) can set `context` to any value, including a victim stack's exact `required_statuses` entry, and `state: 'success'`, causing every `Commit` row across every stack that happens to share that SHA to be marked as passing that named check.

### Finding Description
The broken binding: `context_string_authorized_by(victim Stack#required_statuses)` == `context_string_supplied_by(attacker payload)`. This binding is trivially satisfiable because the attacker fully controls `params.context` and `params.state` in the JSON body of a `status` event, and nothing in the reachable code path constrains which repository's commits a given payload is allowed to update.

Path:
- `Shipit::WebhooksController#create` parses the raw JSON body and dispatches to `Shipit::Webhooks.for_event(event)`, after `verify_signature`, which only checks the HMAC signature against the `webhook_secret` configured for `repository_owner` (`params.dig('repository','owner','login')`) — it says nothing about which specific *repository* the payload references. [1](#0-0) 
- `StatusHandler#process` then does: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — this query matches **any** `Commit` record in the database with that SHA, regardless of which `Stack`/repository it belongs to. [2](#0-1) 
- `Commit#required_statuses` is delegated straight to `stack.required_statuses` [3](#0-2) , and `Status::Group` computes `missing_contexts = required_statuses - visible_statuses.map(&:context)`, so a status whose `context` textually matches a required entry and whose state is `success` clears that specific gate. [4](#0-3) 

Because the SHA-only lookup has no repository/stack scoping, an attacker who owns/controls a repository sharing a SHA with a commit tracked by the victim's Shipit stack (achievable deterministically by forking the victim's public repo — forked history retains byte-identical, and thus SHA-identical, commits) can create a GitHub status on their own commit with `context` set to the victim's configured required check name and `state: success`. GitHub will deliver a genuinely-signed webhook (the attacker never needs Shipit's secrets — GitHub signs it), and `verify_signature` only checks that the signature matches the org-level `webhook_secret`, not that the payload's repository matches the commit being mutated. `drop_unhandled_event` and the `ExplicitParameters` schema on `StatusHandler` (`sha`, `state`, `context`, etc.) also do not check repository identity. [5](#0-4) 

### Impact Explanation
Any commit row across any Shipit-managed stack that shares a SHA with an attacker-controlled commit gets its status/required-check state overwritten with attacker-chosen content, including satisfying a specifically named merge/deploy gate (`required_statuses`) for a victim stack the attacker does not own or have any privilege on. This is a payload for one repository mutating another repository's `Commit`/`Stack` state, directly enabling downstream effects such as `deployable?` becoming true or a merge-gate check passing, which matches the "payload for one repository mutating another's stack, commit, task" / "unauthorized deploy, rollback or merge" Critical category. It is repeatable against any stack whose tracked commits share a SHA with a commit the attacker can drive a real GitHub status update for.

### Likelihood Explanation
Preconditions: the attacker needs a repository under an organization for which Shipit has GitHub App/webhook configuration (`Shipit.github(organization: repository_owner)` must resolve, i.e. not raise `GithubOrganizationUnknown`), and a commit SHA that collides with one tracked by the victim stack — trivially obtained by forking the victim's (often public) repository, since early/shared history retains identical SHA1s. The attacker only needs the ability to push/create a status via GitHub's normal API on their own repo — no Shipit session, API token, or secret is required, since GitHub itself signs the outbound webhook. This is low-cost and repeatable per targeted SHA/context pair.

### Recommendation
Scope the commit lookup in `StatusHandler#process` to the repository referenced in the payload, e.g. join through `Stack`'s `repository`/`github_repo_name` and filter `Commit.joins(:stack).where(sha: params.sha, shipit_stacks: { ... matching repository ... })`, rather than a bare `Commit.where(sha: params.sha)`. The same pattern should be audited for other webhook handlers (e.g. check-run handler) that resolve commits by SHA.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_cross_repo_test.rb
require 'test_helper'

module Shipit
  class StatusHandlerCrossRepoTest < ActiveSupport::TestCase
    test "a status for a SHA shared with another repo's stack satisfies that stack's required_statuses" do
      shared_sha = 'a' * 40

      victim_stack = shipit_stacks(:shipit)
      victim_stack.stub(:required_statuses, ['ci/tests']) do
        victim_commit = victim_stack.commits.create!(sha: shared_sha, message: 'victim commit')

        attacker_stack = shipit_stacks(:cascade) # different repo entirely
        attacker_stack.commits.create!(sha: shared_sha, message: 'attacker fork commit')

        # Binding under test:
        # context_string_authorized_by(victim_stack.required_statuses) == 'ci/tests'
        # context_string_supplied_by(attacker payload) == 'ci/tests'  <- attacker fully controls this
        payload = Shipit::Webhooks::Handlers::StatusHandler::Params.new(
          sha: shared_sha,
          state: 'success',
          context: 'ci/tests'
        )

        Shipit::Webhooks::Handlers::StatusHandler.new.call(payload.to_h)

        victim_commit.reload
        assert_equal 'success', victim_commit.status.state
        assert_empty victim_stack.required_statuses - victim_commit.status.statuses.map(&:context)
        # proves the victim's named required-status gate was satisfied by a status
        # the attacker generated on an unrelated commit sharing only the SHA.
      end
    end
  end
end
```

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L7-18)
```ruby
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
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

**File:** app/models/shipit/commit.rb (L57-58)
```ruby
    delegate :broadcast_update, :github_repo_name, :hidden_statuses, :required_statuses, :blocking_statuses,
             :soft_failing_statuses, to: :stack
```

**File:** app/models/shipit/status/group.rb (L24-31)
```ruby
      def initialize(commit, statuses)
        @commit = commit

        visible_statuses = reject_hidden(statuses.to_a.uniq(&:context))
        missing_contexts = required_statuses - visible_statuses.map(&:context)
        visible_statuses += missing_contexts.map { |c| Status::Missing.new(commit, c) }

        @statuses = visible_statuses.sort_by!(&:context)
```
