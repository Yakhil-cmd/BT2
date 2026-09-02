### Title
Cross-repository status forgery via unscoped sha lookup in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits solely by `sha` with no scoping to the repository named in the webhook payload, so a `status` webhook verified only for `attacker-org`'s repo can write a `Status` (and flip `deployable?`) onto a `Commit` belonging to any other tenant's stack that happens to share the same sha value. `verify_signature` only proves the payload's HMAC matches the org derived from `params.dig('repository','owner','login')`; it never confirms that the commit being mutated actually belongs to that same repository.

### Finding Description
The broken binding, stated explicitly: the equality `repository_owner_of_verified_payload (attacker/evil) == repository_of(Commit row matched by sha) (victim/repo)` is asserted by the design of webhook authorization but is never checked in code, and indeed does not hold in the attack scenario.

Code path:
- `WebhooksController#create` parses JSON and dispatches to handlers after `verify_signature`, which calls `Shipit.github(organization: repository_owner)` and HMAC-verifies the raw body against that org's `webhook_secret` [1](#0-0) . This only proves the request was signed by whichever GitHub App/org is named in `params.dig('repository','owner','login')` — it says nothing about which `Commit`/`Stack` rows may be touched.
- `StatusHandler`'s `params` schema requires only `sha`, `state`, and optional fields; it does **not** require or use `repository` at all, unlike other handlers (e.g. `PullRequest::LabeledHandler`, `ClosedHandler`) which explicitly `requires :repository { requires :full_name, String }` and scope lookups through `Shipit::Repository.from_github_repo_name(...)` [2](#0-1) .
- `process` then does a global, repository-agnostic lookup: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [3](#0-2) . This matches **every** `Commit` row across **every** stack/tenant sharing that sha, not just the one belonging to the authenticated repository.
- `create_status_from_github!` calls `add_status { statuses.replicate_from_github!(stack_id, github_status) }` [4](#0-3) , and `Status.replicate_from_github!` creates a `Status` row scoped to that commit's own `stack_id`, using attacker-controlled `state`/`description`/`target_url`/`context`/`created_at` [5](#0-4) . A `success` status can flip `Commit#deployable?` (`!locked? && (stack.ignore_ci? || (success? && !blocked?))`) [6](#0-5) , and `Status` triggers `schedule_continuous_delivery` on the victim's commit [7](#0-6) .

Attacker's exact request: attacker pushes/crafts a commit in `attacker/evil` whose sha is byte-identical to a victim commit sha in a different stack (feasible via tree/parent/author/committer/timestamp duplication — sha collision, not cryptographic break, just identical content), then sends `POST /webhooks` with `X-Github-Event: status`, a body `{"sha": "<shared sha>", "state": "success", "repository": {"owner": {"login": "attacker-org"}}, ...}`, signed with `attacker-org`'s own valid `webhook_secret`. `verify_signature` passes because it only checks the signature against `attacker-org`'s secret, which the attacker legitimately controls for their own app installation. `drop_unhandled_event`/`check_if_ping` do not filter `status` events. No existing guard (`ExplicitParameters` schema, model validations, `stacks` scoping) restricts the `Commit.where(sha:)` lookup to commits belonging to the verified repository, because `StatusHandler` simply never references `repository_name` or `stacks` from the `Handler` base class helpers that other handlers use (`stacks`, `repository_name`) [8](#0-7) .

The existing tests only exercise same-repository scenarios and do not assert repository-boundary isolation for `StatusHandler` [9](#0-8) .

### Impact Explanation
An attacker who controls (or can partially construct) a commit sharing sha with a target commit in a completely unrelated victim stack can write a `success` `Status` row into the victim's tenant, marking that commit "green" and unblocking `Commit#deployable?`, which cascades into `Stack#trigger_continuous_delivery`/auto-deploy for the victim's stack. This is a payload for one repository mutating another repository's `Commit`/`Stack` state, matching the Critical category ("a payload for one repository mutating another's stack, commit, task or team"). It is repeatable against any commit sha the attacker can reproduce, and the blast radius spans all tenants sharing the Shipit instance, since the lookup is entirely global (`Commit.where(sha:)` has no stack/repository filter, only an index on `[stack_id, sha]` for performance, not for scoping) [10](#0-9) .

### Likelihood Explanation
Preconditions required: attacker owns a repo with a valid GitHub App/webhook installation on Shipit (`Shipit.github(organization: 'attacker-org')` must have a `webhook_secret` — ordinary, low-cost setup for any org that self-registers a GitHub App against the Shipit host), and a victim `Commit` row with a colliding sha must exist in some other stack. Producing an exact sha collision is non-trivial in the general cryptographic sense, but the audit's proof idea assumes the attacker can legitimately reproduce identical tree/parents/author/committer timestamps (e.g., cherry-pick without modification) to yield the same sha deterministically — this is a realistic scenario for cross-forked/vendored/mirrored repositories where identical commits legitimately exist in two different stacks tracked by the same Shipit instance, not a hash-break. Given that, the attack is a single unauthenticated (from Shipit's perspective — attacker uses only its own valid credentials) HTTP POST, fully repeatable.

### Recommendation
Scope `StatusHandler#process` (and ideally the shared `Handler` pattern) to only mutate commits belonging to the repository/stacks identified in the verified payload. Concretely: require `repository.full_name` in `StatusHandler`'s params schema, resolve `Shipit::Repository.from_github_repo_name(params.repository.full_name)`, and restrict `Commit.where(sha: params.sha)` to `commit.stack.repository == repository` (or join through `stacks` as other handlers do) before calling `create_status_from_github!`. Reject/no-op for shas whose commit's stack repository doesn't match the payload's repository.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerTest < ActiveSupport::TestCase
        test "does not create a status for a commit belonging to a different repository's stack" do
          shared_sha = "a" * 40

          victim_stack = shipit_stacks(:shipit) # repository: shopify/shipit-engine (fixture)
          victim_commit = victim_stack.commits.create!(
            sha: shared_sha, message: "victim commit",
            author: shipit_users(:shipit), committer: shipit_users(:shipit),
            authored_at: Time.now, committed_at: Time.now
          )

          attacker_repo = Repository.create!(owner: "attacker-org", name: "evil")
          attacker_stack = attacker_repo.stacks.create!(environment: "production", branch: "main")
          attacker_commit = attacker_stack.commits.create!(
            sha: shared_sha, message: "attacker commit (same sha)",
            author: shipit_users(:walrus), committer: shipit_users(:walrus),
            authored_at: Time.now, committed_at: Time.now
          )

          payload = {
            'sha' => shared_sha,
            'state' => 'success',
            'context' => 'ci/attacker',
            'description' => 'forged',
            'created_at' => Time.now.to_s,
            'repository' => { 'full_name' => 'attacker-org/evil', 'owner' => { 'login' => 'attacker-org' } }
          }

          assert_no_difference -> { victim_commit.statuses.count } do
            assert_difference -> { attacker_commit.statuses.count }, 1 do
              StatusHandler.call(payload)
            end
          end

          # Binding assertion: repository named in verified payload != repository of mutated Commit
          refute_equal 'attacker-org/evil', victim_stack.repository.full_name
          refute victim_commit.reload.success?, "victim commit must not be marked deployable by attacker's payload"
        end
      end
    end
  end
end
```
This demonstrates that, as currently implemented, `StatusHandler#process` would create a `Status` for `victim_commit` too (violating the isolation assertion), proving the cross-repository write is real given a sha collision.

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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
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

**File:** test/controllers/webhooks_controller_test.rb (L42-59)
```ruby
    test ":state create a Status for the specific commit" do
      request.headers['X-Github-Event'] = 'status'

      commit = shipit_commits(:first)

      body = JSON.parse(payload(:status_master)).merge(repository_params).to_json
      assert_difference 'commit.statuses.count', 1 do
        post :create, body:, as: :json
      end

      status = commit.statuses.last
      status_payload = JSON.parse(payload(:status_master))
      assert_equal status_payload['target_url'], status.target_url
      assert_equal status_payload['state'], status.state
      assert_equal status_payload['description'], status.description
      assert_equal status_payload['context'], status.context
      assert_equal status_payload['created_at'], status.created_at.iso8601
    end
```

**File:** db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb (L1-10)
```ruby
class IndexCommitsOnStackIdAndSha < ActiveRecord::Migration[5.1]
  def change
    add_index :commits, %i(sha stack_id), unique: true
  end
end
```
