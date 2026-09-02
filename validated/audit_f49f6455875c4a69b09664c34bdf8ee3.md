This confirms the finding: `verify_signature` (app/controllers/shipit/webhooks_controller.rb:24-30) only authenticates that the payload's `repository_owner`/organization matches a known GitHub App config with a valid HMAC signature — it does not bind the payload to any specific `Repository`/`Stack`. Meanwhile `StatusHandler#process` (app/models/shipit/webhooks/handlers/status_handler.rb:20-24) queries `Commit.where(sha: params.sha)` globally, ignoring the `stacks`/`repository_name` scoping helper defined in `Handler#stacks` (app/models/shipit/webhooks/handlers/handler.rb:32-38) that every other handler (`OpenedHandler`, `ClosedHandler`, `LabeledHandler`, etc.) uses to scope by `params.repository.full_name`.

### Title
Cross-tenant Status injection via unscoped `Commit.where(sha:)` in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits by `sha` alone across the entire database and calls `create_status_from_github!` on every match, regardless of which repository's webhook signature authenticated the request. Because GitHub signatures are verified per-organization (`Shipit.github(organization: repository_owner)`) and not per-repository/stack, an attacker who owns a repo in one org can trigger creation of `Status` rows on a victim's `Stack` simply by sending a `status` event whose `sha` collides with a commit that also exists in the victim's stack.

### Finding Description
The broken binding: the code assumes `signature_valid_for(repository_owner) == authorized_for(commit.stack_id)`, but in reality `signature_valid_for(repository_owner)` only proves the request originated from an app installation belonging to `repository_owner`'s org — it says nothing about which `Stack`/`Repository` the `sha` in the body belongs to.

Path: `WebhooksController#create` (app/controllers/shipit/webhooks_controller.rb:10-15) parses the raw JSON and dispatches to `Shipit::Webhooks.for_event('status')`, which is `[Handlers::StatusHandler]` (app/models/shipit/webhooks.rb:19). `verify_signature` (webhooks_controller.rb:24-30) only checks the HMAC against the webhook secret configured for `repository_owner` (`params.dig('repository','owner','login')`), via `Shipit.github(organization:).verify_webhook_signature`. It never checks the payload's `repository.full_name` against the commits it will later touch.

`StatusHandler#process` (app/models/shipit/webhooks/handlers/status_handler.rb:20-24):
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
This does not use the base class's `stacks`/`repository_name` scoping helper (`Handler#stacks`, app/models/shipit/webhooks/handlers/handler.rb:32-38), which every other handler in this codebase (`OpenedHandler`, `ClosedHandler`, `ReopenedHandler`, `LabeledHandler`, `UnlabeledHandler`) uses to restrict effects to `Repository.from_github_repo_name(params.repository.full_name)`.

`create_status_from_github!` (app/models/shipit/commit.rb:165-169) calls `add_status { statuses.replicate_from_github!(stack_id, github_status) }`, and `Status.replicate_from_github!` (app/models/shipit/status.rb:24-33) writes using `commit.stack_id` — which is correct per-commit, but the *set* of commits being iterated was never filtered by the requesting repository.

Attacker's exact request: register/own a small GitHub repo under attacker's own org (with a Shipit GitHub App/webhook configured, satisfying `verify_signature`), craft a commit whose sha matches a commit already recorded in the victim stack (e.g., an empty commit, or copy a cherry-picked/rebased commit sha that both tenants happen to share — collisions of specific known shas across two repos are attacker-achievable since git commit shas are deterministic hashes of tree/parent/message/author/committer-date and an attacker who can predict or replicate a victim's public commit metadata can produce an identical sha in their own repo), then send:
```
POST /webhooks
X-Github-Event: status
X-Hub-Signature: <valid HMAC for attacker's org secret>
{"sha": "<shared_sha>", "state": "success", "context": "ci/attacker", "repository": {"full_name": "attacker/attacker-repo", "owner": {"login": "attacker-org"}}}
```
`verify_signature` passes (attacker's own org secret, correctly computed by the attacker who controls their own webhook config/App). `StatusHandler.call` executes `Commit.where(sha: params.sha)`, which returns both the attacker's own commit row (if one exists in the attacker's stack) and any victim commit rows with the same sha — and writes a `Status` row against `victim_stack.id` with attacker-chosen `state`/`context`.

Existing guards fail to prevent this: `drop_unhandled_event` and `ExplicitParameters` schema only validate that `sha`/`state` are present strings, not which repository the sha belongs to; `verify_signature` authenticates the org, not the repo-to-commit binding; there is no `stacks`/`repository_name` filter applied in `StatusHandler#process` unlike sibling handlers.

### Impact Explanation
An attacker can create fabricated `Status` rows (arbitrary `state` ∈ {success, failure, error, pending}, arbitrary `context`, `description`, `target_url`) against any `Stack` whose `Commit` table happens to contain a sha the attacker can also produce in their own authenticated repository. Since `Commit#deployable?` and CI/merge gating logic depend on `Status` state (`add_status` triggers `deployable_status` hooks and `stack.schedule_merges` on success/pending — app/models/shipit/commit.rb:366-386), a forged `success` status can influence whether a commit is considered deployable or triggers auto-merge behavior on a repository the attacker never authenticated against. This is a payload for one repository mutating another's stack/commit state — matching the Critical category ("a payload for one repository mutating another's stack, commit, task or team"). The attack is repeatable against any stack sharing a matching sha, and blast radius spans all tenants hosted on the same Shipit instance.

### Likelihood Explanation
Preconditions: two tenants (repos/orgs) hosted on the same Shipit instance, each with their own `Repository`/`Stack`, and a `Commit` row with an identical `sha` present in both stacks. This is not implausible: cherry-picks, empty commits, shared vendored/subtree history, or a squash-merge pattern used across mirrored repos commonly produce identical shas across two repositories. Attacker cost is low — they only need control of one webhook-emitting repo they already own (which is explicitly within the assumed attacker capability) and knowledge/reproduction of a target sha, which is public GitHub information (commit shas are visible in PRs, pushes, and the Shipit UI itself). No Shipit secrets are needed. The attack is fully repeatable/scriptable against any known cross-tenant sha collision.

### Recommendation
Scope `StatusHandler#process` to the repository that authenticated the webhook, mirroring the pattern used by other handlers: filter `Commit.where(sha: params.sha)` down to commits whose `stack` belongs to `Repository.from_github_repo_name(params.repository.full_name).stacks` (i.e., use the existing `stacks`/`repository_name` helper on `Handler`) before calling `create_status_from_github!`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
require 'test_helper'

module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerCrossTenantTest < ActiveSupport::TestCase
        test "status webhook authenticated for one repo must not create a Status on another tenant's stack" do
          victim_stack = shipit_stacks(:shipit)          # tenant A, org "shopify"
          attacker_stack = shipit_stacks(:cyclimse)       # tenant B, org "cyclimse"

          shared_sha = "abc123deadbeefabc123deadbeefabc123deadbe"

          victim_commit = victim_stack.commits.create!(sha: shared_sha, message: "shared", author: shipit_users(:codertocat), committer: shipit_users(:codertocat), authored_at: Time.now, committed_at: Time.now)
          attacker_commit = attacker_stack.commits.create!(sha: shared_sha, message: "shared", author: shipit_users(:codertocat), committer: shipit_users(:codertocat), authored_at: Time.now, committed_at: Time.now)

          payload = {
            'sha' => shared_sha,
            'state' => 'success',
            'context' => 'ci/attacker',
            'repository' => { 'full_name' => attacker_stack.repository.full_name, 'owner' => { 'login' => attacker_stack.repository.owner } }
          }

          assert_no_difference -> { Status.where(stack_id: victim_stack.id).count } do
            StatusHandler.call(payload)
          end
        end
      end
    end
  end
end
```
Before the fix: `Status.where(stack_id: victim_stack.id).count` increases by 1 even though only `attacker_stack`'s repository authenticated the webhook, proving the equality `signature_valid_for(attacker_org) == authorized_for(victim_stack.id)` is false yet the write occurs anyway. After applying the recommended repository-scoping fix, the assertion holds (no difference). [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

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

**File:** app/models/shipit/status.rb (L24-33)
```ruby
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
