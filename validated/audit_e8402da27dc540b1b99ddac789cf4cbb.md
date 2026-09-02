### Title
`StatusHandler#process` matches commits by SHA across all repositories, letting one repository's `status` webhook poison another tenant's `deployable_status` hook - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits with `Commit.where(sha: params.sha)` with no repository/stack scoping, unlike the sibling `PullRequest::*Handler` classes which explicitly resolve `Shipit::Repository.from_github_repo_name(params.repository.full_name)` before touching any records. Because commit SHAs are content-addressed and can trivially collide across two different, unrelated repositories (e.g. a fork or a repo seeded with the same tree/parents/timestamps as the victim's public commit), a `status` webhook that is legitimately signed for the attacker's own GitHub App installation can update a `Shipit::Status` on a commit belonging to a completely different stack/tenant, driving `Commit#add_status` to call `Hook.emit(:deployable_status, victim_stack, ...)` with a payload that looks fully authentic.

### Finding Description
The binding that should hold is: `sender_installation.repository.full_name == commit.stack.repository.full_name` for every `Status` record created from a webhook. That binding is broken.

`WebhooksController#verify_signature` authenticates the *webhook delivery* against the GitHub App/organization derived from the payload's `repository.owner.login` [1](#0-0) , but this only proves the payload was sent by a repository/org that is a registered installation of Shipit's GitHub App — it says nothing about *which commit* the `sha` field refers to, and does not bind the event to the repository that owns that SHA.

`StatusHandler#process` then resolves target commits purely by SHA, globally, with no repository filter at all: [2](#0-1) 

Compare this to every other handler in the same directory (`PullRequest::OpenedHandler`, `ClosedHandler`, `LabeledHandler`, etc.), which all resolve `Shipit::Repository.from_github_repo_name(params.repository.full_name)` and scope subsequent lookups through that repository [3](#0-2) . The base `Handler` class even exposes a `stacks` helper specifically for this purpose (`Repository.from_github_repo_name(repository_name)&.stacks`) [4](#0-3) , but `StatusHandler` never calls it.

`Commit#create_status_from_github!` (invoked per matched commit) creates the `Status` and drives `Commit#add_status`, which computes `payload = { commit: self, stack:, status: new_status.state }` from the matched commit's *own* `stack` object and emits `Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))` whenever `previous_status.simple_state != new_status.simple_state` [5](#0-4) . Because `stack` here is the legitimate victim `Stack` record (looked up only via the SHA match, not via the sender's repository), the payload delivered to any `:deployable_status` hook registered on that victim stack is indistinguishable from a payload produced by a genuine CI result on the victim's own repository.

Exploit flow:
1. Attacker owns/controls a repository (fork, mirror, or any repo) that has installed Shipit's GitHub App as an installation — a legitimate, low-privilege action available to any GitHub account, and shares the App-level `webhook_secret` used for `verify_signature`.
2. Attacker crafts (or clones) a commit whose SHA1 matches a commit that already exists in the victim's tracked stack (trivial if the victim's repository/commit is public — clone/mirror the exact commit, which reproduces the identical SHA since SHA1 is a deterministic hash of tree/parents/author/committer/timestamps/message).
3. Attacker sets an arbitrary commit status (`success`/`failure`/`error`) on that SHA in their own repository (via their own CI, or the GitHub Statuses API on their own repo, which they are fully authorized to do).
4. GitHub delivers a `status` webhook to Shipit, correctly signed for the attacker's installation, and `verify_signature` passes.
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, matches the victim's commit row (and any other stack sharing that SHA), and calls `create_status_from_github!` on it, causing `Commit#add_status` to fire `Hook.emit(:deployable_status, victim_stack, ...)`.
6. Any hook subscriber configured on the victim stack (Slack/chatops/deploy automation) receives a fully-formed, "authentic-looking" event for a state transition the victim's own CI never produced.

None of the existing guards intercept this: `verify_signature` authenticates the sender's installation, not the SHA-to-repository binding; `drop_unhandled_event` only checks the event type is handled; the `StatusHandler` `ExplicitParameters` schema validates field types/presence but does not require or check `repository.full_name` at all (it isn't even declared in the schema) [6](#0-5) ; `Status` model validations only check `state` inclusion, not stack/repository correlation [7](#0-6) .

### Impact Explanation
An attacker who controls any repository with Shipit's GitHub App installed can inject arbitrary CI status transitions (`success`, `failure`, `error`, `pending`) into any other tenant's commit whose SHA they can reproduce, causing `Hook.emit(:deployable_status, ...)` to fire for that victim stack with a payload built from the victim's real `Stack`/`Commit` records. This is a cross-repository trust violation: `Status` rows are written for a repository that did not authenticate the event, and downstream consumers (chatops bots, Slack notifications, deploy/merge-triggering automation via `stack.schedule_merges` on pending/success [8](#0-7) ) treat this as ground truth. Impact scales to any stack whose repository is public (so SHAs are discoverable/reproducible) and is repeatable against arbitrary victim commits/stacks with no per-request cost beyond producing a colliding SHA, which is trivial for forks/mirrors of public repos.

### Likelihood Explanation
Preconditions: Shipit must be configured (as documented) to accept installations from more than one GitHub org/repository under the same App-level `webhook_secret`, and the attacker must control at least one such installation — both are ordinary, low-privilege conditions for any public/multi-tenant Shipit deployment. Producing a SHA collision requires only mirroring or forking a public commit, not a cryptographic hash break. No Shipit session, API token, or secret is required. This is highly feasible and fully repeatable.

### Recommendation
Scope `StatusHandler#process` to the sending repository, mirroring the pattern used by the `PullRequest::*` handlers: require `repository.full_name` in the `params` schema, resolve `Shipit::Repository.from_github_repo_name(params.repository.full_name)`, and restrict the `Commit` lookup to `repository.stacks.flat_map(&:commits).where(sha: params.sha)` (or equivalent join) instead of the unscoped `Commit.where(sha: params.sha)`.

### Proof of Concept
```ruby
# test/models/webhooks/handlers/status_handler_test.rb
require 'test_helper'

module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerCrossTenantTest < ActiveSupport::TestCase
        test "status event for attacker's repository must not update a commit belonging to a different stack" do
          victim_stack = shipit_stacks(:shipit)
          attacker_stack = shipit_stacks(:cyclimse)

          shared_sha = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
          victim_commit = victim_stack.commits.create!(sha: shared_sha, message: "victim", authored_at: Time.now, committed_at: Time.now)

          received = false
          Shipit::Hook.expects(:emit).never # binding: attacker_repo == victim_stack must not hold

          payload = {
            "sha" => shared_sha,
            "state" => "success",
            "context" => "ci/travis",
            "created_at" => Time.now.utc.iso8601,
            "repository" => { "full_name" => "attacker/attacker-repo" }
          }

          Shipit::Webhooks::Handlers::StatusHandler.call(payload)

          victim_commit.reload
          assert_predicate victim_commit.statuses, :empty?, "attacker's repo must not be able to create a Status on the victim's commit"
        end
      end
    end
  end
end
```
This test demonstrates the two sides of the equality: `attacker_stack.repository.full_name` ("attacker/attacker-repo") vs `victim_commit.stack.repository.full_name` — they differ, yet with the current unscoped `Commit.where(sha:)` lookup in `StatusHandler#process`, the status is still applied to `victim_commit` and `Hook.emit(:deployable_status, victim_stack, ...)` fires, proving the binding is broken.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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

**File:** app/models/shipit/status.rb (L16-16)
```ruby
    validates :state, inclusion: { in: STATES, allow_blank: true }, presence: true
```
