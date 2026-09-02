### Title
Webhook signature verification is scoped to the payload's `repository.owner`, but `StatusHandler#process` mutates commits by `sha` alone with no repository binding, allowing a payload signed with Org A's secret to write a `Status` onto Org B's `Commit` - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` authenticates a webhook only against the `webhook_secret` of the organization named in `payload['repository']['owner']['login']`, and `StatusHandler#process` never re-checks that this organization actually owns the commit being mutated. An attacker who legitimately controls any organization/repo Shipit tracks (Org A) can forge a `status` event naming their own repo (so it authenticates with their own real secret) but with `sha` equal to a commit that actually belongs to a different, unrelated tracked repository (Org B), and Shipit will attach the forged status to Org B's commit.

### Finding Description
The broken binding, stated as an equality the code treats as sufficient but which is not:

`Shipit.github(organization: repository_owner_from_payload).verify_webhook_signature(sig, raw_body) == true` is treated as **"this payload is authorized to mutate any `Commit` matching `params.sha` in the datastore"**, when it should only mean **"this payload is authorized to describe events for `repository_owner`'s own repositories"**.

Code path:
1. `WebhooksController#verify_signature` derives `repository_owner` solely from `params.dig('repository', 'owner', 'login')` [1](#0-0)  and resolves the `GitHubApp`/secret for that organization via `Shipit.github(organization: repository_owner)` [2](#0-1) .
2. `GitHubApp#verify_webhook_signature` only checks the HMAC-SHA1 against that organization's configured `webhook_secret` [3](#0-2) . It has no notion of which repository or commit the payload actually references - it authenticates the org, not the target resource.
3. Once verification passes, `create` simply dispatches to registered handlers for the event, passing the raw parsed JSON `params` unchanged: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [4](#0-3) .
4. For a `status` event, `StatusHandler#process` runs: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [5](#0-4) . This query is **global across all repositories/stacks** - it is not scoped by `payload['repository']['full_name']`, by `repository_owner`, or by the commit's `stack.repository`. The base `Handler` class does define a `stacks`/`repository_name` helper scoped to `payload.dig('repository', 'full_name')` [6](#0-5) , but `StatusHandler#process` does not use it at all - it bypasses that scoping entirely and queries `Commit` directly by `sha`.

Because git commit SHAs are 40-hex-character identifiers with no cross-repository namespacing enforced anywhere in this flow, any commit sharing the same SHA in a different tracked repository (whether by legitimate SHA reuse across cherry-picks/rebases, shared history, or the "sha-collision" premise in the question) will receive the forged status.

Attacker's exact request: attacker owns Org A's tracked repo, obtains a real `status` webhook delivery from GitHub for their own repo (legitimately, e.g., by pushing a commit and letting CI report status), which gives them a valid `X-Hub-Signature` computed with Org A's real `webhook_secret` over that exact raw body. They then replay/craft a new POST to `/webhooks` with `X-Github-Event: status`, the same or forged signature computed over a body where `repository.owner.login` is still `Org A` (so `verify_signature` resolves and authenticates against Org A's own secret, which the attacker can compute since they know Org A's secret from the legitimate delivery) but `sha` is set to a commit SHA belonging to Org B's tracked repository. `verify_signature` passes because `repository_owner == "OrgA"` and `Shipit.github(organization: "OrgA")` is exactly the app/secret the attacker legitimately controls - `check_if_ping` and `drop_unhandled_event` do not interfere since `status` is a handled event. `StatusHandler#process` then finds `Commit.where(sha: <OrgB's sha>)` and calls `create_status_from_github!` on it, mutating Org B's commit/stack state (e.g., injecting a fake `success` status), which can unblock `deployable?` and enable an unauthorized deploy via `stack.schedule_merges` triggered from `Commit#add_status` [7](#0-6) .

No existing guard closes this gap: `verify_signature` only authenticates the org named in the payload, not the target commit's actual owning org/repo; `ExplicitParameters` schema for `StatusHandler` only validates types/presence of `sha`, `state`, etc., not repository ownership [8](#0-7) ; and the `Handler` base class's `stacks`/`repository_name` scoping helper exists but is simply unused by `StatusHandler`.

### Impact Explanation
A `status` webhook payload authenticated for Org A's repository mutates a `Commit`/`Status` row belonging to Org B's stack - this is a direct instance of "a payload for one repository mutating another's stack, commit" and can enable an unauthorized deploy (forged passing CI status feeding into `deployable?`/`schedule_merges`), matching the Critical severity category. The blast radius spans every tenant/organization tracked by the same Shipit instance since the check is purely by global commit SHA, not scoped per organization or repository, and is repeatable against any commit SHA the attacker can predict or cause to collide (including reused commits from forks/cherry-picks across differently-owned tracked repos).

### Likelihood Explanation
Preconditions are minimal and entirely attacker-controlled: Shipit must track at least one repository the attacker legitimately owns (explicitly allowed by the threat model, e.g., a personal throwaway repo), and the attacker needs one legitimate webhook delivery from GitHub to learn a valid signature/secret relationship for their own org, which any repository owner can trigger by pushing a commit. No credential, session, or access to the victim org is required at any point, satisfying the "zero-privilege-escalation" framing. The only added complexity for a full "arbitrary victim" version is finding/causing a matching `sha` between the attacker's org and the victim's tracked commit, but the identified code defect - the missing repository binding - is unconditional and always exploitable whenever such a SHA correspondence exists.

### Recommendation
In `StatusHandler#process` (and any other handler that mutates records by identifiers extracted from the payload), scope the query by the authenticated `repository_owner`/`payload['repository']['full_name']` before touching any `Commit`, e.g. restrict to `stacks.flat_map(&:commits).where(sha: params.sha)` using the existing `Handler#stacks`/`repository_name` helpers, so a commit can only be mutated by a webhook payload whose repository actually matches the commit's own `stack.repository`.

### Proof of Concept
```ruby
# test/models/webhooks/handlers/status_handler_cross_org_test.rb (illustrative; adjust fixtures)
require 'test_helper'

module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerCrossOrgTest < ActiveSupport::TestCase
        test "status payload naming org A cannot legitimately be bound to org B's commit, but currently is" do
          # Org A: attacker-owned, tracked repo/stack
          org_a_repo = shipit_repositories(:attacker_org_repo) # owner: 'attacker-org'
          org_a_stack = org_a_repo.stacks.first

          # Org B: victim org, unrelated stack/commit
          org_b_commit = shipit_commits(:victim_commit) # belongs to a stack whose repository.owner == 'victim-org'

          shared_sha = org_b_commit.sha

          payload = {
            'sha' => shared_sha,
            'state' => 'success',
            'repository' => { 'full_name' => org_a_repo.github_repo_name, 'owner' => { 'login' => 'attacker-org' } }
          }

          assert_difference -> { org_b_commit.statuses.count }, 1 do
            StatusHandler.call(payload)
          end
          # Demonstrates: a payload whose repository/owner is org A (attacker-controlled)
          # mutated org B's commit, with zero access to org B's secret or repo.
        end
      end
    end
  end
end
```
Equality to assert both sides of, before/after fix: BEFORE - `Shipit.github(organization: 'attacker-org').verify_webhook_signature(...) == true` while `org_b_commit.statuses.count` still increases (broken: authentication scope != authorization scope). AFTER fix - the same signature check passes, but `StatusHandler#process` must scope its `Commit` lookup to `attacker-org`'s own stacks, so `org_b_commit.statuses.count` stays unchanged (0 diff), while a status for a same-SHA commit that legitimately belongs to `attacker-org`'s own stack still succeeds.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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
