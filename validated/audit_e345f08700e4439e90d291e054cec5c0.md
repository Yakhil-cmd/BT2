### Title
Global `Commit.where(sha:)` lookup in `StatusHandler#process` lets a validly-signed webhook from one GitHub organization mutate `Commit`/`Status` rows belonging to another tenant's stack - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` looks up commits by raw `sha` across the entire `commits` table with no scoping to the repository/organization that authenticated the webhook, then calls `commit.create_status_from_github!(params)` on every match. Signature verification (`WebhooksController#verify_signature`) only proves the request was signed by the organization named in the *payload itself* (`repository.owner.login`), which is attacker-controlled data - it never checks that the sha belongs to that organization's repository.

### Finding Description
The claimed binding is: `verify_signature(sha) == "sha belongs to repository_owner"`. This is false. `verify_signature` in `app/controllers/shipit/webhooks_controller.rb:24-30` resolves `Shipit.github(organization: repository_owner)` where `repository_owner` is read straight from the untrusted payload (`app/controllers/shipit/webhooks_controller.rb:59-62`), and only checks the HMAC against that org's `webhook_secret`. It proves "this payload was signed by org X's webhook secret" - nothing about the `sha` field is validated against org X's actual repository/commit history.

`StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) then does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
```
This is a global, cross-stack, cross-tenant query with no `stack_id`/repository filter. Any `Commit` row in the whole instance whose `sha` column matches the attacker-supplied string gets its status mutated via `commit.create_status_from_github!` → `add_status` → `Hook.emit(:commit_status, ...)`/`Hook.emit(:deployable_status, ...)` and can trigger `stack.schedule_merges`, i.e. actual downstream effects like triggering continuous delivery on a victim stack (`app/models/shipit/commit.rb:281-287`, `365-386`).

Exploit precondition: the attacker must control an org that Shipit trusts with a valid `webhook_secret` (i.e., they must operate/own a Shipit-tracked repository as a legitimate, unprivileged repo owner - this is within the described attacker capability: "push to a fork ... emit webhooks from a repository they own"). Git commit shas are content-addressed; a fork of a victim's public repo, or any repo sharing history/cherry-picked commits with the victim's tracked branch, will have `Commit` rows with **identical shas** to the victim's tracked commits once Shipit ingests them (via `Commit.from_github`, `app/models/shipit/commit.rb:105-125` which stores `sha: commit.sha` verbatim, with no per-stack sha collision guard). The attacker sends a `status` webhook for their own (correctly signed) repository, but sets `sha` to the shared/victim sha. `verify_signature` passes because the signature matches their own org's secret. `StatusHandler#process` then finds and mutates every `Commit` row across all stacks/orgs that happens to share that sha - including the victim's.

Existing guards do not stop this: `verify_signature` only authenticates the signer's identity, not the semantic content (`sha`) of the payload; `ExplicitParameters` schema only enforces `sha` is a `String`, not that it belongs to the authenticated repo; there is no `stack_id`/`repository` foreign-key check in `StatusHandler`'s query.

### Impact Explanation
An attacker who owns/operates any Shipit-tracked repository (a legitimate but unprivileged capability) can forge status mutations (`success`/`failure`/`pending`, arbitrary `description`, `target_url`, `context`) on `Commit` rows belonging to a different tenant's stack, as long as that stack has ingested a commit sharing the same sha (true for forks or cherry-picked/shared upstream history — common for public open-source projects). Because `create_status_from_github!` feeds `stack.schedule_merges` and continuous-delivery scheduling (`Commit#schedule_continuous_delivery`), this can cause an unauthorized deploy/merge decision on the victim stack driven entirely by attacker-controlled webhook content. This matches the Critical category: "a payload for one repository mutating another's stack, commit ... or an unauthorized deploy". It is repeatable against any repository sharing sha history with an attacker-controlled repo, i.e., realistically any fork relationship, which is extremely common in open source.

### Likelihood Explanation
Preconditions: attacker needs a repository (fork or their own repo sharing commit history with the target) registered with Shipit and a working `webhook_secret` for their own org - both attainable by an ordinary GitHub user given the described attacker capabilities. No GitHub App private key, no Shipit session, no victim secrets are required. The sha does not need to be guessed or collided - it is copied verbatim from the public commit history, which is trivially available. This makes the attack low-cost and highly repeatable.

### Recommendation
Scope the `StatusHandler` (and any other handler doing global `Commit.where(sha:)` lookups) to only commits belonging to stacks whose repository matches the payload's authenticated `repository.full_name`/`repository_owner`, e.g. join through `Stack` and filter by `repository_owner`/`repository_name` derived from the verified webhook context rather than blindly matching by sha alone.

### Proof of Concept
```ruby
# test/models/webhooks/status_handler_cross_tenant_test.rb
require "test_helper"

module Shipit
  class StatusHandlerCrossTenantTest < ActiveSupport::TestCase
    test "a validly-signed webhook from org A mutates org B's commit row when shas collide" do
      victim_stack = shipit_stacks(:shipit)          # belongs to org "B"
      victim_commit = victim_stack.commits.create!(sha: "a" * 40, message: "victim commit")

      attacker_stack = stacks(:cyclimse)             # belongs to attacker-controlled org "A"
      # Attacker's own repo happens to contain a commit with the identical sha
      # (e.g. via fork / shared history) - no collision, just copied sha.
      attacker_stack.commits.create!(sha: "a" * 40, message: "same sha, different repo")

      payload = {
        "sha" => "a" * 40,
        "state" => "success",
        "context" => "ci/attacker",
        "repository" => { "owner" => { "login" => attacker_stack.repository.owner } }
      }

      # signed with org A's *own* legitimate webhook secret
      signature = "sha1=" + OpenSSL::HMAC.hexdigest(
        "sha1", Shipit.github(organization: attacker_stack.repository.owner).send(:webhook_secret),
        payload.to_json
      )

      post shipit.hooks_path,
        params: payload.to_json,
        headers: { "X-Github-Event" => "status", "X-Hub-Signature" => signature,
                   "Content-Type" => "application/json" }

      assert_response :ok

      victim_commit.reload
      # BEFORE: victim_commit.status should remain unaffected by org A's webhook
      # AFTER (bug): it is mutated by a webhook that only authenticated org A
      assert_equal "success", victim_commit.status.state,
        "org B's commit was mutated by a webhook that only authenticated org A"
    end
  end
end
```
This demonstrates the equality `verify_signature(payload) == "sha in payload belongs to signer's repository"` is false: the signature check passes for org A, but the mutated `Commit` row belongs to org B's stack.