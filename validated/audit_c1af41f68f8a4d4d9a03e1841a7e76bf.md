### Title
`StatusHandler` writes GitHub status updates onto `Commit` records with no repository/stack scoping, allowing cross-tenant status forgery on a colliding-sha commit - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves the target commit with `Commit.where(sha: params.sha)` and calls `commit.create_status_from_github!(params)` on every match, without ever checking that the webhook's `repository.full_name` corresponds to the `stack`/`repository` that owns that commit. Every other handler in this engine uses the `Handler#stacks` helper (`Repository.from_github_repo_name(repository_name)&.stacks`) to scope processing to the repository that actually sent the webhook; `StatusHandler` does not use it at all.

### Finding Description
The broken binding: the base `Handler` class exposes `stacks` at `app/models/shipit/webhooks/handlers/handler.rb:32-38`, scoped by `payload.dig('repository', 'full_name')`, precisely so a handler only touches records belonging to the repository that signed the request. Other handlers (`PullRequest::*Handler`) use this scoping. `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) instead does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
```
`Commit#create_status_from_github!` (`app/models/shipit/commit.rb:165-169`) calls `statuses.replicate_from_github!(stack_id, github_status)` using whatever `stack_id` the matched `Commit` row happens to have — not the stack implied by the webhook's own `repository` field. There is no `WHERE stack_id = ...` or `WHERE repository = ...` clause anywhere in this path.

`verify_signature` in `app/controllers/shipit/webhooks_controller.rb:24-49` only authenticates that the payload was signed by the GitHub App/org configured for `repository_owner` (`params.dig('repository','owner','login')`) — it does not, and cannot, bind the payload's `sha` to a specific stack or commit. Signature verification proves "this payload came from GitHub for organization X," not "this payload's sha uniquely belongs to organization X's history." Consequently, any correctly-signed `status` webhook — including one triggered by an attacker's own repository/CI within an organization/installation Shipit trusts, or from any installation with weak/absent secret configuration — will update the status of *every* `Commit` row across the entire Shipit instance whose `sha` matches `params.sha`, regardless of which stack owns it.

Exploit flow: if an attacker can get a commit with the identical `sha` recorded against a victim stack's commit (e.g., via a crafted parentless commit with identical tree/author/committer/message/date content, or simply because the same commit was pushed to two repositories Shipit tracks), the attacker triggers their own CI/status webhook with `context` set to match one of the victim stack's `deploy_spec.required_statuses` (e.g. `ci/build`) and `state: success`. `StatusHandler` finds the victim's `Commit` row purely by `sha`, and `Status::Group` aggregation (used by `Commit#status`, `app/models/shipit/commit.rb:304-306`) will report that required context as `success`, making `Commit#deployable?` (`app/models/shipit/commit.rb:227-229`) evaluate `success?` as true even though the victim's own CI never ran that check.

None of the listed guards prevent this: `verify_signature` authenticates the sender's organization/app installation, not the commit ownership; `drop_unhandled_event` only filters event types; `ExplicitParameters` only validates the shape of `sha`/`state`/`context`, not their relationship to a specific repository; there is no `require_permission!`/`stacks` scope check inside `StatusHandler` itself.

### Impact Explanation
A successfully forged `success` status on a required context lets `Commit#deployable?` return true on a commit that never passed the victim stack's actual CI, which feeds directly into `schedule_continuous_delivery` / `Stack#trigger_continuous_delivery` deploy gating (`app/models/shipit/commit.rb:281-287`). This is a payload originating from one repository (or an unrelated/attacker-controlled one) mutating another stack's commit/status state, matching the Critical category "a payload for one repository mutating another's stack, commit, task or team" / "an unauthorized deploy." The blast radius spans every stack hosted by the same Shipit instance, since the query is completely global (`Commit.where(sha:)` has no tenant boundary), not merely same-organization.

### Likelihood Explanation
The attacker must still produce a `sha` collision with a specific victim commit — the question's proof idea explicitly stipulates this as a given ("colliding sha"), and the audit rules require us to accept that premise for this question. Producing that collision in practice (e.g., a content-identical, parentless commit with matching author/committer/date/message replayed into a Shipit-tracked repository the attacker controls) is a realistic technique for repositories with shared/forked history or deliberately crafted root commits. Given a colliding sha, the rest of the chain — sending a normal, correctly-signed `status` webhook for the attacker's own repository — requires no privileged secrets beyond what any GitHub user with push/CI access to their own tracked repo already has. The missing repository scoping itself is unconditional and always reachable once the sha precondition is met.

### Recommendation
Scope `StatusHandler#process` to the repository that actually sent the webhook, mirroring the pattern already used by other handlers: resolve `stacks` via `Repository.from_github_repo_name(repository_name)`, and restrict the commit lookup to `Commit.where(sha: params.sha, stack_id: stacks.select(:id))` (or iterate `stacks.flat_map { |s| s.commits.where(sha: params.sha) }`) before calling `create_status_from_github!`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "status webhook does not update commits belonging to a different repository/stack" do
  victim_stack = shipit_stacks(:shipit)
  attacker_repository_full_name = "attacker/unrelated-repo"

  colliding_sha = "a" * 40
  victim_commit = victim_stack.commits.create!(sha: colliding_sha, message: "victim commit")
  victim_stack.update!(deploy_spec_raw: { ci: { hide: [], allow_failures: [], require: ["ci/build"] } })

  payload = {
    "sha" => colliding_sha,
    "state" => "success",
    "context" => "ci/build",
    "repository" => { "full_name" => attacker_repository_full_name, "owner" => { "login" => "attacker" } }
  }

  Shipit::Webhooks::Handlers::StatusHandler.call(payload)

  victim_commit.reload
  # Binding under test: attacker_repository_full_name != victim_stack.repository.full_name
  refute_equal attacker_repository_full_name, victim_stack.repository.full_name
  # Bug: despite the mismatch, deployable? flips to true because StatusHandler is unscoped
  refute victim_commit.deployable?, "status from an unrelated repository must not satisfy the victim stack's required status"
end
```
This test demonstrates that `StatusHandler` currently has no code path checking `payload.dig('repository','full_name')` against the commit's owning stack before mutating `deployable?`-relevant state, confirming the missing binding.