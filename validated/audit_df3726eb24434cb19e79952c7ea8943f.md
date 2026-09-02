### Title
Cross-repository status write via unscoped `Commit.where(sha:)` in `StatusHandler#process` amplified by `blocking_statuses` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits purely by bare SHA with no repository/stack scoping, unlike sibling handlers such as `CheckSuiteHandler` which explicitly scope via `stacks.where(...)`. Any authenticated status webhook (i.e., one that passes `verify_signature` for *some* organization known to Shipit) is applied to every `Commit` record across the entire installation that happens to share that SHA, regardless of which repository actually generated the event, which — combined with a victim stack's `blocking_statuses` configuration — can flip `blocked?`/`deployable?` for a stack the attacker never authenticated for.

### Finding Description
The broken invariant, stated as an equality that should hold but doesn't:
`commit.stack.repository.full_name == payload.dig('repository', 'full_name')` for every `Commit` mutated by a `status` event — this is enforced for `check_suite` (`CheckSuiteHandler#process` at `app/models/shipit/webhooks/handlers/check_suite_handler.rb:14` uses `stacks.where(branch: ...)` derived from `Repository.from_github_repo_name(repository_name)`, see `Handler#stacks`/`Handler#repository_name` at `app/models/shipit/webhooks/handlers/handler.rb:32-38`), but is **not** enforced for `status`.

`StatusHandler#process` is:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [1](#0-0) 

It never calls the inherited `stacks` helper (`app/models/shipit/webhooks/handlers/handler.rb:32-38`) that other handlers use to constrain lookups to the repository named in the payload. It queries `Commit` (a global table shared by all stacks/repositories) by bare `sha` alone.

`WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) only proves that the payload's `X-Hub-Signature` matches the GitHub App/secret registered for `repository_owner` (the organization named in the payload) — it proves *an* organization authenticated the event, not that the SHA belongs to that organization's repository. Once past that gate, `StatusHandler#process` fans the write out to every stack in the system with a matching SHA.

Exploit flow: an attacker who owns or can push to any repository that shares git ancestry with a victim's tracked repository (the canonical case being a fork of the victim repository, where pre-fork commits retain identical SHA1 values) can set an arbitrary commit status (`context: "ci/integration"`, any `state`) on one of those shared-ancestry SHAs via the normal GitHub status API on their own repo. If that repo is covered by the same Shipit GitHub App/organization installation, GitHub signs and forwards the webhook normally — `verify_signature` passes because the signature is valid for that organization. `StatusHandler#process` then matches the SHA against `Commit.where(sha: ...)` and writes/updates a `Status` row on the commit as it exists in the **victim's** stack, because `Commit.sha` is the only match key.

Downstream this feeds `Commit#blocked?` (`app/models/shipit/commit.rb:231-237`), which is used by `deployable?` (`app/models/shipit/commit.rb:227-229`) and gates continuous delivery (`schedule_continuous_delivery`, `app/models/shipit/commit.rb:281-287`) whenever the victim stack has `blocking_statuses` configured to react to a context such as `ci/integration`. An attacker-forced `success` status can clear a block and trigger a deploy; an attacker-forced `failure`/`error`/`pending` status can force a block on an otherwise-shippable commit.

None of the existing guards catch this: `verify_signature` authenticates the *organization*, not the SHA-to-repository binding; `ExplicitParameters` (`params do ... end` in `StatusHandler`) only validates the shape of the payload, not repository ownership; `drop_unhandled_event` only checks the event type is registered; there is no `Repository` format validator or `stacks` scoping applied in this handler at all.

### Impact Explanation
A payload authenticated for one repository (or an attacker-controlled fork sharing that org's app installation) mutates `Status`/commit state belonging to a different repository's stack — this is the "payload for one repository mutating another's stack/commit" category, rated Critical. Concretely: the attacker can force or clear `blocked?` on arbitrary commits in a victim stack, which (with `continuous_deployment` and `blocking_statuses` configured) can cause an unauthorized deploy or an unwarranted block of a legitimate deploy. The attack is repeatable against any commit SHA shared between an attacker-controlled repo and any Shipit-tracked stack in the same GitHub App/organization scope, giving broad blast radius across all stacks under that installation.

### Likelihood Explanation
Preconditions: (1) the attacker needs a repository under the same GitHub organization/App installation Shipit trusts (e.g., a fork of the victim repo living in the org, or any repo the org's App is installed on) so `verify_signature` succeeds; (2) the attacker needs a commit SHA that is simultaneously present as a `Commit` row in the victim's Shipit-tracked stack — trivially achievable via forking, since forks retain identical SHA1s for shared history, not requiring any hash-collision effort; (3) the victim stack must have `blocking_statuses` configured for the forged context to have gating effect (per the question's premise). Attacker cost is low: pushing a status via the GitHub API to a repo they already have write access to. This is realistically repeatable, not a one-off theoretical collision.

### Recommendation
Scope `StatusHandler#process` the same way `CheckSuiteHandler` does: resolve the repository from `payload.dig('repository', 'full_name')` via `Repository.from_github_repo_name`, restrict to that repository's `stacks`, and only update `Commit` rows belonging to those stacks' `commits` association instead of a bare `Commit.where(sha:)` global lookup, e.g.:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`, or extending `test/controllers/webhooks_controller_test.rb`):
1. Create two stacks/repositories: `victim/repo` (with `blocking_statuses` configured to require context `ci/integration`) and `attacker/repo`.
2. Create a `Commit` with the same `sha` value in **both** stacks (simulating shared fork ancestry) — `victim_commit = victim_stack.commits.create!(sha: shared_sha, ...)` and `attacker_commit = attacker_stack.commits.create!(sha: shared_sha, ...)`.
3. Assert baseline: `refute victim_commit.blocked?` (or whatever pre-state) — i.e. `victim_commit.blocking? == false` before any status exists for `ci/integration`.
4. Stub `verify_signature` to simulate a legitimately signed webhook for `attacker/repo` (as existing tests do: `GithubHook.any_instance.stubs(:verify_signature).returns(true)`), then POST to `/webhooks` with `X-Github-Event: status` and a payload whose `repository.full_name == "attacker/repo"`, `sha: shared_sha`, `context: "ci/integration"`, `state: "failure"`.
5. Assert the equality that should have held but didn't: `victim_commit.reload.statuses.count` increased and `victim_commit.reload.blocked?` (or `blocking?`) is now `true`/changed, even though the payload's `repository.full_name` was `attacker/repo`, not `victim/repo`. This demonstrates `Commit.where(sha:)` in `StatusHandler#process` wrote a `Status` onto the victim's commit despite the webhook only authenticating `attacker/repo`.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
