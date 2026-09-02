### Title
Cross-repository status injection via unscoped `Commit.where(sha:)` lookup - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits globally by `sha` and never consults `params.repository.full_name` or the base class's `stacks`/`repository_name` helpers, unlike every other state-mutating webhook handler (`PushHandler`, `CheckSuiteHandler`, `PullRequest::OpenedHandler`, `ClosedHandler`, `ReopenedHandler`, `LabeledHandler`, `UnlabeledHandler`), which all resolve `Repository.from_github_repo_name(repository payload)` before touching any record. This lets a webhook whose `repository.full_name` names an attacker-controlled repo write a `Status` onto a commit belonging to a completely different (victim) stack, as long as the two repos share a commit `sha`.

### Finding Description
The binding that should hold, and holds everywhere else: `repository_name_in_payload == repository_owning_the_mutated_record`. The base class enforces this via `Handler#stacks`, which resolves `Repository.from_github_repo_name(repository_name)` and scopes to that repository's stacks [1](#0-0) . `PushHandler#process` uses `stacks.not_archived.where(branch:)` [2](#0-1) , `CheckSuiteHandler#process` uses `stacks.where(branch:)` [3](#0-2) , and every `PullRequest::*Handler` explicitly resolves `repository` from `params.repository.full_name` before scoping queries (e.g. `OpenedHandler#repository`) [4](#0-3) .

`StatusHandler#process`, by contrast, does:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [5](#0-4) 

This query is unscoped by any repository/stack — `params.sha` alone selects every `Commit` row across the entire Shipit instance that happens to have that sha, regardless of which repository's stack it belongs to. `StatusHandler` never calls `stacks` or `repository_name` and never invokes `Repository.from_github_repo_name`, even though its `params` schema doesn't even require a `repository` block [6](#0-5) .

Exploit flow: an attacker owns/controls a repository whose GitHub App installation shares the same `webhook_secret` as the victim's organization (e.g. a fork residing in the same GitHub org/installation as the victim repo, or any repo covered by the same app installation configured in Shipit). Because forks share git history, some commit `sha`s are identical between the attacker's repo and the victim's tracked repo/stack. The attacker uses the GitHub Commit Status API on their own repo (which they can legitimately call for any sha in their own repository's history, including inherited ancestor commits) to set an arbitrary state/description/target_url for that shared sha. GitHub signs and delivers the resulting `status` webhook with a valid signature (computed from the shared app's `webhook_secret`, verified in `WebhooksController#verify_signature` using `Shipit.github(organization: repository_owner)` — but `repository_owner` is only used to select which HMAC secret to check against, not to constrain which commits get updated) [7](#0-6) . `StatusHandler` then finds *every* `Commit` row with that sha — including the one in the victim's stack — and calls `commit.create_status_from_github!(params)` on it, writing attacker-controlled state/description/context/target_url into the victim's commit status history, which can influence CI-gated deploy/merge decisions (`Status#enable_ci_on_stack`, `schedule_continuous_delivery` callbacks) [8](#0-7) .

Existing guards do not prevent this: `verify_signature` only checks that the payload was signed by the correct organization's app secret — it does not check that the named repository in the payload actually owns the affected commit [7](#0-6) . The `ExplicitParameters` schema for `StatusHandler` doesn't require or use a `repository` object at all [6](#0-5) , so there is no schema-level enforcement either.

### Impact Explanation
An attacker who controls (or has commit/status-setting rights on) a repository covered by the same GitHub App installation as a victim organization can inject a forged CI status onto a victim's tracked commit without ever authenticating against that victim's repository. This is a write to another repository's `Status`/`Commit` record driven purely by an attacker-supplied `sha` value, matching the Critical category "a payload for one repository mutating another's stack, commit, task or team." It is repeatable against any commit whose sha happens to be shared across repos under the same app installation (most reliably: forks/branches within the same org), and the blast radius spans every stack tracked by Shipit that shares history with the attacker's repo.

### Likelihood Explanation
Exploitation requires: (1) the attacker's repository be covered by the same GitHub App/organization webhook configuration as the victim (so the HMAC signature check passes) — commonly true for forks or sibling repos within one GitHub org/installation; (2) a shared commit sha between attacker's repo and the victim's tracked stack, which is trivially satisfiable via forking (shared ancestor commits) — no special Shipit or GitHub secret is needed by the attacker beyond normal push/fork/status-API access to their own repo. This is low-cost and repeatable on demand.

### Recommendation
In `StatusHandler#process`, scope the commit lookup to the repository named in the payload, mirroring the pattern used by every other handler, e.g. restrict to `stacks.joins(:commits).merge(Commit.where(sha: params.sha))` (or equivalently `Repository.from_github_repo_name(repository_name)&.stacks&.commits&.where(sha: params.sha)`), and require/validate the `repository.full_name` field in the params schema so the binding `repository_name_in_payload == repository_owning_commit` is enforced identically to `Handler#stacks`.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`, no live GitHub calls):
1. Create two stacks/repositories in fixtures: `stack_a` (victim, repository `victim/repo`) and `stack_b` (attacker, repository `attacker/repo`).
2. Create a `Commit` with `sha: 'deadbeef'` belonging to `stack_a` only (simulating a shared ancestor sha that also exists physically in attacker's git history but is *not* recorded as a commit under `stack_b` in Shipit's DB — or, to demonstrate the structural gap directly, create the identical sha under both stacks and show cross-repo write).
3. Stub `Shipit::Repository.from_github_repo_name` and assert it is `never` called by `StatusHandler`:
   ```ruby
   Shipit::Repository.expects(:from_github_repo_name).never
   Shipit::Webhooks::Handlers::StatusHandler.call(status_payload_naming("attacker/repo"))
   ```
   versus an equivalent test for `PullRequest::OpenedHandler` asserting `Shipit::Repository.expects(:from_github_repo_name).with("attacker/repo")`.
4. Assert that after calling `StatusHandler.call` with a payload where `repository.full_name == "attacker/repo"` and `sha == commit_in_stack_a.sha`, `commit_in_stack_a.statuses.count` increases by 1 — i.e. `stack_a` (never named in the payload) was mutated by a payload claiming to be from `attacker/repo`.
5. Contrast with `PullRequest::OpenedHandler`, where an equivalent payload naming `attacker/repo` cannot create/mutate any `ReviewStack` under `stack_a`'s repository, because `repository` is resolved via `Repository.from_github_repo_name(params.repository.full_name)` and scoped accordingly.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
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

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```
