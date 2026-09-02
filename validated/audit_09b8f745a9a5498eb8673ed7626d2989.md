### Title
Cross-repository status forgery via unscoped SHA lookup in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` loads commits by bare SHA with no repository/stack scoping, unlike the base `Handler#stacks` helper which scopes by `repository_name`. A `status` webhook validly signed for one GitHub org/repo can therefore write a `Shipit::Status` row onto a `Commit` belonging to a completely different stack whenever that stack happens to contain a commit with the same SHA, letting an attacker flip `blocked?`/`deployable?` for a victim stack that has `blocking_statuses` configured.

### Finding Description
The invariant that should hold is: `status.repository_name == commit.stack.github_repo_name` for every `Shipit::Status` created from a webhook. This does not hold in the code.

`Shipit::WebhooksController#verify_signature` only checks that the payload is validly signed for the org identified by `params.dig('repository', 'owner', 'login')` [1](#0-0)  — it does not restrict which records the handler is allowed to mutate afterward.

The generic `Handler` base class provides a `stacks` helper that scopes lookups to the repository named in the payload: `Repository.from_github_repo_name(repository_name)&.stacks` [2](#0-1) . `StatusHandler#process`, however, ignores this helper entirely and queries commits globally by SHA:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [3](#0-2) 

Because `Commit` rows across all stacks/repositories share one table and are only distinguished by `sha` + `stack_id`, any commit — regardless of which repository it belongs to — whose `sha` matches `params.sha` gets a new `Status` record created via `create_status_from_github!` [4](#0-3) .

This status record then participates in `blocking?`/`required?` computation: `blocking? = !success? && commit.blocking_statuses.include?(context)` [5](#0-4) , and `Commit#blocked?` scans `stack.commits.reachable...any?(&:blocking?)` [6](#0-5) . `deployable?` in turn depends on `success? && !blocked?` [7](#0-6) . Forging a `success` status for `context: release/gate` on a commit shared with a victim stack that requires that gate can therefore clear a previously-blocking status and flip `blocked?`/`deployable?` for the victim stack, or (with `state: failure/error`) newly block it.

**Exploit flow:** An attacker who controls a repository where the Shipit GitHub App is installed (so GitHub signs webhooks for that org, satisfying `verify_signature`) sends a `status` event whose `sha` equals a commit SHA that also exists in a victim stack's `commits` table (git SHAs are shared verbatim between repositories that share history — forks, mirrors, cherry-picks, monorepo splits, etc.), with `context: release/gate`, `state: success`. `StatusHandler` writes this status onto every `Commit` row with that SHA across all stacks, including the victim's, altering `blocked?`/`deployable?` there.

Existing guards do not prevent this: `verify_signature` only authenticates *which org* sent the payload, not *which stack's records* the payload is permitted to modify; `drop_unhandled_event` and the `ExplicitParameters` schema only validate shape/presence of fields, not repository ownership; there is no `require_permission!`/`stacks` scoping call inside `StatusHandler#process`.

### Impact Explanation
A successfully forged `status` webhook writes a `Shipit::Status` row to a commit belonging to a stack the attacker never authenticated for, and can flip that victim stack's `blocked?`/`deployable?` state (unblocking or blocking a required `release/gate` check). This matches the Critical category "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy" — it is a cross-tenant state-manipulation bug and, on stacks that gate merges/deploys on `release/gate`, can force or prevent a ship. It is repeatable against any stack sharing a colliding commit SHA and requires no session, API token, or Shipit-side secret.

### Likelihood Explanation
Exploitation requires: (1) the attacker to control a repository with the Shipit GitHub App/webhook installed so a genuine, validly-signed `status` webhook can be emitted; and (2) a commit SHA collision between the attacker's repo and the victim stack's commit history. Condition (2) is the limiting factor — it is not a cryptographic SHA1 collision requirement in typical cases; it occurs naturally whenever repositories share git history (forks, mirrors, subtree/vendor syncs, monorepo splits) so is realistic in organizations running multiple Shipit-tracked stacks off related repositories. Given that precondition, the attack is trivial and repeatable (one webhook per forced flip) and requires no privileged Shipit role.

### Recommendation
Scope `StatusHandler#process` to the repository that authenticated the webhook, e.g. restrict to commits belonging to stacks returned by the base `Handler#stacks` helper (as other handlers do) before updating statuses, or filter `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`, rejecting/ignoring commits whose stack's `github_repo_name` doesn't match `repository_name` from the payload.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`):
1. Create two stacks, `stack_a` (attacker-controlled repo, e.g. `attacker/repo`) and `stack_v` (victim repo, e.g. `victim/repo`) with `stack_v.blocking_statuses = ['release/gate']`.
2. Create `commit_v` under `stack_v` with a known `sha` (e.g. `"a" * 40`) and an existing blocking status (`release/gate`, state `failure`) so `commit_v.blocked?` is `true` and `commit_v.deployable?` is `false`.
3. Create `commit_a` under `stack_a` with the identical `sha` value (simulating a shared commit) — no direct relationship to `stack_v` is declared anywhere in Shipit config.
4. Build a payload `{ repository: { full_name: 'attacker/repo', owner: { login: 'attacker' } } , sha: commit_a.sha, state: 'success', context: 'release/gate' }` and call `Shipit::Webhooks::Handlers::StatusHandler.call(payload)`.
5. Assert: `commit_v.reload.blocked?` changed from `true` to `false` (or `commit_v.status.success?`/`deployable?` changed), even though the payload's `repository.full_name` (`attacker/repo`) never matches `stack_v.github_repo_name` (`victim/repo`) — proving `Commit.where(sha:)` wrote a status onto a commit outside the authenticated repository.

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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/commit.rb (L231-237)
```ruby
    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
    end
```

**File:** app/models/shipit/status/common.rb (L46-48)
```ruby
      def blocking?
        !success? && commit.blocking_statuses.include?(context)
      end
```
