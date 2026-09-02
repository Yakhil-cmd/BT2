### Title
Cross-repository status forgery via unscoped `Commit.where(sha:)` lookup - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves the target commit by a bare SHA lookup across the entire `commits` table instead of scoping to the repository that authenticated the webhook, unlike other handlers that use the base `Handler#stacks` helper (which resolves via `Repository.from_github_repo_name(repository_name)`). Because git commit SHAs are content-addressed and identical across forks that share history, any GitHub user with a legitimately signed webhook for their own fork/repo can write a `ci/smoke` `failure` status onto a commit row belonging to a victim's stack, as long as that commit (a shared ancestor) already exists in the victim stack's `commits` table.

### Finding Description
The broken binding: the code assumes `Commit.where(sha: params.sha)` == "commits belonging to the repository that authenticated this webhook", but in reality `Commit.where(sha: params.sha)` == "all commits in the database with this SHA, across every repository/stack," because `sha` alone is not scoped to a repository in this query.

Path: `POST /webhooks` → `Shipit::WebhooksController#create` (`app/controllers/shipit/webhooks_controller.rb:10-15`) verifies the GitHub signature via `verify_signature`, which only checks that the payload was signed by the org/app configured for `repository_owner` [1](#0-0) . It does not restrict which repository's commits the handler is later allowed to mutate. The `status` event is then dispatched to `StatusHandler#process`:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [2](#0-1) 

This bypasses the repository-scoping mechanism that the base `Handler` class exposes for exactly this purpose:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end
``` [3](#0-2) 

Other handlers (`push_handler.rb`, `check_suite_handler.rb`, the `pull_request/*` handlers) use `stacks`/`repository_name` to constrain writes to the authenticated repository, confirming this is the intended invariant that `StatusHandler` fails to enforce.

Because commit SHA1s are content-addressed (they include ancestry, tree, author/committer, timestamps, message), a commit that is a shared ancestor between a victim's repo and any fork of it (including one the attacker owns) has an identical SHA in both. Once the victim stack has already ingested that commit into its `commits` table (normal history sync), the attacker can trigger a `status` webhook from their own, independently owned/forked repository with `context: ci/smoke`, `state: failure`, for that same shared SHA. `verify_signature` validates only that the payload is a genuine GitHub webhook for the attacker's own repository/org — it says nothing about which stack's commit rows may be updated. `StatusHandler#process` then finds and mutates the `Commit` row(s) with that SHA regardless of which stack/repository they belong to, via `commit.create_status_from_github!(params)` → `Shipit::Commit#create_status_from_github!` → `Shipit::Commit#add_status`, which recomputes `status`/`deployable?` and re-emits `deployable_status`/`commit_status` hooks and calls `stack.schedule_merges` [4](#0-3) [5](#0-4) .

If the victim stack is the production environment and requires `ci/smoke` as part of its required/blocking statuses, flipping that context to `failure` on a shared ancestor commit can flip `Commit#blocked?`/`deployable?` for downstream commits in that stack (via `stack.commits.reachable.newer_than(...).older_than(self).any?(&:blocking?)` [6](#0-5) ), forcing an unintended block of production deploys/merges — a write for a repository that did not authenticate it.

None of the listed guards prevent this: `verify_signature` authenticates the sender's own repo/org, not the target of the mutation; `drop_unhandled_event` and the `ExplicitParameters` schema only validate payload shape (`sha`, `state`, `context`, etc.), not repository ownership; there is no `require_permission!`/`stacks` scoping call inside `StatusHandler#process` at all.

### Impact Explanation
A payload authenticated for repository A can flip CI status on a `Commit` row that in fact belongs to stack/repository B's history, as long as A and B share that commit (fork relationship, common ancestor, or cherry-pick with identical metadata). This matches the "Critical — a payload for one repository mutating another's stack/commit" category: it can force a production stack to be blocked (denial of legitimate deploys) or, depending on which statuses are configured as required/blocking, unblock/allow deploys of commits the victim's CI never actually validated with a passing `ci/smoke`. The attack is repeatable against any stack that has ingested a commit shared with a repository the attacker controls (most straightforwardly, any fork of a public repo Shipit tracks).

### Likelihood Explanation
Preconditions: (1) the victim stack must already have the shared commit recorded in its `commits` table (true for any ancestor of a currently tracked branch — normal for active stacks); (2) the attacker needs a webhook that passes `verify_signature`, i.e., a repository under an organization/app that Shipit is configured to accept webhooks from, and the ability to make a genuine `status` event fire for that shared SHA (e.g., by forking the public repo and having their own CI/webhook forwarding post to the same Shipit `/webhooks` endpoint, or directly re-sending a GitHub-signed `status` payload they legitimately received). This is low-cost for anyone who can fork a public repo tracked by Shipit and is fully repeatable/scriptable.

### Recommendation
Scope the commit lookup in `StatusHandler#process` to the repository that authenticated the webhook, mirroring the base `Handler#stacks` helper, e.g.:
```ruby
def process
  Commit.where(sha: params.sha, stack: stacks).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
using `stacks` (derived from `repository_name`) instead of a bare, unscoped SHA match.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`, hypothetical since none currently enforces this invariant):
1. Create two `Shipit::Repository` records, `victim_repo` (`full_name: "acme/prod"`) and `attacker_repo` (`full_name: "attacker/fork"`).
2. Create `victim_stack` on `victim_repo` with `environment: "production"` and required status `ci/smoke`.
3. Create a `Commit` with `sha: "deadbeef..." `belonging to `victim_stack`, with no existing `ci/smoke` status (so `deployable?` is currently `true`/pending resolved as success).
4. Assert binding before: `Shipit::Commit.where(sha: "deadbeef...", stack: victim_stack).first.deployable?` == `true` (or whatever baseline state), while the payload's `repository.full_name` == `"attacker/fork"` != `victim_stack.repository.full_name` == `"acme/prod"`.
5. Call `Shipit::Webhooks::Handlers::StatusHandler.call({"sha" => "deadbeef...", "state" => "failure", "context" => "ci/smoke", "repository" => {"full_name" => "attacker/fork", ...}})`.
6. Assert after: the victim commit's status/`deployable?`/`blocked?` changed (e.g., now `false`), even though the payload's `repository.full_name` never matched `victim_stack`'s repository — proving the two named values (`payload.repository.full_name` vs `commit.stack.repository.full_name`) diverge while the write still succeeds.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
```ruby
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
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-34)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
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

**File:** app/models/shipit/commit.rb (L231-237)
```ruby
    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
    end
```

**File:** app/models/shipit/commit.rb (L366-386)
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
      new_status
    end
```
