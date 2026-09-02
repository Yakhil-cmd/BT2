### Title
Cross-tenant Status webhook forgery via unscoped `Commit.where(sha:)` lookup — (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits solely by `sha`, with no filter on the repository that sent the webhook, then calls `Commit#create_status_from_github!` on every match. Because `Commit#deployable?` is driven by `success?`, which derives from the latest `Status` row [1](#0-0) , any authenticated GitHub repository can flip an arbitrary victim stack's commit from "no CI signal" to `deployable? == true` by sending a status webhook that happens to share the same commit `sha` (trivial for forked/mirrored commits, since git SHAs are content-addressed and identical across forks).

### Finding Description
The broken binding is: **the repository that authenticates a status webhook == the repository that owns the `Stack`/`Commit` the status is written to**. This equality is enforced by every other webhook handler through `Handler#stacks`, which resolves the target scope via `Repository.from_github_repo_name(repository_name)` before acting [2](#0-1) . `StatusHandler` does not use `stacks` at all:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [3](#0-2) 

This global `Commit.where(sha: ...)` scan is not filtered by `payload['repository']['full_name']`, so it matches every `Commit` row in the database with that SHA, regardless of which `Stack`/`Repository` it belongs to. Since git commit SHAs are computed from content only (not from the hosting repository), an attacker who forks or otherwise reproduces a victim's public commit can trivially obtain a repository containing a commit with an identical `sha`, register a valid GitHub webhook on their own repo (which they legitimately control), and send a `status` event with `state: success` and a `context` matching the victim stack's `ci.require`.

`Commit#create_status_from_github!` calls `add_status`, which persists the new `Status` and recomputes `status` via `Status::Group.compact` [4](#0-3) [5](#0-4) . Once this first-ever `Status` row exists, `success?` (delegated to `status`) becomes true, and `deployable?` flips from `false` to `true` purely because `stack.ignore_ci?` is now irrelevant — `success? && !blocked?` is satisfied [6](#0-5) . This can additionally trigger `schedule_continuous_delivery`, queuing a real deploy for the victim stack [7](#0-6) .

None of the standard guards catch this: `verify_signature`/`GitHubApp#verify_webhook_signature` only prove the request came from *a* registered GitHub App installation/repo (the attacker's own, which is legitimate), not that it came from the *victim's* repo. `ExplicitParameters` schema validation only checks payload shape (`sha`, `state`, `context`, etc.), not repository ownership. `drop_unhandled_event`, `force_github_authentication`, `User#authorized?`, and `require_permission!` are session/API-token controls irrelevant to inbound webhook processing. The divergence is entirely due to `StatusHandler` omitting the repository-scoping step every sibling handler performs via `stacks`.

### Impact Explanation
An attacker who controls any GitHub repository (fork or otherwise) can inject a `success` CI status onto a commit belonging to a stack they do not own and never authenticated against, as long as the commit `sha` collides (trivially achievable for shared/forked commits). This is a genuine cross-tenant write: a payload authenticated for repository A mutates repository/stack B's `Commit`/`Status` state, matching the Critical category "a payload for one repository mutating another's stack, commit, task or team." Downstream, this can make an otherwise-blocked commit `deployable?`, and combined with `continuous_deployment?`, can trigger an unauthorized deploy of the victim's stack. The attack is repeatable against any stack/commit pair where the attacker can reproduce or predict the SHA.

### Likelihood Explanation
Preconditions are modest: the victim commit must have zero (or non-conflicting) prior `Status` rows, and the attacker needs a repository under their control containing a commit with an identical SHA (trivial via forking public repos, since GitHub preserves SHAs across forks) with a working GitHub App/webhook installation on that repository — something any GitHub user can set up on their own repo. No Shipit secrets, session, or API token are required. This is a low-cost, repeatable attack limited only by the attacker's ability to know/predict a target commit's SHA and the CI `context` the victim stack expects.

### Recommendation
Scope `StatusHandler#process` (and any other sha-keyed handler) to the repository that sent the webhook, mirroring `Handler#stacks`: resolve `Repository.from_github_repo_name(repository_name)` first, then only update `Commit` rows belonging to that repository's stacks (e.g., `stacks.flat_map(&:commits).where(sha: params.sha)` or add an explicit `stack_id`/`repository` join condition to the `Commit.where(sha:)` query) before calling `create_status_from_github!`.

### Proof of Concept
Minitest plan (model-level, no live GitHub):
1. Create two `Stack`/`Repository` fixtures, `victim_repo` and `attacker_repo`.
2. Create `victim_commit = Commit.create!(stack: victim_stack, sha: 'deadbeef...')` with no `Status` rows; assert `victim_commit.statuses.empty?` and `victim_commit.deployable? == false`.
3. Create `attacker_commit = Commit.create!(stack: attacker_stack, sha: 'deadbeef...')` (same sha, different stack/repository).
4. Build a `StatusHandler` payload with `repository.full_name = attacker_repo.full_name`, `sha: 'deadbeef...'`, `state: 'success'`, `context` matching victim stack's `ci.require`.
5. Invoke `Shipit::Webhooks::Handlers::StatusHandler.call(payload)`.
6. Assert `victim_commit.reload.deployable? == true` even though the webhook's `repository` was `attacker_repo`, proving the write crossed tenant boundaries — i.e., assert the binding `payload['repository']['full_name'] == victim_stack.repository.full_name` is false, yet `victim_commit.status.success?` becomes true anyway.

### Citations

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L219-229)
```ruby
    delegate :pending?, :success?, :error?, :failure?, :blocking?, :state, to: :status

    def active?
      return false unless stack.active_task?

      stack.active_task.includes_commit?(self)
    end

    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```

**File:** app/models/shipit/commit.rb (L304-306)
```ruby
    def status
      @status ||= Status::Group.compact(self, statuses_and_check_runs)
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
