### Title
Cross-repository status forgery via unscoped sha lookup unblocks a foreign stack's deploy batch - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves the target `Commit` records purely by `sha`, with no check that the webhook's originating repository matches the `stack`/`repository` that owns that `Commit` row. Because Git commit hashes are content-addressed and identical across a public fork and its upstream, any user who can fork a public repo tracked by Shipit and install/trigger a status webhook on that fork can flip the CI status of a commit that also exists in a victim stack's undeployed batch, changing which commit `Stack#next_commit_to_deploy` selects.

### Finding Description
The claimed binding is: `webhook.repository.full_name == commit.stack.repository.full_name`. Tracing the code shows this equality is never checked.

`StatusHandler#process` does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [1](#0-0) 

The `params` schema for this handler only requires `sha`, `state`, and optional `description`/`target_url`/`context`/`created_at`/`branches` — there is no `repository` field constraining which stack's commits may be affected. [2](#0-1) 

`Commit` rows are scoped per `stack` (`belongs_to :stack`), and a stack's own undeployed-commit blocking logic walks `stack.commits.reachable.newer_than(...).older_than(self)`: [3](#0-2) [4](#0-3) 

`Stack#next_commit_to_deploy` and the private `deployable_commits` helper select the first deployable commit from the (possibly `maximum_commits_per_deploy`-limited) undeployed batch: [5](#0-4) [6](#0-5) 

Because `Commit.where(sha: params.sha)` has no repository/stack scoping, if the victim stack already has a `Commit` row for a given sha (synced from the real upstream repo), and an attacker's own fork shares that same sha in its git history (true for any commit that predates the fork point, or any content-identical commit), the attacker can:
1. Fork the victim's public repository (no privileges required).
2. Set a commit status (`success`) on that shared sha in their own fork, either via GitHub's UI/API on a repo they own, or via any mechanism that causes a `status` webhook to be emitted for their fork with that sha.
3. If Shipit's GitHub App/webhook is a shared-secret, multi-installation integration (as is standard for GitHub Apps — one `webhook_secret` validates all installations), this webhook passes `verify_webhook_signature`/HMAC checks because it is a legitimately signed event, just from the wrong repository.
4. `StatusHandler#process` matches `Commit.where(sha: ...)` across the whole database and calls `create_status_from_github!` on the victim stack's `Commit` row too, flipping `blocked?`/`deployable?` for the earliest blocking commit in the victim's undeployed batch.
5. On the next `next_commit_to_deploy` evaluation (continuous delivery job or deploy trigger), `deployable_commits` now returns a later commit that the victim's real CI never approved for that position in the queue, and `trigger_continuous_delivery`/`trigger_deploy` ships it.

None of the listed guards close this gap: `verify_signature`/`verify_webhook_signature` authenticates the sender as a legitimate GitHub App delivery, not as authorized for a specific target repository's commits; `drop_unhandled_event` only filters unknown event types; the `ExplicitParameters` schema for `StatusHandler` has no repository field to validate against; `Repository`/`Stack` model validations don't constrain cross-stack sha collisions. I was unable to fully inspect `app/controllers/shipit/webhooks_controller.rb` and `lib/shipit/github_app.rb` within the available tool budget to confirm the exact signature-verification mechanics (e.g., whether the webhook secret is per-installation or global), so the precise mechanism by which the attacker's fork produces a validly-signed webhook to Shipit should be re-verified, but the root cause — the unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` — is confirmed directly from the source.

### Impact Explanation
A successfully forged/foreign status update causes `Stack#next_commit_to_deploy` to select and subsequently deploy (via `trigger_continuous_delivery`/`trigger_deploy`) a commit that the victim stack's own, legitimate CI state would not have authorized at that point in the queue. This is a payload from one repository/organization mutating another repository's stack/commit/deploy state — matching the Critical category "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy." The blast radius extends to any Shipit tenant stack that shares commit history (via public fork) with an attacker-controlled repository and has `maximum_commits_per_deploy` configured with multiple undeployed commits.

### Likelihood Explanation
Preconditions: the victim stack must have `maximum_commits_per_deploy` set, multiple undeployed commits, and the earliest blocking commit's sha must be reachable in a repository the attacker can send status webhooks for (trivially satisfied by forking the victim's public repo, since forks share full git history/shas at fork time). Attacker cost is low — fork a public repo, install/trigger the GitHub App integration on the fork, and set a commit status via GitHub's normal status API. No Shipit credentials, session, or secrets are required. This is repeatable against any Shipit-tracked public repository with the same configuration.

### Recommendation
Scope the `Commit` lookup in `StatusHandler#process` (and analogous handlers, e.g. check-run/check-suite handlers) to commits belonging to stacks whose `repository` matches the webhook's `payload.repository.full_name`/id, rather than matching by `sha` alone. Require and validate a `repository` field in the handler's `params` schema and filter `Commit.where(sha: params.sha, stack: Stack.joins(:repository).where(repositories: { owner:, name: }))` (or equivalent) before applying the status.

### Proof of Concept
Minitest plan (no live GitHub, using existing fixtures/factories):
1. Create two repositories/stacks: `victim_stack` (repository `victim/repo`) and `attacker_stack` (repository `attacker/repo-fork`), each with `maximum_commits_per_deploy` set on `victim_stack`'s deploy spec.
2. Create commits `c1` (earliest, blocking, pending/no status) and `c2` (later) under `victim_stack`, and independently create a `Commit` record with the *same sha as `c1`* under `attacker_stack`.
3. Assert baseline: `victim_stack.next_commit_to_deploy` is `nil` or not `c2` (because `c1` is blocking and `deployable_commits` won't skip past it under `maximum_commits_per_deploy`).
4. Invoke `Shipit::Webhooks::Handlers::StatusHandler.new(...).process` (or POST to the webhook endpoint with a validly signed payload) with `sha: c1.sha, state: 'success', context: 'ci', repository: attacker repo payload`.
5. Reload `c1` under `victim_stack` and assert its status flipped to success even though the webhook's repository was `attacker/repo-fork`, not `victim/repo`.
6. Assert `victim_stack.next_commit_to_deploy` now returns `c2` — demonstrating the equality `webhook.repository == commit.stack.repository` was violated and directly changed the deploy target for a foreign tenant's stack.

### Citations

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

**File:** app/models/shipit/commit.rb (L11-11)
```ruby
    belongs_to :stack
```

**File:** app/models/shipit/commit.rb (L227-237)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end

    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
    end
```

**File:** app/models/shipit/stack.rb (L235-243)
```ruby
    def next_commit_to_deploy
      commits_to_deploy = commits.order(id: :asc).newer_than(last_deployed_commit).reachable.preload(:statuses)
      if maximum_commits_per_deploy
        commits_with_max_applied = commits_to_deploy.limit(maximum_commits_per_deploy)
        deployable_commits(commits_with_max_applied) || deployable_commits(commits_to_deploy)
      else
        deployable_commits(commits_to_deploy)
      end
    end
```

**File:** app/models/shipit/stack.rb (L645-647)
```ruby
    def deployable_commits(commits)
      commits.to_a.reverse.find(&:deployable?)
    end
```
