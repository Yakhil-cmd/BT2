### Title
Unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` lets a `status` webhook for one repository poison the CI/merge state of any other stack sharing that SHA - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves the target commit(s) for an incoming GitHub `status` webhook purely by raw SHA equality across the entire `commits` table, with no filter on `stack_id`/repository. Because `Commit` rows for logically unrelated stacks can carry the same SHA (shared git history between a fork and upstream, or two stacks tracking the same repository), a validly-signed `status` webhook belonging to one repository can write a `sonarqube: failure` status onto a commit belonging to a completely different stack.

### Finding Description
The claimed invariant, stated as an equality, is:
`repository_that_authenticated(payload) == repository_of(Commit rows mutated by params.sha)`

In `app/models/shipit/webhooks/handlers/status_handler.rb`:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [1](#0-0) 

There is no `repository`/`repository_owner`/`repository.full_name` check anywhere in this handler — unlike push- or PR-oriented handlers, it never resolves a `Repository`/`Stack` from the webhook payload's repository field before mutating state. It resolves commits purely by the attacker-controlled `sha` parameter across **every** stack in the installation.

`Commit#create_status_from_github!` → `add_status` then does:
```ruby
if previous_status.simple_state != new_status.simple_state
  ...
  stack.schedule_merges if new_status.pending? || new_status.success?
end
``` [2](#0-1) 

For a `failure` status on a `required`/`merge.require`d context (e.g. `sonarqube`), the commit's `status` (via `Status::Group`) flips to failing, which is read directly by `MergeRequest#any_status_checks_failed?` / `#all_status_checks_passed?` through `StatusChecker.new(head, head.statuses_and_check_runs, ...)`:
```ruby
def any_status_checks_failed?
  status = StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec)
  status.failure? || status.error?
end
``` [3](#0-2) 

`ProcessMergeRequestsJob` runs `reject_unless_mergeable!`, which calls `reject!('ci_failing')` if `any_status_checks_failed?` is true:
```ruby
def reject_unless_mergeable!
  return reject!('merge_conflict') if merge_conflict?
  return reject!('ci_missing') if any_status_checks_missing?
  return reject!('ci_failing') if any_status_checks_failed?
  ...
end
``` [4](#0-3) 

So a `commit` row on the victim stack that shares the poisoned SHA has its readable status flipped to failing, which will reject/block a pending merge request on the **victim** stack even though the required-context status never actually ran against the victim's repository/commit via GitHub. Because `Commit` rows are only unique on `(sha, stack_id)` (see the `commits` index note in the changelog: "Index `commits` table by `(sha, stack_id)`"), the same SHA is expected and supported to exist under multiple `stack_id`s — e.g. staging/production stacks tracking the same GitHub repository, or a fork sharing pre-divergence history with upstream — which is exactly the condition this handler fails to account for.

**Exploit flow:** The attacker owns/controls a repository with its own Shipit stack (or a fork whose early history matches the victim's shared upstream). They cause GitHub to emit (or, if the webhook secret used to authenticate the endpoint is shared across all repos/installations of the GitHub App rather than being genuinely repo-specific, directly send) a `status` webhook with `sha` set to a SHA that is also present as a `Commit` row on the victim's `merge_queue_enabled: true` stack, `context: sonarqube`, `state: failure`. `StatusHandler` iterates every `Commit` matching that bare SHA regardless of `stack_id`, writing the failing status onto the victim's commit as well as the attacker's own.

Existing guards do not stop this: signature verification only proves *some* repository/installation authenticated the payload, not that the SHA belongs to that repository; `ExplicitParameters` only validates the shape of `sha`/`state`/`context`, not ownership; and no model validation on `Commit`/`Status` ties a status write back to the repository that produced it.

I was not able to fully re-verify, within this pass, whether `Shipit::WebhooksController`/`GithubApp#verify_webhook_signature` binds the signing secret to a specific repository/installation rather than a single application-wide secret; this affects only the *cost* of obtaining a validly-signed payload, not the core root cause, which is squarely in `StatusHandler#process`'s unscoped `Commit.where(sha:)` lookup.

### Impact Explanation
A `status` webhook that is authenticated for one repository/installation can write a `Status` row against a `Commit` belonging to an entirely different stack whenever the SHAs coincide (multi-stack-per-repo deployments, staging/production split, or forks sharing pre-fork history are all realistic, supported configurations). On a `merge_queue_enabled: true` victim stack, this directly causes an unauthorized block (merge-request rejection via `reject!('ci_failing')`) of code the victim never actually failed CI on — matching the Critical category "a payload for one repository mutating another's stack, commit, task or team" / "unauthorized deploy, rollback or merge" (here, an unauthorized *block* of merge/deploy progress). The attack is repeatable against any stack sharing a SHA with an attacker-reachable repository.

### Likelihood Explanation
Requires: (1) an attacker-controlled or attacker-reachable repository with a route to emit a webhook that Shipit's endpoint accepts, and (2) a SHA collision with a `Commit` row already ingested into the victim's stack — realistic for stacks tracking the same repository under multiple environments, or forks/mirrors sharing history. No privileged Shipit role, session, or secret is required beyond what is needed to get GitHub to deliver (or replicate) a `status` event for a repository the attacker legitimately controls.

### Recommendation
Scope `StatusHandler#process` (and `Commit.where(sha:)` lookups it drives) to the repository that authenticated the webhook: resolve the `Repository`/`Stack` set from the payload's `repository` field first, then filter `Commit.where(sha: params.sha, stack_id: repository.stacks.select(:id))` (or equivalent join) before calling `create_status_from_github!`, mirroring the repository-scoping already used by push/PR handlers.

### Proof of Concept
minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb` or similar):
1. Create two `Repository`/`Stack` fixtures, `victim_stack` (`merge_queue_enabled: true`) and `attacker_stack`, each with a `Commit` row sharing the same `sha` (simulating shared history), and a pending `MergeRequest` on `victim_stack` whose `head` is that commit, currently mergeable (no failing required status).
2. Assert LHS/RHS equality before: `victim_commit.status.success?` (or unknown) and `merge_request.all_status_checks_passed?` are both true/consistent with "not blocked".
3. Invoke `Shipit::Webhooks::Handlers::StatusHandler.new(...).process` (or POST through the handler layer) with payload `{ sha: shared_sha, state: 'failure', context: 'sonarqube' }` — without any repository attribution to `victim_stack`.
4. Assert that `victim_commit.reload.status.failure?` is now true and `merge_request.reload` is rejected (`ci_failing`), proving the binding "a status affects only the repository that authenticated it" no longer holds — the write crossed into `victim_stack` despite the payload never being attributed to it.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/merge_request.rb (L155-162)
```ruby
    def reject_unless_mergeable!
      return reject!('merge_conflict') if merge_conflict?
      return reject!('ci_missing') if any_status_checks_missing?
      return reject!('ci_failing') if any_status_checks_failed?
      return reject!('requires_rebase') if stale?

      false
    end
```

**File:** app/models/shipit/merge_request.rb (L199-202)
```ruby
    def any_status_checks_failed?
      status = StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec)
      status.failure? || status.error?
    end
```
