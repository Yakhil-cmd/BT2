### Title
Unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` lets one repository's status webhook overwrite CI state for commits in unrelated stacks/repositories - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves target commits purely by SHA, with no constraint tying the commit's `stack`/repository to the repository that authenticated the incoming webhook. Because Git SHAs are content-addressed and identical objects legitimately exist across forks/mirrors of the same underlying commit, an attacker who owns any repository sharing a SHA with a victim's tracked commit can emit a signed `status` event from their own repo and have Shipit apply that status (e.g. `context: deploy/production`, `state: failure`) to the victim's commit, flipping `deployable?`/merge eligibility in a stack they do not control.

### Finding Description
The broken binding the code should enforce is: `commit.stack.repository == webhook.repository` for every `Commit` a status is applied to. In `StatusHandler#process`: [1](#0-0) 

the handler does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` with no repository/stack filter at all. Compare this to `CheckSuiteHandler#process`, which at least scopes by `stacks.where(branch: ...)` before touching commits: [2](#0-1) 

`WebhooksController#verify_signature` only checks that the signature is valid for the *organization* derived from the payload's own `repository.owner.login`: [3](#0-2) [4](#0-3) 

This only proves the request was signed by *some* app installation for the attacker's own org/repo — it proves nothing about which repository's commits the payload is entitled to mutate. Since `Commit#required_statuses`/`blocking_statuses` are delegated to `stack` (`app/models/shipit/commit.rb` line 57-58), and `Status::Group#select_significant_status` (`app/models/shipit/status/group.rb` lines 75-83) determines `deployable?`-relevant state from whatever `Status` rows exist for the commit, writing a `failure` status with `context: deploy/production` via `create_status_from_github!` directly changes the victim stack's computed status/deployability regardless of which repository actually produced that SHA.

Exploit flow: attacker creates/forks a repository containing a commit object with the identical SHA already present in the victim's tracked repository (trivially achievable by forking or mirroring the victim's repo, or contriving any scenario where the same underlying commit object is shared across two repos tracked as separate stacks). Attacker's repo receives a legitimately signed GitHub `status` webhook (or the attacker triggers one for their own repo/CI), Shipit's controller verifies the signature against the attacker's own org and it passes. `StatusHandler#process` then looks up `Commit.where(sha: <shared sha>)`, which returns rows belonging to the victim's stack too, and calls `create_status_from_github!` on all of them — silently corrupting the victim's CI status.

None of the existing guards catch this: `verify_signature` authenticates the *sender's* org, not the *target* commit's owning repository; `drop_unhandled_event` only checks the event type is registered; the `ExplicitParameters` schema in `StatusHandler` only validates payload shape (`sha`, `state`, `context`, etc.), not repository scoping; there is no `stacks` filter, no `Repository` equality check, and no model validation in `Status` or `Commit` that ties an incoming status to the repository that authenticated it.

### Impact Explanation
A `failure` status written for a required context (e.g. `deploy/production`) directly changes `Commit#status`/`deployable?` computation via `Status::Group`, which gates deploys and `ProcessMergeRequestsJob` merge scheduling. This is a cross-repository/cross-tenant write: a payload authenticated for repository A mutates state (`Status` records, and therefore deployability/merge eligibility) owned by repository B/stack B, matching the "payload for one repository mutating another's stack, commit ... " Critical category. The attack is repeatable against any stack whose commits happen to share a SHA with a repository the attacker controls, and can be used to block deploys (DoS on deployability) or, combined with other manipulation, to force a `success` status through the same unscoped path to unlock deploys/merges that shouldn't be eligible.

### Likelihood Explanation
The attacker needs no privileges within Shipit and no secrets — only the ability to own/control a GitHub repository and cause a `status` webhook to be delivered for it (which GitHub sends automatically for their own CI or can be triggered via the GitHub Status API on a repo they administer). The main precondition is a shared SHA between attacker-controlled and victim repositories, which is realistic in fork/mirror/monorepo-migration scenarios that Shipit is commonly used with (shared history is the norm, not the exception, for `git` objects). No rate limiting or additional guard exists to stop repeated attempts.

### Recommendation
Scope `StatusHandler#process` to only touch commits whose `stack` belongs to the repository that authenticated the webhook — e.g. resolve `stacks` for the payload's `repository.full_name` (as `PushHandler`/`CheckSuiteHandler` do) and restrict `Commit.where(sha: params.sha, stack: stacks)` instead of a global SHA lookup across all stacks.

### Proof of Concept
Minitest plan (webhooks_controller_test.rb or a new status_handler_test.rb):
1. Seed two stacks: `stack_a` (attacker-owned repo, e.g. `attacker/repo`) and `stack_victim` (repo `victim/repo`) with `cached_deploy_spec` requiring `ci.require = ['deploy/production']` on the victim stack.
2. Create `commit_victim` in `stack_victim` with `sha = SHARED_SHA` and an existing passing status for `deploy/production`; assert `commit_victim.deployable?` is `true` before the attack.
3. Also create `commit_attacker` in `stack_a` with the same `SHARED_SHA` (simulating a shared git object across forks).
4. Stub `GithubApp#verify_webhook_signature` to return true only for the attacker's org (`Shipit.github(organization: 'attacker').expects(:verify_webhook_signature).returns(true)`), representing a webhook that only proves authenticity for the attacker's repo.
5. POST `/webhooks` with `X-Github-Event: status`, body `{ sha: SHARED_SHA, state: 'failure', context: 'deploy/production', repository: { full_name: 'attacker/repo', owner: { login: 'attacker' } } }`.
6. Assert: `commit_victim.reload.statuses.where(context: 'deploy/production').last.state == 'failure'` and `refute_predicate commit_victim, :deployable?` — proving repository A's payload mutated repository B's commit/stack state, i.e. the binding `commit.stack.repository == payload.repository` was violated.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```
