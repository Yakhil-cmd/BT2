### Title
Unscoped `Commit.where(sha:)` in `StatusHandler#process` lets a status from any repository flip commit state for another stack (including production) - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves the target commit purely by bare SHA, with no check that the SHA belongs to the repository that authenticated the webhook. Because git commit SHAs are preserved across forks and shared history, a status webhook legitimately signed for one repository can create a `Status` record on a `Commit` belonging to a completely different stack, silently flipping that stack's deployability/blocking state.

### Finding Description
The broken binding is: `commit.stack.repository` (the repo that actually owns the SHA in the victim stack) `==` `repository_owner`/the repo that authenticated the incoming webhook. The code never establishes this equality.

Path:
1. `Shipit::WebhooksController#create` (`app/controllers/shipit/webhooks_controller.rb:10-15`) dispatches the parsed JSON body to `Shipit::Webhooks.for_event('status')`, i.e. `Handlers::StatusHandler`.
2. `verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-30`) only checks that the payload is signed by the GitHub App belonging to `repository_owner` (the org/owner in the payload). It never checks that the `sha` in the payload belongs to a commit in that specific repository — it only proves "this event came from GitHub for some repo under this org/app installation."
3. `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`):
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
This is a bare, cross-stack, cross-repository lookup — `Commit.where(sha:)` is not scoped to any repository or stack. Any `Commit` row across the whole Shipit instance with that SHA gets a new `Status` written via `commit.create_status_from_github!` (`app/models/shipit/commit.rb:165-169`), which calls `add_status`/`schedule_merges`/`schedule_continuous_delivery` on that commit's own `stack` (`app/models/shipit/commit.rb:281-287,366-386`), affecting `deployable?` (`app/models/shipit/commit.rb:227-229`) and `blocked?` (`app/models/shipit/commit.rb:231-237`).

Exploit flow: an attacker who owns/controls a repository within the same GitHub App installation/org as a victim's production stack (e.g., a personal fork or a low-privilege sandbox repo) pushes a commit whose SHA is identical to a commit that also exists in the victim's production stack (this is trivial via a plain `git fork` — GitHub forks retain identical SHAs for all unmodified history, and shared ancestor commits are common even without forking). GitHub legitimately fires a `status` webhook for the attacker's own repo with `context: shipit/checks`, `state: success` for that SHA. The webhook passes `verify_signature` because it is a real, correctly-signed event for that org/app. `StatusHandler#process` then matches the SHA against **all** commits in the database, including the identical commit row belonging to the victim's production stack, and writes a `success` status there too — potentially flipping `deployable?` to true (unblocking/permitting an unauthorized deploy) or, depending on required/blocking context configuration, forcing a block.

None of the existing guards catch this: `verify_signature` authenticates the org/app, not the specific repository-to-commit binding; `drop_unhandled_event` only filters unknown event types; the `ExplicitParameters` schema (`params do ... end` in `status_handler.rb`) only validates shapes/types of `sha`/`state`/`context`, not ownership; there is no `require_permission!`, `stacks` scope, or repository-format validator anywhere in this call path that ties the commit lookup back to the authenticating repository.

### Impact Explanation
A payload correctly authenticated for repository A causes a database write (a new `Status`) on a `Commit` belonging to repository B's stack — this is exactly the "payload for one repository mutating another's stack, commit" Critical category. If stack B is a production stack gating deploys on `shipit/checks`, the forced `success` status can make an otherwise-blocked or CI-pending commit `deployable?` (`app/models/shipit/commit.rb:227-229`), triggering `schedule_continuous_delivery` and an actual deploy/merge of code that was never validated by the victim repository's own CI. This is repeatable against any commit SHA shared between an attacker-accessible repo and any tracked stack, across the entire Shipit instance, since the lookup has zero repository scoping.

### Likelihood Explanation
Preconditions: the attacker needs at least one repository under the same Shipit/GitHub App installation where they can push and let GitHub fire a genuine `status` webhook (e.g., a personal fork of the victim repo, or any other repo they control in that org/installation), and a SHA that is shared with the victim's tracked stack (trivially achieved by forking, since forks retain identical commit SHAs for unmodified history, or by common ancestor commits before a branch diverges). No Shipit credentials, session, or secrets are required — only ordinary GitHub push/webhook capability on the attacker's own repo. This is low-cost and repeatable.

### Recommendation
Scope the commit lookup in `StatusHandler#process` to the repository that authenticated the webhook: resolve stacks/commits via the payload's `repository.full_name` (matching `Stack#repository`) before matching by SHA, e.g. `Commit.joins(:stack).where(sha: params.sha, shipit_stacks: { repository_id: repository_from_payload.id })`, mirroring how other handlers (e.g. `PushHandler`) scope writes to the repository in the payload.

### Proof of Concept
Minitest plan (`test/models/webhooks/handlers/status_handler_test.rb` or similar, no live GitHub):
1. Create two stacks/repositories, `victim` (production environment, `required_statuses` including `shipit/checks`) and `attacker_owned`, each with a `Commit` row sharing the same `sha` value (simulating a forked/shared commit).
2. Assert baseline: `victim_commit.reload.deployable?` is `false` (e.g., no successful `shipit/checks` status yet) — this is the equality-before state.
3. Build a status webhook `params` hash `{ sha: shared_sha, state: 'success', context: 'shipit/checks', repository: { full_name: 'attacker_owned/repo' } }` and call `Shipit::Webhooks::Handlers::StatusHandler.new.call(params)` (or POST to `/webhooks` with a stubbed `verify_webhook_signature` returning true for the attacker's org, per existing test pattern in `test/controllers/webhooks_controller_test.rb`).
4. Assert `victim_commit.statuses.count` increased by 1 and `victim_commit.reload.deployable?` is now `true` (or whatever flip is expected), proving a payload signed for `attacker_owned` mutated `victim`'s commit/stack state — the equality `commit.stack.repository == repository_owner` is violated.