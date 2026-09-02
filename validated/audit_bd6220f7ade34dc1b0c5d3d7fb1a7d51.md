### Title
`StatusHandler#process` creates `Status` rows for stacks belonging to repositories other than the webhook sender - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` resolves target commits with `Commit.where(sha: params.sha)` and calls `commit.create_status_from_github!(params)` for every match, without ever consulting `Handler#stacks`/`repository_name`, which is the mechanism every other handler (e.g. `PushHandler`) uses to scope actions to the repository that actually sent the webhook. Because git commit SHAs are shared verbatim across forks/duplicated history, a webhook correctly signed for one repository can create `Status` rows attached to `Commit`/`Stack` records belonging to a completely unrelated repository.

### Finding Description
Binding claimed to hold: `Status.count` created by one verified webhook == number of stacks whose `stack.repository.full_name == payload['repository']['full_name']`.

Traced code path:
- `Handler#repository_name` / `Handler#stacks` in `app/models/shipit/webhooks/handlers/handler.rb` (lines 32-38) exist precisely to scope any action to `Repository.from_github_repo_name(repository_name)`, and `PushHandler#process` (`app/models/shipit/webhooks/handlers/push_handler.rb` lines 12-17) correctly uses `stacks.not_archived.where(branch:)`.
- `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb` lines 20-24) instead does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`. This query is **global across the whole `commits` table**, unfiltered by `repository_name`/`stacks`.
- `Commit#create_status_from_github!` (`app/models/shipit/commit.rb` lines 165-169) calls `statuses.replicate_from_github!(stack_id, github_status)` using the iterated commit's own `stack_id` - not any stack tied to the webhook's repository.
- `Status.replicate_from_github!` (`app/models/shipit/status.rb` lines 24-33) then does `find_or_create_by!(stack_id:, state:, ...)`, creating a new `Status` row scoped to whatever `stack_id` that unrelated `Commit` belongs to.

Root cause: SHA is treated as a unique identifier across the whole installation, but SHA-1 commit hashes are commonly duplicated across repositories that share history (forks, mirrors, template repos, cherry-picked-with-identical-metadata commits). `verify_signature`/`GitHubApp#verify_webhook_signature` only prove that *a* legitimate webhook was sent by *a* specific repository the attacker controls (e.g. their own fork registered as a Shipit stack) - they do nothing to constrain which `Commit`/`Stack` rows get touched inside `process`. `drop_unhandled_event` and the `ExplicitParameters` schema only validate the shape of `sha`/`state`, not repository ownership. There is no model validation preventing `Status.replicate_from_github!` from attaching to a `stack_id` that doesn't match the sending repository.

Exploit flow: An attacker forks a legitimate repository that is already tracked as a Shipit stack (this fork shares identical commit objects/SHAs for the shared history). The attacker registers their fork as a Shipit stack (or it may already exist, e.g. in multi-repo/mirrored setups), causing `Commit` rows with the shared SHAs to exist for both stacks. The attacker then sends (or lets GitHub send, since it's their own repo/webhook) a correctly-signed `status` webhook for their own fork, referencing one of the shared SHAs, with an arbitrary `state`/`description`/`target_url`/`context`. `StatusHandler#process` matches all `Commit` rows across every stack sharing that SHA and creates a forged `Status` on the victim's stack too.

### Impact Explanation
A `Status` written this way affects the victim stack's CI/deployability logic: `Commit#add_status`, `Commit#deployable?`, `Hook.emit(:commit_status, ...)`, `Hook.emit(:deployable_status, ...)`, and `stack.schedule_merges` are all invoked as side effects of `add_status` (`app/models/shipit/commit.rb` lines 366-386). An attacker who controls only their own fork's webhook can therefore inject a fabricated `success`/`failure` status onto another tenant's commit, potentially unblocking continuous deployment (`schedule_continuous_delivery`) or unblocking merges on a stack they do not own/authorize. This is a cross-tenant write into another repository's `Stack`/`Commit` data and can influence an unauthorized deploy/merge decision, matching the Critical category "a payload for one repository mutating another's stack, commit, task or team."

### Likelihood Explanation
Preconditions: two Shipit stacks must track repositories that share commit history (a common and easily attacker-engineered setup - forking any repository already onboarded to the target Shipit instance, or two stacks pointed at the same upstream/mirror). The attacker needs no Shipit credentials: they only need to be able to send a webhook that will be verified against their own repository's/App installation's webhook secret, which they control by adding a webhook or having GitHub itself deliver a real `status` event for their own fork. Feasible and repeatable against any stack that shares a base history with any repository the attacker can create/fork and register as a Shipit stack.

### Recommendation
Scope `StatusHandler#process` the same way `PushHandler` does: resolve commits only through `stacks` (i.e. `Repository.from_github_repo_name(repository_name)&.stacks`), e.g. `Commit.where(sha: params.sha, stack_id: stacks.select(:id)).each { ... }`, so a `Status` can only be created for commits belonging to a stack whose repository matches `payload['repository']['full_name']`.

### Proof of Concept
Minitest plan (`test/models/webhooks/handlers/status_handler_test.rb`, not part of this audit's file but describes the reproducible scenario):
1. Create `repo_a = shipit.repositories.create!(...)` and `stack_a` on it, and `repo_b`, `repo_c` similarly, each with its own `stack`.
2. Create three `Commit` rows with the identical `sha: 'deadbeef' * 5` one per stack (`stack_a`, `stack_b`, `stack_c`) to simulate shared history across forks.
3. Build a `status` webhook payload with `repository.full_name = repo_a.full_name` and `sha = 'deadbeef'*5`.
4. Call `Shipit::Webhooks::Handlers::StatusHandler.call(payload)`.
5. Assert: `Status.where(stack_id: stack_a.id).count == 1` (expected, repo_a's own stack) BUT also observe `Status.where(stack_id: stack_b.id).count == 1` and `Status.where(stack_id: stack_c.id).count == 1` — i.e. `Status.count` increased by 3, not 1, from a single-repo webhook, violating the claimed binding (`Status` rows created should equal only stacks whose repository matches `repo_a.full_name`, i.e. 1, but is unbounded/cross-repo in practice).