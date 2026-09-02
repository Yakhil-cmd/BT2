### Title
Cross-repository commit-status webhook triggers `Stack#schedule_merges` on an unrelated stack via unscoped `Commit.where(sha:)` lookup - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves the target commits for an incoming `status` webhook with a global, stack-unscoped query (`Commit.where(sha: params.sha)`), then calls `create_status_from_github!` on every match. Because commit SHAs are not unique across stacks/repositories (e.g. two Shipit-managed repos that share git history, such as a fork and its upstream, or any coincidental SHA reuse), a correctly-signed webhook emitted by Repo A can update a `Commit` row that belongs to Stack B, driving `Commit#add_status` to call `stack.schedule_merges` on Stack B even though the verified event actually originated from Repo A.

### Finding Description
The binding the code is supposed to preserve is: `Stack.schedule_merges_target == Repository_that_emitted_the_verified_webhook`. In practice:

- `WebhooksController#verify_signature` authenticates only that the payload was signed by the GitHub App belonging to `repository_owner` (the org in the payload's own `repository.owner.login`) [1](#0-0) . It proves *who sent the event*, not which `Commit`/`Stack` rows are permitted to be mutated by it.
- `StatusHandler#process` then does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [2](#0-1) 
This query is global across the entire `commits` table and is not scoped to the stack/repository that emitted the authenticated webhook, unlike other parts of the model that intentionally scope SHA lookups to a single stack (e.g. `stack.commits.reachable.by_sha(sha)` used elsewhere) [3](#0-2) .
- `Commit#create_status_from_github!` calls `add_status`, and `add_status` calls `stack.schedule_merges` on `self.stack` — the `Commit`'s own associated stack — whenever `previous_status.simple_state != new_status.simple_state` and the new status is `pending?` or `success?`:
```ruby
if previous_status.simple_state != new_status.simple_state
  ...
  stack.schedule_merges if new_status.pending? || new_status.success?
end
``` [4](#0-3) 

Attack flow: attacker owns/controls Repo A (already onboarded in Shipit as their own Stack A, capability explicitly granted: "emit webhooks from a repository they own"). Repo A shares git history with victim Repo B (e.g. A is a fork of B, or contains cherry-picked/identical commits), so a commit SHA `X` exists in both `Stack A`'s and `Stack B`'s `commits` table. The attacker sets a real GitHub commit status on Repo A for SHA `X` (they have full write access to their own repo). GitHub sends a legitimately-signed `status` webhook for Repo A. `verify_signature` passes because the signature genuinely matches Repo A's app secret. `StatusHandler#process` then matches **every** `Commit` row with `sha == X`, including Stack B's row, and calls `add_status` on it — flipping Stack B's `simple_state` and invoking `Stack#schedule_merges` (`ProcessMergeRequestsJob.perform_later`) on the victim stack, despite the webhook never having been verified as originating from Repo B.

None of the existing guards catch this: `verify_signature` authenticates the sender org, not the resulting DB scope; `drop_unhandled_event` only filters by event type; the `ExplicitParameters` schema only validates payload shape; nothing in `StatusHandler` cross-checks `params.dig('repository', ...)` against `commit.stack.repository`.

### Impact Explanation
The victim's merge queue is unlocked/re-processed (`ProcessMergeRequestsJob`) as a side effect of an event from a completely unrelated, attacker-controlled repository — a cross-tenant write triggered by unverified provenance, matching "a payload for one repository mutating another's stack ... or an unauthorized ... merge" (Critical). This is repeatable against any Stack whose repository shares any commit SHA with an attacker-owned repository (most straightforwardly via forking a public/target repo).

### Likelihood Explanation
Requires: (1) attacker owns/administers a repository already onboarded into Shipit (so the GitHub App is installed and can deliver signed webhooks for it), and (2) that repository shares at least one commit SHA with the victim's repository (trivially true for a fork sharing history with its upstream, or any repo history overlap). Both conditions are attacker-achievable at low cost with no Shipit privileges, session, or secrets required — only the ability to fork a repo and create a commit status on their own fork.

### Recommendation
Scope the commit lookup in `StatusHandler#process` (and similarly in `CheckRunHandler`/other SHA-keyed handlers) to only the `Stack`(s) belonging to the repository identified in the verified payload, e.g. `Commit.joins(:stack).merge(Stack.where(repository: Repository.from_github_repo_name(params.dig('repository','full_name'))))`, or verify `commit.stack.repository.full_name == payload repository full_name` before calling `create_status_from_github!`.

### Proof of Concept
Minitest plan (Mocha), no live GitHub:
```ruby
test "status webhook from repo A does not schedule merges on unrelated stack B sharing a commit sha" do
  stack_a = shipit_stacks(:shipit) # attacker-owned stack/repo
  stack_b = shipit_stacks(:cyclimse) # victim stack, different repository

  shared_sha = "a" * 40
  commit_a = stack_a.commits.create!(sha: shared_sha, message: "shared")
  commit_b = stack_b.commits.create!(sha: shared_sha, message: "shared")

  Shipit::Stack.any_instance.expects(:schedule_merges).never

  payload = { sha: shared_sha, state: "success", context: "ci" }
  Shipit::Webhooks::Handlers::StatusHandler.new(payload).process

  # Expectation fails today: stack_b.schedule_merges is invoked even though
  # the (simulated) verified webhook came only from stack_a's repository.
end
```
Assert: for a webhook whose verified provenance is `stack_a.repository`, `Stack#schedule_merges` must be called (if at all) only with receiver `== stack_a`, never `stack_b`. Current code fails this assertion because `Commit.where(sha:)` returns both `commit_a` and `commit_b`.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/stack.rb (L266-266)
```ruby
      actual_deployed_commit = commits.reachable.by_sha(sha)
```

**File:** app/models/shipit/commit.rb (L379-384)
```ruby
      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
```
