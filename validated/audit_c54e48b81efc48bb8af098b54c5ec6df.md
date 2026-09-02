### Title
Cross-tenant `Stack#schedule_merges` triggered by SHA-collision status webhook - ([File: app/models/shipit/commit.rb])

### Summary
The `StatusHandler` for GitHub status webhooks looks up commits globally by SHA (`Commit.where(sha: params.sha)`) with no scoping to the repository that the verified webhook payload actually belongs to. Because `Commit#create_status_from_github!` reads `stack` off whichever `Commit` row matches the SHA, an attacker who controls a repository configured in Shipit (or shares a base commit with a victim repo, e.g. via a fork) can trigger `stack.schedule_merges` on a completely unrelated victim stack using a properly-signed webhook for their *own* repository.

### Finding Description
The binding that should hold is: `stack whose repository authenticated this webhook == stack passed to schedule_merges`. It is broken because the code path never re-checks the payload's `repository.full_name` after signature verification.

Path:
1. `Shipit::WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) verifies the HMAC signature using `Shipit.github(organization: repository_owner)`, which authenticates that GitHub sent this event *for that organization/app config* — it does not scope trust to a single repository or stack. [1](#0-0) 
2. `StatusHandler#process` then does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — a **global, cross-stack, cross-repository** SQL lookup by SHA alone, with no filter on repository/stack. [2](#0-1) 
3. `Commit#create_status_from_github!` calls the private `add_status`, which reads `stack` off the matched `Commit` record (`belongs_to :stack`), not off the verified payload's repository. [3](#0-2) 
4. Inside `add_status`, `stack.schedule_merges if new_status.pending? || new_status.success?` fires against whatever stack the matched `Commit` belongs to. [4](#0-3) 

Because git commits are content-addressed, the same SHA can legitimately exist in two different Shipit-tracked stacks that share history (e.g., a victim's repo and an attacker-controlled fork, or two stacks tracking the same upstream repo at different environments). An attacker who owns any repository configured in Shipit can send (via real GitHub, since they own that repo) a status webhook for a SHA that is also present in a victim stack's commit history. GitHub signs this webhook correctly for the attacker's own org/repo, so `verify_signature` passes legitimately — the signature check was never designed to prevent this, since it authenticates "GitHub sent this for org X," not "this SHA belongs to stack Y." `StatusHandler` then updates *every* `Commit` row with that SHA across the whole installation, including the victim's, and fires `schedule_merges` on the victim's stack.

None of the listed guards prevent this: `verify_signature` only checks org-level HMAC, `drop_unhandled_event` only filters by event type, there is no `ExplicitParameters` check on `repository.full_name` vs `stack`, and `Commit.where(sha:)` has no stack/repo scoping.

### Impact Explanation
An attacker can force `ProcessMergeRequestsJob`/`schedule_merges` to run against an arbitrary victim stack whose only "authorization" was sharing a commit SHA with a repository the attacker controls — a payload for one repository mutating another's stack behavior (forced merge-processing cycle). This matches the Critical category: "a payload for one repository mutating another's stack, commit, task or team." It is repeatable for every subsequent status push the attacker makes on the shared SHA, and could apply across many victim stacks that share a fork ancestry or common upstream.

### Likelihood Explanation
Preconditions: the attacker needs (a) any repository that Shipit has configured a GitHub App/webhook for (this can be their own fork or unrelated repo they set up in Shipit), and (b) a commit SHA that is also present in a target stack's `commits` table — most easily achieved by forking a public repo tracked by Shipit, since fork history shares identical SHAs with the upstream by construction, no brute-force or hash collision needed. The attacker does not need any Shipit credentials; they only need to push/trigger a real GitHub status event on a commit they legitimately have in their own repo/fork. This is a low-cost, realistic, and repeatable precondition, not a theoretical hash-collision attack.

### Recommendation
Scope `StatusHandler#process` (and similarly `CheckRunHandler` and other SHA-keyed handlers) to the repository named in the verified payload, e.g. resolve the `Stack` via `params.repository.full_name` first and constrain `Commit.where(sha: params.sha, stack_id: stack.id)` (or filter `commit.stack.github_repo_name == payload repository`) before calling `create_status_from_github!`, so a webhook can only mutate commits/stacks belonging to the repository that actually emitted it.

### Proof of Concept
Minitest test plan (Mocha) under `test/`:
1. Create two `Stack` fixtures, `victim_stack` (repo `victim/repo`) and `attacker_stack` (repo `attacker/repo`), each with a `Commit` sharing the same `sha` (simulating shared fork ancestry).
2. Stub `Shipit.github(organization: 'attacker').verify_webhook_signature` to return `true` (simulating a correctly signed webhook from the attacker's own repo).
3. `Stack.any_instance.expects(:schedule_merges)` — set expectation specifically on `victim_stack` instance (e.g. `victim_stack.expects(:schedule_merges)`), and `attacker_stack.expects(:schedule_merges)` as well (both should NOT both be asserted as intended-only-one).
4. POST to `/webhooks` with `X-Github-Event: status` header and a JSON body: `{ "sha": "<shared_sha>", "state": "success", "repository": { "full_name": "attacker/repo", "owner": { "login": "attacker" } } }`.
5. Assert `victim_stack.schedule_merges` was called even though the payload's `repository.full_name` was `attacker/repo`, proving cross-tenant mutation — i.e., assert the equality `stack authenticated by webhook (attacker_stack) != stack passed to schedule_merges (also includes victim_stack)` still holds true (bug present) rather than being fixed to only call `schedule_merges` on `attacker_stack`.

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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
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
