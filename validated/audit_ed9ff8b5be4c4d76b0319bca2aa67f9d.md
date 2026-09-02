### Title
Cross-repository status forgery via unscoped SHA lookup in `StatusHandler#process` triggers unauthorized merge queue advancement - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves target commits with `Commit.where(sha: params.sha)`, which is not scoped to the repository that authenticated the incoming webhook. Signature verification in `Shipit::WebhooksController#verify_signature` only proves that the payload's claimed `repository_owner` owns a valid webhook secret; it does not constrain which `Stack`/`Commit` records the handler is allowed to mutate. Any commit sharing the attacker's SHA across unrelated stacks receives the forged status, and on a stack with `merge_queue_enabled: true` a `success` status on the required context (`security/scan`) can flip `Commit#deployable?`/blocking state and trigger `stack.schedule_merges` in `Commit#add_status`.

### Finding Description
The broken binding is the implicit assumption that:
`Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` == "update only commits belonging to the stack whose repository authenticated this webhook via `verify_signature`"

These are not equal. `verify_signature` in [1](#0-0)   validates the HMAC using `Shipit.github(organization: repository_owner)`, i.e., it authenticates that *some* repo owned by `repository_owner` sent this payload — it never binds the payload to a specific `Stack`/`Commit` record. `StatusHandler#process` then performs a bare, cross-stack `Commit.where(sha:)` lookup with no repository/stack filter: [2](#0-1) . Since `Commit` rows are keyed by `stack_id` and `sha` is not guaranteed unique across stacks (each stack tracks its own set of commits, and identical SHAs can appear in different stacks — e.g., forked/mirrored repositories, or repositories sharing history), a `sha` value the attacker controls in their own authenticated payload can match a `Commit` row belonging to an entirely different, victim stack that the attacker's org never authenticated for.

Once matched, `commit.create_status_from_github!(params)` writes a new `Status` for the victim commit: [3](#0-2) . This flows into `add_status`, which recomputes `Status::Group` state and, if the simple state changed and the new status is `pending?` or `success?`, calls `stack.schedule_merges`: [4](#0-3) . On a stack with `merge_queue_enabled: true`, a green required context (e.g. `security/scan`) can therefore feed the merge queue evaluation for a commit the attacker never had access to, and `deployable?` is likewise governed by the forged status: [5](#0-4) .

Exploit flow: the attacker owns/controls a repository (fork or otherwise) whose commit history happens to share a SHA with a commit tracked by the victim stack (this is realistic for forked repos before divergence, or for any repo mirroring/rebasing onto the same upstream commit). The attacker pushes/creates that commit in their own repo, which is enough for GitHub to send (or for the attacker to directly POST, since GitHub itself will emit this for any repo containing that SHA) a legitimately-signed `status` webhook from their own organization/app installation, with `context: security/scan`, `state: success`, `sha: <shared sha>`. `verify_signature` passes because it's checking the attacker's own repo's HMAC secret, not the victim's. `StatusHandler#process` then updates every stack's commit sharing that SHA, including the victim's, potentially unblocking merges/deploys or blocking them if a mismatched required context is forged as failing.

None of the listed guards close this gap: `verify_signature` checks legitimacy of the sender's own repo, not scope of the mutation; `ExplicitParameters` only validates the shape of `params`, not repository binding; there is no `require_permission!`/`stacks` scope check inside `StatusHandler#process`.

### Impact Explanation
An attacker who legitimately controls one repository can cause a `Status` record to be written for a `Commit` belonging to a completely unrelated victim `Stack`, via forged-but-validly-signed webhook payload. If the victim stack has `merge_queue_enabled: true` and requires the same context name (`security/scan` or any other configured required status), this can flip `deployable?`/blocking state and drive `stack.schedule_merges`, resulting in an unauthorized merge/deploy decision for code the attacker doesn't control and never had status authority over. This matches "Critical — a payload for one repository mutating another's stack, commit ... or an unauthorized deploy, rollback or merge."

### Likelihood Explanation
Preconditions: the victim stack must have `merge_queue_enabled: true` and be configured to require the forged context; the attacker's commit SHA must coincide with a commit tracked in the victim's `commits` table (most realistically satisfied for forked/rebased repos sharing upstream history, or any scenario where the same commit object is pushed to two different GitHub repos both integrated with the same Shipit instance). The attacker needs no Shipit credentials — only the ability to have GitHub emit (or to directly send, since Shipit doesn't correlate the payload's declared `repository` field against the actual matched commit) a validly signed status event for their own repo. This is repeatable against any shared SHA and any number of stacks.

### Recommendation
Scope the `Commit` lookup in `StatusHandler#process` to the repository declared in the webhook payload (e.g., join through `Stack` and match `stack.repository` against `payload.repository`/`repository_owner` + `repository_name`) instead of a bare cross-stack `sha` match. Additionally, `create_status_from_github!` should validate that the status's originating repository matches the commit's stack repository before persisting.

### Proof of Concept
minitest plan (to be added under `test/models/shipit/webhooks/handlers/status_handler_test.rb`, out of scope for this audit but described for validation):
1. Create two stacks, `victim_stack` (`merge_queue_enabled: true`, `required_statuses: ['security/scan']`) and `attacker_stack`, each with a `Commit` row sharing the same `sha` value (`"deadbeef" * 5`).
2. Assert baseline: `victim_stack.commits.last.deployable?` == `false` (no status yet) — left side of the equality.
3. Build a `status` webhook payload with `sha` = shared sha, `context: "security/scan"`, `state: "success"`, and a `repository` field pointing to `attacker_stack`'s repo.
4. Call `Shipit::Webhooks::Handlers::StatusHandler.new(payload).process` (bypassing signature verification, simulating an attacker-authenticated request from their own repo).
5. Assert: `victim_stack.commits.last.reload.deployable?` == `true` and/or `victim_stack` merge queue was scheduled (`stack.schedule_merges` invoked) — right side of the equality now diverges from the left, proving the cross-stack mutation, with no assertion ever checking that `payload.repository` matches `victim_stack.repository`.

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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
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
