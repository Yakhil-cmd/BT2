### Title
Cross-repository status confusion via unscoped `Commit.where(sha:)` in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` writes GitHub status updates to every `Commit` record sharing a given SHA, regardless of which repository authenticated the webhook. Because `schedule_merges` and continuous-delivery logic key off `commit.status`/`stack.schedule_merges`, a status event legitimately received for one repository can flip CI state and trigger merge-queue/deploy behaviour on an unrelated stack that happens to contain a `Commit` row with the same SHA (e.g. a shared commit between a fork and upstream, or any two stacks that independently ingested the identical SHA).

### Finding Description
The broken binding: the intended invariant is
`status.context == 'ci/jenkins' for sha S` should only mutate `Commit` rows belonging to the stack whose repository authenticated the webhook, i.e. `commit.stack.repository.full_name == payload['repository']['full_name']`.

Actual code: [1](#0-0) 
`process` does `Commit.where(sha: params.sha).each { |c| c.create_status_from_github!(params) }` — it never consults `payload['repository']` or the `stacks`/`repository_name` helpers that the base `Handler` class exposes for exactly this purpose: [2](#0-1) 

The `commits` table only enforces uniqueness of `sha` per `stack_id` (`add_index :commits, [:sha, :stack_id], unique: true`), meaning the same SHA can legitimately exist as separate `Commit` rows across many different stacks (e.g., fork/upstream pairs, or copied history). `StatusHandler` has no repository/stack scoping, so a status for that SHA is applied to all of them.

`verify_signature` in `Shipit::WebhooksController` authenticates the *request* against the org/app whose secret matches `payload['repository']['owner']['login']`, confirming only that the *sender* legitimately controls that org's webhook — it does **not** constrain which `Commit` rows the payload is allowed to mutate: [3](#0-2) 

Downstream, `create_status_from_github!` calls `add_status`, which — if the state changes — calls `stack.schedule_merges` when the new status is `pending` or `success`: [4](#0-3) 

Exploit flow: an attacker who owns/controls a GitHub repository (fork or otherwise) that is tracked as a Shipit stack can send/trigger a legitimate, correctly-signed `status` webhook for their own repository, naming `sha` equal to a commit SHA that is shared with (present in) a victim stack with `merge_queue_enabled: true` requiring `ci/jenkins`. Because `Commit.where(sha: params.sha)` is not scoped by repository, the victim's `Commit` row for that SHA also receives the status update, its state flips to `success`, and `stack.schedule_merges` fires on the victim stack, advancing/blocking the merge queue and potentially causing `merge!`/deploy to run.

### Impact Explanation
This is a payload for one repository (the attacker's) mutating another repository's stack/commit state (the victim's), which matches the "Critical" category explicitly listed in the rules ("a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy, rollback or merge"). The blast radius is any pair of stacks that share a commit SHA in their respective `commits` tables (common for forks, mirrors, or any repo relationship where identical commits are ingested into two tracked stacks). Repeated abuse lets an attacker force green/red CI state on a victim's merge queue on demand for any SHA they can get ingested into their own controlled stack.

### Likelihood Explanation
Preconditions: (1) attacker must control at least one Shipit-tracked repository/stack (or be able to send a validly signed status webhook for one — signature verification is per-org and does pass for the attacker's own legitimately configured org); (2) the target commit SHA must exist as a `Commit` row in both the attacker's stack and the victim's stack — realistic for forks, monorepo mirrors, or shared history; (3) the victim stack must have `merge_queue_enabled: true` and require the `ci/jenkins` context. Attacker cost is low (own repo + normal GitHub status API usage); no Shipit credentials, session, or secrets are required for the victim side. This is fully repeatable against any stack pair meeting these SHA-overlap conditions.

### Recommendation
Scope `StatusHandler#process` (and similarly `check_suite`/`check_run` handlers if affected) to only update commits belonging to the stack(s) resolved from `payload['repository']['full_name']`, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or joining `Commit` to `Stack`/`Repository` and filtering by the authenticated repository, mirroring the `stacks` helper already defined in `Handler`.

### Proof of Concept
minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`):
1. Create two stacks, `attacker_stack` (repo `attacker/repo`) and `victim_stack` (repo `victim/repo`, `merge_queue_enabled: true`, required status `ci/jenkins`).
2. Create `Commit` rows with the identical `sha: "deadbeef..."` for both `attacker_stack` and `victim_stack`.
3. Assert precondition (equality broken later): `victim_commit.status.state == 'unknown'` (or pending) and `victim_stack.merge_status` shows no queued merge.
4. Build a `status` payload: `{ "sha" => "deadbeef...", "state" => "success", "context" => "ci/jenkins", "repository" => { "full_name" => "attacker/repo", "owner" => { "login" => "attacker" } } }`.
5. Call `Shipit::Webhooks::Handlers::StatusHandler.call(payload)`.
6. Assert the divergence: `victim_commit.reload.status.state == 'success'` and that `Stack#schedule_merges` was invoked/`MergeRequest` state advanced on `victim_stack`, even though the payload's `repository.full_name` was `attacker/repo`, never `victim/repo`.
7. Contrast with expected behavior: assert `attacker_commit.reload.status.state == 'success'` was the *only* intended effect, demonstrating the cross-repository write.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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
