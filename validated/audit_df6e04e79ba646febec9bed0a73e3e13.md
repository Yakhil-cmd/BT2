### Title
Cross-repository commit `status` write via unscoped `Commit.where(sha:)` lookup enables unauthorized merge-queue advance on `merge_queue_enabled` stacks - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves target commits purely by `sha` with no repository/stack scoping, so a validly-signed `status` webhook for one repository can flip the state of a `Commit` row belonging to a different stack whenever the same SHA exists in both repositories' `commits` tables. On a stack with `merge_queue_enabled: true`, a `success` state for the stack's required context (`ci/test`) makes the affected commit `deployable?`, which drives `Commit#add_status` to call `stack.schedule_merges`, advancing/forcing the merge queue.

### Finding Description
The broken binding is: `webhook.repository.owner/full_name == commit.stack.repository.owner/full_name` is assumed by the invariant but never enforced in code. Instead: [1](#0-0) 

`Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` matches every `Commit` row across every `Stack`/repository sharing that SHA, with no `stack_id`/`repository` filter derived from the webhook's `repository` payload. `create_status_from_github!` then replicates the status and calls `add_status`, which recomputes `Commit#status`/`deployable?` and, when the simple state changes to `success`/`pending`, calls `stack.schedule_merges` if `merge_queue_enabled?`: [2](#0-1) [3](#0-2) 

The only authentication check performed before dispatch is `WebhooksController#verify_signature`, which validates the HMAC against the secret for `repository_owner` taken from the payload's `repository.owner.login`/`organization.login`: [4](#0-3) 

This confirms the webhook is authenticated *for the repository that sent it*, but that authentication is never carried forward into `StatusHandler#process` to constrain which `Commit` rows may be mutated. Any repository/organization for which the attacker can legitimately post GitHub `status` events (e.g., their own fork/org with the same GitHub App/webhook installed) can therefore write a `success`/`ci/test` status onto a `Commit` row that belongs to an entirely different, victim stack, as long as the SHA is shared (identical git objects, e.g. via fast-forward merges, forks, or mirrored history). Existing guards (`verify_signature`, `drop_unhandled_event`, `ExplicitParameters` schema) validate *that a payload came from a real GitHub webhook for some repository*, but do nothing to scope *which stack's commits* that payload is permitted to touch.

### Impact Explanation
A successful exploitation lets an attacker-controlled repository's genuine (but foreign) `status` webhook flip a commit's state on a victim's `merge_queue_enabled` stack, causing `stack.schedule_merges` to run and the merge queue to advance/ship or block a PR the attacker does not own. This is a payload for one repository mutating another's stack/commit, matching the Critical impact category (unauthorized deploy/rollback/merge of attacker-influenced state). It is repeatable against any victim stack whose tracked repository happens to share a commit SHA with an attacker-controlled repository.

### Likelihood Explanation
Exploitation requires: (1) a victim stack configured with `merge_queue_enabled: true` and a required `ci/test` context, and (2) a commit SHA collision between the attacker's authenticated repository and the victim stack's `commits` table (i.e., the identical git object recorded in both, which is a real-world occurrence for forks and fast-forward merges, but is not guaranteed for arbitrary victim/attacker repo pairs and cannot be forced without such shared history). The attacker's own webhook must still pass `verify_signature`, meaning it must be a genuinely signed event for a repository/org actually integrated with the same Shipit GitHub App instance. Given those preconditions, the attack is repeatable and requires no privileged Shipit role.

### Recommendation
Scope `StatusHandler#process` (and analogous handlers) by the webhook's `repository` payload: resolve target `Commit`s via `Commit.joins(:stack).merge(Stack.where(repository_owner/name from payload)).where(sha: params.sha)` rather than a bare `sha` match, ensuring a status can only be applied to commits belonging to stacks whose tracked repository matches the authenticated webhook's repository.

### Proof of Concept
Minitest plan:
1. Create `stack_a` (victim) with `merge_queue_enabled: true`, requiring status context `ci/test`, and `stack_b` (attacker-controlled repository, distinct `repository_owner`/`repository_name`).
2. Create a `Commit` with a fixed `sha` under `stack_a`, and a second `Commit` with the *same* `sha` under `stack_b` (simulating shared git history).
3. Build a `status` webhook payload: `{ sha: <shared_sha>, context: 'ci/test', state: 'success', repository: { owner: { login: stack_b.repository_owner }, name: stack_b.repository_name } }`.
4. Assert BEFORE: `stack_a`'s commit `deployable?` is `false` (or merge queue not scheduled) — i.e., `stack_a_commit.deployable? == false`.
5. Invoke `Shipit::Webhooks::Handlers::StatusHandler.new(...).process` (or POST to `/webhooks` with a valid signature computed for `stack_b`'s owner) with the payload from step 3.
6. Assert AFTER: `stack_a_commit.reload.deployable? == true` and/or `stack_a.expects(:schedule_merges)` was invoked — demonstrating that a status authenticated only for `stack_b`'s repository altered `stack_a`'s (victim) commit state and triggered its merge-queue advance.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/commit.rb (L365-386)
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

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end
```
