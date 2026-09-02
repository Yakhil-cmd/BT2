### Title
Unscoped cross-repository SHA lookup in `StatusHandler#process` lets an attacker write forged statuses onto a victim's commit - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits by bare `sha` with no repository/stack scoping, unlike sibling handlers (`OpenedHandler`, `ClosedHandler`) that resolve `Shipit::Repository.from_github_repo_name(params.repository.full_name)` before acting. Any commit row in the entire Shipit database sharing that SHA — including one that belongs to a stack tracking a completely different GitHub repository — gets a status created from the attacker-controlled payload.

### Finding Description
The broken binding is: the handler should enforce `commit.stack.repository == Repository.from_github_repo_name(payload.repository.full_name)` before writing, but instead does: [1](#0-0) 

`Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` iterates every `Commit` record across all stacks/repositories that happens to share the exact SHA string, and calls `create_status_from_github!` regardless of which repository authenticated the webhook. Compare this to `PullRequest::OpenedHandler`/`ClosedHandler`, which explicitly resolve `repository` from `params.repository.full_name` and scope operations to `repository.review_stacks` [2](#0-1) . `StatusHandler`'s `params` schema doesn't even require a `repository` field [3](#0-2) , so scoping isn't merely omitted in `process` — the handler never captures which repository the event came from.

`create_status_from_github!` then calls `add_status`, which recomputes `Status::Group` state, fires `deployable_status`/`commit_status` hooks, and — critically — calls `stack.schedule_merges if new_status.pending? || new_status.success?` [4](#0-3) . For a stack with `merge_queue_enabled: true`, `schedule_merges` progresses queued `MergeRequest`s, and `MergeRequest#merge!` executes `stack.github_api.merge_pull_request(...)` once `all_status_checks_passed?` is satisfied via `StatusChecker` reading the head commit's statuses [5](#0-4) , [6](#0-5) .

**Exploit precondition — verified as significant but only partially confirmed.** The `verify_signature` before_action requires a valid HMAC computed with `Shipit.github(organization: repository_owner).webhook_secret` for the org named in `payload.repository.owner.login` [7](#0-6) . This means the attacker must be able to produce a validly-signed webhook for *some* org known to the Shipit instance (e.g., an org they control that has the GitHub App/webhook installed for their own repo). This is plausible in a multi-org/public Shipit deployment, and the signature check validates only "this payload came from a legitimate webhook of org X" — it does **not** validate that the `sha` inside the payload actually belongs to a commit reachable in org X's repository. Because `StatusHandler` performs no post-signature repository/stack scoping, once signature verification passes for the attacker's own org, the `sha`/`context`/`state` fields are trusted globally against `Commit.where(sha:)`.

The remaining precondition for real-world exploitability is a SHA collision between the attacker's repo and the victim's tracked repo. This is realistic when the victim's repo has any public history that the attacker can fork or reference (shared ancestor commits have byte-identical SHAs by construction), but the task did not confirm the specific mechanism the attacker would use to get a shared SHA recorded as a `Commit` row in the victim's stack in this codebase's test/fixture setup — I could not verify this without running the sync pipeline (`GithubSyncJob`) code, which was out of scope to fully trace in the remaining budget.

Existing guards checked and found insufficient: `verify_signature` (authenticates org, not SHA ownership), `drop_unhandled_event` (irrelevant — status is a handled event), the `ExplicitParameters` schema for `StatusHandler` (only requires `sha`/`state`, no repository binding at all), and model validations on `Status`/`Commit` (no repository check). No handler-level `stacks`/`repository` scoping exists for this handler, unlike its siblings.

### Impact Explanation
An attacker who can get one validly signed `status` webhook accepted for their own org can write a `Status` record (arbitrary `context`, `state`, `description`, `target_url`) onto any `Commit` row anywhere in the instance that shares the SHA — this is a cross-tenant write (a payload for one repository mutating another's commit/stack). On a victim stack with `merge_queue_enabled: true` and a queued `MergeRequest` whose head is the shared commit, flipping the required `review/approved` context to `success` (not `failure` as literally stated for advancing the queue — `schedule_merges` fires on `pending?` or `success?`) can trigger `MergeRequest#merge!`, causing an unauthorized GitHub merge via `stack.github_api.merge_pull_request`. This matches "Critical — a payload for one repository mutating another's stack/commit... or an unauthorized deploy/rollback/merge."

### Likelihood Explanation
Requires: (1) attacker has a validly-signed webhook path into the Shipit host for some org (own repo/App installation), (2) a SHA collision — realistically a shared ancestor commit — must already exist as a `Commit` row in the victim's stack, and (3) the victim stack must have `merge_queue_enabled: true` with a pending `MergeRequest` whose head equals that shared commit and whose only unmet requirement is the manipulated `review/approved` context. Conditions (2) and (3) are not attacker-controlled and depend on victim configuration/history overlap, making this situational rather than trivially repeatable against arbitrary stacks, but the code path itself imposes zero repository check once (1) is satisfied.

### Recommendation
In `StatusHandler`, require `repository.full_name` in the params schema and scope the lookup: resolve `repository = Shipit::Repository.from_github_repo_name(params.repository.full_name)` and only process `Commit.where(sha: params.sha, stack_id: repository.stacks.select(:id))`, mirroring the pattern already used in `PullRequest::OpenedHandler`/`ClosedHandler`.

### Proof of Concept
minitest plan (`test/controllers/webhooks_controller_test.rb` or `test/models/shipit/webhooks/handlers/status_handler_test.rb`):
1. Create `stack_a` (attacker's repo, e.g. `attacker/repo`) and `stack_b` (victim, `merge_queue_enabled: true`, requires `review/approved`) each with a `Commit` sharing `sha: "deadbeef..."`.
2. Create a pending `MergeRequest` on `stack_b` with `head` = that commit, otherwise mergeable (`mergeable: true`), missing only the `review/approved` status.
3. POST a `status` webhook with `repository.full_name = "attacker/repo"`, `sha: "deadbeef..."`, `context: "review/approved"`, `state: "success"`, signed for `attacker`'s org.
4. Assert: `stack_b`'s commit now has a `success` status for `review/approved` (binding broken: `commit_b.status.context_state("review/approved") == "success"` even though only `attacker/repo` authenticated), and assert `MergeRequest#merge!`/`schedule_merges` was invoked on `stack_b` (e.g. `ProcessMergeRequestsJob` enqueued or `Shipit::MergeRequest.any_instance.expects(:merge!)`), proving unauthorized merge progression on a stack the attacker never authenticated for.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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

**File:** app/models/shipit/merge_request.rb (L164-176)
```ruby
    def merge!
      raise InvalidTransition unless pending?

      raise NotReady if not_mergeable_yet?

      stack.github_api.merge_pull_request(
        stack.github_repo_name,
        number,
        merge_message,
        sha: head.sha,
        commit_message: 'Merged by Shipit',
        merge_method: stack.merge_method
      )
```

**File:** app/models/shipit/merge_request.rb (L193-202)
```ruby
    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end

    def any_status_checks_failed?
      status = StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec)
      status.failure? || status.error?
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
