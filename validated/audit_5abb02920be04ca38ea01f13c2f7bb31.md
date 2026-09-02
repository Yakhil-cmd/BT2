### Title
`StatusHandler#process` writes to `Commit` rows by bare SHA with no repository scoping, letting a status from one repo flip CI state on another repository's stack/commit - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves target commits with `Commit.where(sha: params.sha)` and never filters by the reporting repository, unlike other handlers that use the base `Handler#stacks` helper scoped through `Repository.from_github_repo_name(repository_name)`. Any `Commit` record anywhere in the database that happens to carry the same SHA value as the one in the incoming `status` webhook gets its status updated, regardless of which repository the webhook actually came from.

### Finding Description
The broken binding: the code should enforce `commit.stack.repository.full_name == payload['repository']['full_name']` before writing a status, but it enforces nothing of the sort. [1](#0-0) 

Compare with the base class helper that every repo-scoped handler is supposed to use: [2](#0-1) 

`StatusHandler` never calls `stacks`/`repository_name`; it queries `Commit` globally by `sha` and calls `commit.create_status_from_github!(params)` for every match, which mutates `statuses` and recomputes `status` for that specific `Commit`/`Stack` pair: [3](#0-2) [4](#0-3) 

That `status`/`add_status` path is what feeds `deployable?`, `blocked?`, and `stack.schedule_merges`, i.e. it can flip a stack's ship/block/merge decision: [5](#0-4) 

Existing guards do not close this gap: `verify_signature` only proves the payload came from a GitHub App installation that is authorized to send `status` events for *some* organization known to Shipit (`Shipit.github(organization: repository_owner)`); it says nothing about which `Commit`/`Stack` the SHA inside the payload should be allowed to touch. [6](#0-5) 

`Commit` rows are keyed by `sha` + `stack_id`, and a SHA is a deterministic hash of content+parent+author/committer metadata, not a per-repo secret. An attacker who forks a public repository tracked by Shipit inherits byte-identical commits (and therefore identical SHAs) for all of that shared history, and can also submit a PR whose head is one of those pre-existing, byte-identical commits. If the target stack has `review_stacks_enabled true, allow_all`, that PR auto-provisions a review stack whose `Commit` row shares the same `sha` as a `Commit` row on a completely unrelated "victim" stack. Once that SHA collision exists, any subsequent `status` webhook for `context: security/scan` on that SHA — legitimately signed for whatever repository actually reports it — is applied by `StatusHandler#process` to *every* `Commit` row with that SHA, including the victim stack's row, flipping its `security/scan` state and therefore its deployability/blocking decision.

### Impact Explanation
A status payload authenticated for one repository can write to `Commit`/`Status` records belonging to an unrelated `Stack`, changing that stack's blocking/deployable state and — combined with `review_stacks_enabled`/`allow_all` auto-provisioning review stacks that execute `shipit.yml` — can force an unauthorized ship or block on a stack the attacker never authenticated against. This matches the Critical category "a payload for one repository mutating another's stack, commit, task or team." The blast radius covers any two `Commit` rows in the installation that happen to share a SHA (achievable at will via forking/replicating public commits), so it is repeatable against any stack using `security/scan` (or any other context) as a required/blocking status.

### Likelihood Explanation
Preconditions: (1) a victim stack requiring/blocking on a status context (e.g. `security/scan`); (2) some mechanism producing a `Commit` row with a SHA that matches a commit the attacker controls or can replicate — most directly via `review_stacks_enabled true` + `allow_all`, which auto-provisions a `Stack`/`Commit` for any external PR's head SHA. An attacker only needs the ability to fork a public repo or open a PR (explicitly listed as in-scope attacker capability) — no Shipit credentials, session, or webhook secret are needed for the SHA-collision setup itself. The remaining piece — a legitimately signed `status` event for that SHA — still requires GitHub (or a CI system with push access) to emit it, but `StatusHandler#process`'s lack of scoping is what turns that otherwise-contained event into cross-stack impact.

### Recommendation
Scope `StatusHandler#process` the same way other handlers are scoped: resolve the reporting repository via `repository_name`/`stacks` (or an explicit `stack.repository` check) and restrict the `Commit` lookup to `stack.commits.where(sha: params.sha)` instead of a bare `Commit.where(sha: params.sha)` over the whole table.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`, not run here per scope rules but described for the fix validation):
1. Create `repo_a` and `stack_a` (victim), with `required_statuses = ['security/scan']`, `review_stacks_enabled: true`, `allow_all: true`.
2. Create `commit_a` under `stack_a` with `sha = "abc123..."` (some fixed 40-char sha).
3. Create `repo_b` and `stack_b` (attacker-influenced / review stack), and a `commit_b` under `stack_b` with the **same** `sha = "abc123..."`.
4. Assert before: `commit_a.status.state != 'success'` and `commit_a.deployable?` reflects the pre-status state (binding: `commit_a.stack_id != commit_b.stack_id` but `commit_a.sha == commit_b.sha`).
5. Call `Shipit::Webhooks::Handlers::StatusHandler.call('sha' => 'abc123...', 'state' => 'success', 'context' => 'security/scan', 'repository' => { 'full_name' => repo_b.full_name, 'owner' => { 'login' => repo_b.owner } })`.
6. Assert after: `commit_a.reload.status.state == 'success'` even though the payload's `repository.full_name` was `repo_b`, not `repo_a` — proving a status "authenticated" for `repo_b` mutated `commit_a`/`stack_a`, violating the invariant "a status for `security/scan` only affects the repository that authenticated it."

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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L227-237)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end

    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
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
