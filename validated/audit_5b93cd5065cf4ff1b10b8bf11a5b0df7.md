### Title
Cross-repository commit status forgery via unscoped `Commit.where(sha:)` lookup - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` resolves the commit(s) to update purely by `sha`, with no constraint tying the write to the repository that actually emitted the webhook. Any commit sha shared between two different `Stack`s (e.g. a forked repository sharing ancestor commits with the original, or any other repo with an identical sha) lets a webhook legitimately signed for repo B forge a `Status` on a `Commit` belonging to unrelated repo/stack A, corrupting the CI state consulted by `Commit#status`, `#deployable?`, `#blocked?`, and downstream deploy/merge scheduling during an in-flight task.

### Finding Description
The intended binding is: `commit.stack.github_repo_name == payload.dig('repository', 'full_name')` for every `Commit` row that a webhook is allowed to mutate. The base `Handler` class even defines a `stacks` helper for this purpose [1](#0-0) , but `StatusHandler#process` never uses it:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [2](#0-1) 

`Commit.where(sha: params.sha)` is a global, unscoped lookup across *all* stacks/repositories in the Shipit instance, not just the repository named in `payload['repository']['full_name']`.

`verify_signature` in `WebhooksController` only proves the payload was signed with the secret registered for `repository_owner` (the GitHub *organization*, not the specific repo) [3](#0-2) . It does not, and cannot, prove that the `sha` in the payload only exists in the repository that sent it — GitHub commit SHAs are computed over content+parents+metadata and are legitimately reused across forks/mirrors of the same history. Per the given threat model, an attacker who "owns" a repository able to "emit webhooks" (i.e. controls a repo that is itself onboarded as a Shipit `Stack`) can fork or otherwise obtain a repo sharing ancestor commit shas with a victim's tracked repo, then trigger (via real GitHub activity on their own repo) a `status` webhook for one of those shared shas with an arbitrary `state`/`description`/`target_url`.

Exploit flow:
1. Attacker owns/controls Stack B (a repo registered in Shipit that shares ancestor commit sha `X` with victim Stack A, e.g. via fork history).
2. Victim Stack A has an active task (deploy) covering commit `X`.
3. Attacker causes a real, validly-signed GitHub `status` webhook for sha `X` to be delivered (e.g. posting/forcing a CI status on their own repo).
4. `StatusHandler#process` finds *every* `Commit` row with `sha == X`, including stack A's row, and calls `create_status_from_github!` on it [4](#0-3) .
5. `add_status` reloads state, compares `previous_status`/`new_status`, and — critically — calls `stack.schedule_merges` and emits `deployable_status`/`commit_status` hooks using stack A's own `stack` object whenever the simple state changes [5](#0-4) .
6. Any code reading `Commit#status`/`#success?`/`#deployable?` for stack A during the in-flight task (UI polling, `deployable?` checks, continuous-delivery scheduling at `schedule_continuous_delivery`) now reflects attacker-controlled content sourced from repo B, not stack A's real CI [6](#0-5) [7](#0-6) .

`Commit#active?` itself is unaffected (it only checks `stack.active_task.includes_commit?`, comparing internal record IDs) [8](#0-7)  and `Task#includes_commit?` compares commit ids scoped to the task's own `since_commit`/`until_commit` [9](#0-8) , so the specific "active? forgery" framing in the question does not hold. The real, demonstrable bug is the unscoped status write in `StatusHandler`, which corrupts the *status* consulted alongside `active?` for stack A's in-flight commit.

### Impact Explanation
An attacker controlling any repository onboarded as a Shipit stack can write arbitrary `Status` rows (`state`, `description`, `target_url`, `context`) onto `Commit` records belonging to a completely unrelated stack/repository/tenant, as long as a sha collision (most realistically via shared fork ancestry) exists. This can flip `Commit#success?`/`#deployable?` to true for a commit whose real CI never passed, triggering `stack.schedule_merges`, `ContinuousDeliveryJob`, or misleading operators/automation mid-deploy into treating an in-flight task's commit as green. This matches "a payload for one repository mutating another's stack/commit" (Critical) since it can influence an unauthorized deploy/merge decision on stack A sourced from repo B's payload.

### Likelihood Explanation
Requires: (a) the attacker's own repo is registered as a Shipit `Stack` (explicitly permitted under the given threat model — "emit webhooks from a repository they own"), and (b) a sha collision with the victim commit, most practically achieved via forked/shared history rather than a true SHA-1 break. No Shipit secrets, sessions, or maintainer status are needed. This is repeatable against any stack sharing history with an attacker-controlled repo, and the webhook signature check does not detect or prevent it since it only authenticates at the organization level, not the specific repository/commit ownership.

### Recommendation
Scope the lookup in `StatusHandler#process` (and equivalently `CheckRunHandler`/similar handlers if affected) to commits belonging to `stacks` resolved from `payload['repository']['full_name']`, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`, so a status write can only ever affect commits in stacks tracking the repository that actually sent the webhook.

### Proof of Concept
Minitest plan (model/handler-level, no live GitHub):
1. Create two stacks, `stack_a` (repo `org/victim`) and `stack_b` (repo `attacker/fork`).
2. Create `commit_a = Commit.create!(stack: stack_a, sha: 'deadbeef...', ...)` and `commit_b = Commit.create!(stack: stack_b, sha: 'deadbeef...', ...)` — same sha, different stacks, simulating shared fork ancestry.
3. Start/record an active task on `stack_a` whose `since_commit`/`until_commit` range includes `commit_a` (so `commit_a.active?` is true).
4. Assert baseline: `commit_a.status.state != 'success'` (or whatever forged value) — LHS (`commit_a`'s real status) equals RHS (state actually produced by stack A's own CI).
5. Build a status payload with `repository.full_name = 'attacker/fork'`, `sha: 'deadbeef...'`, `state: 'success'`, and call `Shipit::Webhooks::Handlers::StatusHandler.call(payload)`.
6. Reload `commit_a` and assert `commit_a.status.state == 'success'` — showing the LHS (stack A's consulted status) now equals a value sourced from stack B's payload, i.e. the equality `commit.stack.github_repo_name == payload['repository']['full_name']` was never enforced and the binding is broken, while `commit_a.active?` remains true throughout (confirming the corruption happened during the in-flight task window).

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L221-225)
```ruby
    def active?
      return false unless stack.active_task?

      stack.active_task.includes_commit?(self)
    end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
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

**File:** app/models/shipit/task.rb (L420-428)
```ruby
    def includes_commit?(commit)
      return false unless commit_range?

      if since_commit == until_commit
        commit.id == since_commit.id
      else
        commit.id > since_commit.id && commit.id <= until_commit.id
      end
    end
```
