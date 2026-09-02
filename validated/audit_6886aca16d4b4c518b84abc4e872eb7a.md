### Title
Cross-repository status write via unscoped `Commit.where(sha:)` lookup - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` resolves target commits with `Commit.where(sha: params.sha)`, a query that spans every stack/repository in the database, and writes `create_status_from_github!` to all matches. `WebhooksController#verify_signature` only authenticates that the payload originated from *a* known GitHub organization (`repository_owner`), not that it belongs to the specific stack whose commit it is about to mutate, so a status event legitimately signed for one repository can flip the CI state of a commit belonging to a completely different (production) stack whenever the two share the same commit SHA.

### Finding Description
The broken binding the code implicitly assumes is: `params.dig('repository','full_name') == commit.stack.repository.full_name` for every `commit` returned by `Commit.where(sha: params.sha)`. That equality is never checked.

Path:
- `Shipit::WebhooksController#create` parses the JSON body and dispatches to `Shipit::Webhooks.for_event(event)` handlers after `verify_signature` [1](#0-0) .
- `verify_signature` derives `repository_owner` from `params.dig('repository','owner','login')` and validates the HMAC against `Shipit.github(organization: repository_owner)`'s secret [2](#0-1) . This only proves the request came from *some* repo under that GitHub organization/app config — it does not bind the payload to a specific repository, and it is entirely orthogonal to the `sha` field's ownership.
- `StatusHandler#process` then does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [3](#0-2) 
This query is a bare `sha` match with no `stack_id`/repository filter, so it returns every `Commit` row across every stack in the installation that happens to share that SHA.
- `create_status_from_github!` → `add_status` replicates the GitHub status, recomputes `status`, and — on a state transition to success/pending — calls `stack.schedule_merges` and, via `after_commit`, `schedule_continuous_delivery`, which enqueues `ContinuousDeliveryJob` when `deployable? && stack.continuous_deployment? && stack.deployable?` [4](#0-3) [5](#0-4) .
- `deployable?` becomes true once the aggregated `status` (built from `statuses_and_check_runs` via `Status::Group`) reports `success?` and the commit is not `blocked?` [6](#0-5) .

Exploit flow: git commit SHA1 is a hash of tree, parents, author/committer, timestamps and message — fully content-addressed. If a victim's production stack repository is public (or its commit is otherwise observable), an attacker can reconstruct a commit object with byte-identical metadata in a repository they control (their own fork/org), producing the *same SHA* as the victim's commit. GitHub then legitimately signs and delivers a `status` webhook (`context: ci/kubernetes`, `state: success`) for the attacker's own repository/organization. That webhook passes `verify_signature` because it is authentic for the attacker's org. `StatusHandler#process`, however, matches `Commit.where(sha: ...)` against the whole table and updates the victim's commit's status too, potentially flipping `deployable?` on the victim's production stack and triggering continuous delivery, or, if `ci/kubernetes` is in `blocking_statuses`, blocking merges/deploys.

None of the existing guards catch this: `verify_signature` checks organization-level HMAC, not per-repository binding of the `sha`; `drop_unhandled_event` only filters unknown event types; the `ExplicitParameters` schema (`params.sha`, `params.context`, `params.state`) validates types, not ownership; there is no `Repository` format check or `stacks` scope applied in `StatusHandler#process`. The comparable handlers (`by_sha`/`by_sha!` on `Commit`) exist elsewhere in the model but `StatusHandler` deliberately uses the unscoped `where(sha:)`, and no repository join/filter (e.g. `joins(:stack).merge(Stack.where(repository: ...))`) is present.

### Impact Explanation
A successfully forged/collided SHA lets an attacker mutate the CI status of a commit belonging to a stack they never authenticated for — a payload for one repository mutating another's commit/stack. If that stack is a production environment relying on `ci/kubernetes` as a required or blocking status, the attacker can force `deployable?` to flip to `true` (triggering an unauthorized deploy via `schedule_continuous_delivery`/`ContinuousDeliveryJob`) or to `false`/blocking (denial of legitimate deploys/merges). This is repeatable against any stack whose repository's commits are observable/reconstructible by the attacker, and the blast radius spans every stack in the Shipit installation, not just the attacker's own repository — matching the Critical "a payload for one repository mutating another's stack, commit, task or team" / "unauthorized deploy" category.

### Likelihood Explanation
Preconditions: the attacker needs (a) a GitHub repository/org they control to receive authenticated webhooks, and (b) the ability to produce a commit object with byte-identical SHA to a commit in the target stack — feasible when the victim commit's content (tree, parents, author/committer, timestamps, message) is knowable, e.g. public repositories, shared upstream history, or cherry-picked/rebased commits. No Shipit secrets, sessions, or API tokens are required; only genuine GitHub webhook delivery for a repo the attacker owns. This raises the bar above trivial but remains within reach for attackers targeting specific, observable victim commits, and it is repeatable for any matching SHA.

### Recommendation
Scope the commit lookup in `StatusHandler#process` (and by extension any other handler using bare `Commit.where(sha:)`) to the repository that authenticated the webhook, e.g. join through `stack` and filter by `params.dig('repository','full_name')` (or organization+name) before applying `create_status_from_github!`, mirroring the repository-bound resolution already used elsewhere (`Commit.by_sha`/`by_sha!` scoped per stack).

### Proof of Concept
Minitest plan (no live GitHub):
1. Create `stack_a` (attacker's repo, e.g. `attacker/repo`) and `stack_b` (victim's production stack, `environment: 'production'`, with `ci/kubernetes` configured as a required/blocking status).
2. Create `commit_a = shipit_commits(:stack_a, sha: 'deadbeef...')` and `commit_b = shipit_commits(:stack_b, sha: 'deadbeef...')` with the same SHA but belonging to different stacks.
3. Assert baseline: `commit_b.deployable?` is `false` (no successful `ci/kubernetes` status yet). This is the equality to test: `commit_a.stack_id != commit_b.stack_id` while `commit_a.sha == commit_b.sha`.
4. Build a `status` webhook payload for `stack_a`'s repository with `sha: 'deadbeef...'`, `context: 'ci/kubernetes'`, `state: 'success'`.
5. Call `Shipit::Webhooks::Handlers::StatusHandler.new(params).process` (or POST through `WebhooksController` with a valid signature for `stack_a`'s org) directly.
6. Assert `commit_b.reload.deployable?` is now `true` (or, for a blocking-status variant, that `commit_b.blocked?`/downstream commits are now blocked) — demonstrating the victim stack's commit state was mutated by a webhook authenticated only for the attacker's repository.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
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
