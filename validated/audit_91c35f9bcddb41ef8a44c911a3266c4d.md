### Title
`StatusHandler#process` matches statuses to commits by SHA alone across all stacks/repositories, letting a status webhook from an unrelated (attacker-owned) repository trigger a deploy on a victim stack - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` resolves target commits with `Commit.where(sha: params.sha)` with no check that the webhook's `repository`/`organization` field matches the `stack.repository` that owns that commit. Combined with `verify_signature` in `WebhooksController`, which verifies the payload only against the GitHub App belonging to the *payload's own* `repository_owner`, an attacker who controls a distinct, validly configured GitHub App/org can send a self-signed `status` webhook naming any known commit SHA and have `Shipit::Status` rows attached to a victim's `Commit`/`Stack`, which can trigger `Stack#trigger_continuous_delivery` and an unauthorized deploy.

### Finding Description
The broken binding is: `Status.stack_id == Stack.find(Status.stack_id).repository == webhook.payload["repository"]["full_name"]`. This should hold (a Status attributed to a stack must have originated from that stack's own repository), but nothing in the code enforces it.

Trace:
1. `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) computes `repository_owner` purely from the attacker-controlled payload (`params.dig('repository','owner','login')`) and calls `Shipit.github(organization: repository_owner)` to verify the HMAC signature. If the attacker owns a distinct, validly configured GitHub App for their own org, this succeeds using the attacker's own legitimate webhook secret - it proves nothing about which Shipit stack the SHA belongs to, only that the payload was signed by *some* configured app.
2. `Shipit::Webhooks::Handlers::StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
```
This looks up commits **only by `sha`**, globally across all stacks, with no comparison of `params.dig('repository','full_name')` (or owner) against `commit.stack.repository`.
3. `Commit#create_status_from_github!` (`app/models/shipit/commit.rb:165-169`) creates the `Status` using the commit's own `stack_id` (`statuses.replicate_from_github!(stack_id, github_status)`), i.e., the **victim's** stack, not any stack derived from the attacker's payload.
4. `Status` creation triggers `after_commit :schedule_continuous_delivery` (`app/models/shipit/status.rb:19,42-44`), which eventually calls `Stack#trigger_continuous_delivery` → `next_commit_to_deploy` → `deployable_commits` (`app/models/shipit/stack.rb:210-243`), which only checks the commit's `Status`/`CheckRun` state, not their provenance, before calling `trigger_deploy(commit, Shipit.user, ...)`.

Since a SHA is a globally-unique 40-hex identifier, and the victim's pending commit's SHA is publicly visible in Shipit's UI/API (per the stated precondition), the attacker does not need push access, org membership, or knowledge of the victim's webhook secret - only their own independently valid GitHub App/org configuration reachable through `Shipit.github(organization: ...)`. The `Commit.where(sha: ...)` lookup will match the victim's existing `Commit` row (created earlier via a legitimate push/sync), and the forged `context`/`state: 'success'` status gets attached to it as if it came from the victim's own CI.

None of the existing guards close this gap: `verify_signature` only proves the payload was signed by *an* app, not that its repository matches the target stack's repository; `drop_unhandled_event` only checks the event type is registered; `ExplicitParameters` (`StatusHandler.params`) validates payload shape, not repository identity; there is no `require_permission!`/`User#authorized?`/team check on webhook processing at all, since webhooks are inherently unauthenticated w.r.t. Shipit users.

### Impact Explanation
An attacker can inject a forged "success" CI status onto an arbitrary victim `Commit`/`Stack` they do not own, using only their own GitHub App credentials, causing `Stack#trigger_continuous_delivery` to deploy attacker-chosen commit content (assuming the victim stack already contains that commit, e.g. from an accepted PR awaiting real CI) using the victim's `Command`/`PTY.spawn` execution and the victim's `GITHUB_TOKEN`. This is a cross-repository authorization bypass leading to an unauthorized deploy - matching the "Critical: a payload for one repository mutating another's stack/commit/task... unauthorized deploy" category. It is repeatable against any stack configured with `continuous_deployment: true` for which the attacker can learn a pending commit's SHA (readable via public Shipit UI/API), and is not limited to a single victim - any stack is reachable this way as long as the SHA collision (same-SHA commit already tracked by that stack) exists.

### Likelihood Explanation
Preconditions are modest: the victim stack must have `continuous_deployment: true` and required CI contexts satisfiable by a single fabricated status (or the last missing one); the attacker needs their own independently configured GitHub App/org known to `Shipit.github`, and needs to learn the victim's pending commit's SHA (stated as discoverable from public UI/API). No secrets, no team membership, and no privileged role are required - only sending a normal, correctly-signed webhook for the attacker's own org with a `repository` field left as-is (their own) while a `sha` field they don't own. This is directly reachable via `POST /webhooks` and is inexpensive and repeatable.

### Recommendation
In `StatusHandler#process` (and analogously any handler that resolves records by SHA/id without checking the payload's repository), scope the commit lookup to the correct stack, e.g.:
```ruby
Commit.joins(:stack).merge(Stack.where(repository: Repository.from_github_payload(params))).where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
```
Concretely, resolve the `repository`/`organization` in the payload to a canonical repo identity (owner/name) and require `commit.stack.repository == payload_repository` before calling `create_status_from_github!`, discarding non-matching commits.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb` or `test/models/commits_test.rb`), no live GitHub:
1. Create `victim_stack` (fixture `shipit_stacks(:shipit)`) with `continuous_deployment: true` and a `Commit` (`victim_commit`) with a known `sha`.
2. Stub `GithubHook`/`verify_signature` (as existing tests do) to simulate a validly signed payload from a **different** organization/app (e.g., `Shipit.github(organization: 'attacker-org')`).
3. POST a `status` webhook payload with `sha: victim_commit.sha`, `state: 'success'`, `context:` matching victim's required CI, and `repository.full_name` set to `attacker-org/attacker-repo` (unrelated to `victim_stack.repository`).
4. Assert:
   - `victim_commit.statuses.count` increased by 1 (Status attached despite mismatched repository) - proving one side of the equality (`Status.stack_id == victim_stack.id`) while the other side (`payload.repository.full_name == victim_stack.repository`) is false.
   - Stub `Command`/`PTY.spawn` (Mocha) and assert `Stack#trigger_continuous_delivery`/`trigger_deploy` is invoked for `victim_stack` with the victim's `GITHUB_TOKEN` env, triggered solely by the forged cross-repo status webhook. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

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

**File:** app/models/shipit/status.rb (L18-44)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

    delegate :broadcast_update, to: :commit

    class << self
      def replicate_from_github!(stack_id, github_status)
        find_or_create_by!(
          stack_id:,
          state: github_status.state,
          description: github_status.description,
          target_url: github_status.target_url,
          context: github_status.context,
          created_at: github_status.created_at
        )
      end
    end

    private

    def enable_ci_on_stack
      commit.stack.enable_ci!
    end

    def schedule_continuous_delivery
      commit.schedule_continuous_delivery
    end
```

**File:** app/models/shipit/stack.rb (L210-243)
```ruby
    def trigger_continuous_delivery
      return if cached_deploy_spec.blank?

      commit = next_commit_to_deploy

      if should_resume_continuous_delivery?(commit)
        continuous_delivery_resumed!
        return
      end

      if should_delay_continuous_delivery?(commit)
        continuous_delivery_delayed!
        return
      end

      begin
        trigger_deploy(commit, Shipit.user, env: cached_deploy_spec.default_deploy_env)
      rescue Task::ConcurrentTaskRunning
      end
    end

    def schedule_merges
      ProcessMergeRequestsJob.perform_later(self)
    end

    def next_commit_to_deploy
      commits_to_deploy = commits.order(id: :asc).newer_than(last_deployed_commit).reachable.preload(:statuses)
      if maximum_commits_per_deploy
        commits_with_max_applied = commits_to_deploy.limit(maximum_commits_per_deploy)
        deployable_commits(commits_with_max_applied) || deployable_commits(commits_to_deploy)
      else
        deployable_commits(commits_to_deploy)
      end
    end
```
