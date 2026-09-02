### Title
`StatusHandler#process` matches Statuses by `sha` alone, applying a cross-repo webhook to any Stack's Commit with the same SHA, firing that victim Stack's `Hook.emit(:commit_status/:deployable_status)` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits with `Commit.where(sha: params.sha)` without scoping to the repository named in the webhook payload, unlike every sibling handler (`PushHandler`, `CheckSuiteHandler`) which scope via the base class's `stacks` helper (`Repository.from_github_repo_name(repository_name)`). A signature-verified `status` webhook for repository A therefore updates and fires hooks for *any* Stack whose tracked `Commit.sha` happens to match, including Stacks belonging to a different repository/org entirely. [1](#0-0) [2](#0-1) 

### Finding Description
The intended binding is: `Stack.firing_hooks == Stack.owning(payload['repository']['full_name'])`, i.e. only the Stack(s) tracking the repository named in and authenticated by the webhook should have their Hooks fire.

Tracing the path:
- `WebhooksController#verify_signature` authenticates the payload against `Shipit.github(organization: repository_owner).verify_webhook_signature`, keyed only on `repository_owner` (the org from `payload['repository']['owner']['login']`), not on the specific repository or Stack. [3](#0-2) 
- `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches to `StatusHandler.call(params)` → `new(params).process`. [4](#0-3) 
- Every other handler (`PushHandler`, `CheckSuiteHandler`) restricts its query to the Stacks of the repository named in the payload via the `Handler#stacks` helper, which resolves `Repository.from_github_repo_name(repository_name)` where `repository_name = payload.dig('repository', 'full_name')`. [2](#0-1) [5](#0-4) [6](#0-5) 
- `StatusHandler#process`, however, does **not** use `stacks`/`repository_name` at all - it runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`, a global, unscoped lookup across every Stack in the installation. [1](#0-0) 
- `create_status_from_github!` calls the private `add_status`, which creates a `Status` row and, on a state transition, fires `Hook.emit(:commit_status, stack, ...)` and `Hook.emit(:deployable_status, stack, ...)` for `commit.stack` - the Stack that owns the matched Commit row, not necessarily the Stack tied to the repository that sent the webhook. [7](#0-6) [8](#0-7) 
- `Commit.sha` is indexed/scoped per `(stack_id, sha)` (`db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb`), i.e. Shipit itself expects the *same* SHA to legitimately exist under multiple different Stacks (e.g. Stacks tracking forks, mirrors, or renamed/duplicated repos of the same upstream history), since git SHAs are content-addressed and identical across forks that share history.

Exploit flow: attacker owns/controls a GitHub repository (a fork, or any repo) on which they can install/trigger the same GitHub App/webhook integration Shipit listens to, and whose commit history intersects with a victim Stack's tracked repository (trivially true for any public fork - forked commits retain identical SHA1 to the upstream repo). The attacker sets a commit status (via the GitHub API, which they can do on their own repository) on a commit SHA that is shared with the victim's tracked history. GitHub delivers a genuinely signed `status` webhook to Shipit for the attacker's own repository/org. `verify_signature` passes because it only checks the org-level `webhook_secret`, and `StatusHandler#process` finds and updates the victim's `Commit` row purely by SHA match, triggering `Hook.emit(:commit_status/:deployable_status, victim_stack, payload)` on the victim's configured outbound Hook.

Existing guards (`verify_signature`, `drop_unhandled_event`, `ExplicitParameters` schema) only validate that *some* org's webhook signature is correct and that required params exist; none of them validate that the resolved `Commit`/`Stack` in `StatusHandler#process` actually belongs to the repository named in that same payload. This is the specific omission relative to the pattern used by `PushHandler`/`CheckSuiteHandler`.

### Impact Explanation
An attacker can cause a victim Stack's outbound Hook (Slack, generic webhook, etc.) configured for `commit_status`/`deploy_status` events to fire with the victim's commit's `message`/`description`/`target_url`/`state`, without ever authenticating against the victim's repository or webhook secret - only the attacker's own org's signature is required. This is an unauthorized cross-tenant write (`Status` record created on a Commit belonging to a repository/stack the attacker never authenticated for) and a data-exposure vector (hook payload data about the victim's commit reaching an endpoint the attacker did not control triggering, but whose firing/timing/content the attacker now controls). It also can trigger `stack.schedule_merges` on the victim Stack when the injected status is `pending`/`success`, potentially influencing the victim's merge queue processing. This matches "a payload for one repository mutating another's stack, commit ... or an unauthorized deploy/merge" (Critical) in the case of `schedule_merges` interaction, and at minimum a High-severity unauthorized cross-tenant state mutation / hook trigger.

### Likelihood Explanation
Preconditions: (1) victim Stack has Hooks configured for `commit_status`/`deployable_status`/`deploy_status`; (2) a `Commit` with a matching `sha` exists under the victim Stack - trivially satisfiable when the victim tracks a public repository, since any fork or mirror shares identical commit SHAs for the same history; (3) the attacker can send a real signed `status` event for their own org (they own a repo, install/trigger the integration, and call GitHub's status API on their own commit). No Shipit secrets, sessions, or team membership are required - only ordinary GitHub repository ownership by the attacker. This is realistically feasible and repeatable against any victim Stack tracking a public/forkable repository whose commit SHAs are known (all of them, since SHAs are visible in `git log`/GitHub UI).

### Recommendation
Scope `StatusHandler#process` (and `Commit.create_status_from_github!`) to the repository named in the payload, matching the pattern used by `PushHandler`/`CheckSuiteHandler`: resolve `stacks` via `Repository.from_github_repo_name(repository_name)` first, then only update/emit hooks for `Commit` rows under those specific Stacks, e.g. `stacks.each { |stack| stack.commits.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) } }` instead of the unscoped `Commit.where(sha: params.sha)`.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (conceptual, would need Handler/Stack setup helpers)
test "a status webhook for repository A does not fire hooks on Stack B's commit with the same sha" do
  attacker_stack = shipit_stacks(:attacker_repo_stack)   # tracks org "attacker/attacker-repo"
  victim_stack   = shipit_stacks(:victim_repo_stack)     # tracks org "victim/victim-repo", has hooks for :deploy_status
  shared_sha = "deadbeef" * 5

  victim_commit = victim_stack.commits.create!(sha: shared_sha, ...)
  # No commit exists for attacker_stack with this sha (attacker forged/coincided sha only in payload, not tracked)

  request.headers['X-Github-Event'] = 'status'
  body = {
    'sha' => shared_sha,
    'state' => 'success',
    'context' => 'ci/travis',
    'repository' => { 'full_name' => 'attacker/attacker-repo', 'owner' => { 'login' => 'attacker' } }
  }.to_json

  # signed correctly for org "attacker" per verify_webhook_signature

  expect_no_hook(:deployable_status) do
    post :create, body:, as: :json
  end
  # Currently FAILS: victim_commit is matched via Commit.where(sha: shared_sha)
  # and victim_stack's Hook.emit(:deployable_status, victim_stack, ...) fires,
  # even though the signed payload only authenticates repository "attacker/attacker-repo".
end
```
This demonstrates the equality `Stack.firing_hooks == Stack.owning(payload['repository']['full_name'])` does not hold: the victim Stack (not owning the authenticated repository) fires its Hook solely because of a matching global `sha`.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
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

**File:** app/models/shipit/commit.rb (L366-384)
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
```
