### Title
Cross-repository status forgery via unscoped `Commit.where(sha:)` lookup enables unauthorized deploy trigger - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits to attach a GitHub `status` webhook to using `Commit.where(sha: params.sha)` with no repository scoping, unlike every other handler (`PushHandler`, `CheckSuiteHandler`) which resolve `stacks` from `Repository.from_github_repo_name(payload.repository.full_name)` first. Because the `commits` table only enforces uniqueness on the compound key `(sha, stack_id)`, not `sha` alone, a real, correctly-signed webhook for a repository the attacker controls can attach a forged `success` status to a commit row belonging to a completely different victim stack whenever the two repositories share a commit sha (e.g. via a fork's shared ancestry). This satisfies `commit.deployable?` for the victim stack and, per the question's traced path, none of `Stack#should_delay_continuous_delivery?` / `should_resume_continuous_delivery?` detect the forged origin, so `trigger_continuous_delivery` proceeds to `trigger_deploy`.

### Finding Description
The broken binding: the code assumes
`Commit.where(sha: params.sha) == commits(Repository.from_github_repo_name(payload['repository']['full_name']))`
but in fact `Commit.where(sha: params.sha)` returns every commit row across **every** stack that happens to share that sha, since the DB index is unique on `(sha, stack_id)` [1](#0-0) , not on `sha` alone.

`StatusHandler#process` never calls the `stacks` helper (which resolves the repository from the webhook payload) that `PushHandler` and `CheckSuiteHandler` both use to scope their side effects: [2](#0-1) 
Compare with the scoped handlers: [3](#0-2) [4](#0-3) 
and the base `Handler#stacks` method that exists precisely for this scoping but goes unused here: [5](#0-4) 

Webhook signature verification (`WebhooksController#verify_signature`) only proves the payload was signed by the GitHub App instance for the claimed `repository_owner`; it says nothing about which repository's commit sha may be referenced, and GitHub Apps use a single webhook secret shared across all installations, so a real webhook from a repository the attacker legitimately owns/installed the app on is validly signed: [6](#0-5) 

Exploit flow:
1. Attacker forks or otherwise obtains a repository sharing a base commit sha with the victim's tracked repository (common with forks, since git preserves commit SHAs across clones), and installs/uses the GitHub integration on their own repo.
2. Attacker triggers (or fabricates, via their own real, unprivileged CI/status integration) a `status` event with `state: "success"` for that shared sha on their own repository. This webhook is correctly signed because it genuinely originates from GitHub for a repo the attacker controls.
3. `StatusHandler#process` runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — this matches the victim stack's commit row too, because it shares the sha, and creates a `Status` record with `stack_id` set to the *victim's* stack id via `commit.statuses.replicate_from_github!(stack_id, ...)` (`stack_id` is the victim commit's own `stack_id`, taken from the matched row, not from the webhook payload) [7](#0-6) .
4. This flips `commit.deployable?` to true for the victim's stack and fires `schedule_continuous_delivery`, which enqueues `ContinuousDeliveryJob` after a 10s buffer [8](#0-7) .
5. `Stack#trigger_continuous_delivery`'s guards (`should_delay_continuous_delivery?`, `should_resume_continuous_delivery?`) only check timing (`recently_pushed?`) and prior failure state (`deploy_failed?`), never the origin of the status; if the victim's real commit is older than `RECENT_COMMIT_THRESHOLD` (10s) and was never deployed/failed before, both guards evaluate false and `trigger_deploy` runs [9](#0-8) [10](#0-9) .

No existing guard catches this: `verify_signature` validates only the sender, not the sha-to-repository binding; the `ExplicitParameters` schema for `StatusHandler` only validates types of `sha`/`state`, not ownership; and `Stack`'s continuous-delivery guards are, as the question states, entirely local timing/state checks with no way to verify that the `deployable?` signal originated from the victim's own authenticated CI.

### Impact Explanation
An attacker who controls any repository sharing a commit sha with a victim's tracked repository (trivially achievable via GitHub forks) can force a `Status` record — and consequently a real `Deploy`/`Task` — to be created against the victim's stack without ever having credentials, session, or API token for the victim's Shipit instance or GitHub organization. This is a payload for one repository mutating another repository's `Stack`/`Commit`/`Task` state and triggering an unauthorized deploy, matching the Critical impact category exactly ("a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy"). It is repeatable against any stack whose tracked repository shares ancestry (a fork relationship, a common upstream, or otherwise identical commit objects) with a repository the attacker can generate real webhooks for.

### Likelihood Explanation
Preconditions: (1) the victim's Shipit `commits` table must already contain a row for the shared sha (i.e., that commit was previously synced into the victim's stack via a push/sync event — realistic for shared/common ancestor commits in forked repos or monorepo-style shared history); (2) the attacker needs a repository they control that GitHub will send correctly-signed `status` webhooks for, which is normal, unprivileged self-service (fork + install app, or a repo where the same GitHub App/CI is already active); (3) the victim commit must be older than 10 seconds and have no prior failed deploy — trivially satisfied for almost any commit that isn't brand new. No secrets (`webhook_secret`, `api_clients_secret`, GitHub tokens) are required. Attacker cost is a single legitimate webhook delivery from their own repo.

### Recommendation
Scope `StatusHandler#process` through the `stacks` helper the same way `PushHandler` and `CheckSuiteHandler` do, e.g.:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
This ensures a status webhook can only mutate commits belonging to the repository that actually sent it.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "status webhook for an unrelated repository must not update a victim stack's commit sharing the same sha" do
  victim_stack = shipit_stacks(:shipit)
  shared_sha = "deadbeef" * 5
  victim_commit = victim_stack.commits.create!(sha: shared_sha, created_at: 1.hour.ago, message: "shared ancestor")

  attacker_repo_payload = {
    'sha' => shared_sha,
    'state' => 'success',
    'context' => 'ci/attacker',
    'created_at' => Time.now.iso8601,
    'repository' => { 'full_name' => 'attacker/unrelated-repo' } # not victim_stack's repo
  }

  assert_no_difference -> { victim_commit.statuses.count } do
    Shipit::Webhooks::Handlers::StatusHandler.call(attacker_repo_payload)
  end

  refute victim_commit.reload.deployable?
end
```
Both sides of the binding to assert: `victim_commit.statuses.count` (before) `==` `victim_commit.statuses.count` (after) should hold but currently fails, and `Stack#trigger_continuous_delivery` called on `victim_stack` after the forged webhook should not create a `Deploy`/`Task`, but currently does, confirming the cross-repository authorization bypass.

### Citations

**File:** db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb (L1-5)
```ruby
class IndexCommitsOnStackIdAndSha < ActiveRecord::Migration[5.1]
  def change
    add_index :commits, %i(sha stack_id), unique: true
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```

**File:** app/models/shipit/stack.rb (L210-229)
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
```

**File:** app/models/shipit/stack.rb (L701-713)
```ruby
    def should_resume_continuous_delivery?(commit)
      (deployment_checks_passed? && !deployable?) ||
        deployed_too_recently? ||
        commit.nil? ||
        commit.deployed?
    end

    def should_delay_continuous_delivery?(commit)
      commit.deploy_failed? ||
        (checks? && !EphemeralCommitChecks.new(commit).run.success?) ||
        !deployment_checks_passed? ||
        commit.recently_pushed?
    end
```
