### Title
`StatusHandler#process` writes commit statuses without verifying the webhook's repository owns the commit, enabling cross-repo forged-status deploys - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits purely by `sha` across the entire installation and calls `commit.create_status_from_github!(params)` on every match, with no check that the commit's owning stack/repository matches the webhook's `repository.full_name`. Any attacker who controls a repository sharing commit history with a victim's tracked repo (e.g. a public fork, which is exactly the "repository they own" precondition) can send a genuinely-signed GitHub status webhook from their own repo and have it written as a `Status` on the victim stack's commit, flipping `Commit#deployable?` and letting `trigger_continuous_delivery` deploy it.

### Finding Description
Binding claimed: `Status` rows consumed by `Commit#deployable?` for stack `S` must satisfy `status.payload.repository.full_name == S.repository.full_name`.

Actual code: [1](#0-0) 
`process` does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — it never consults `payload.dig('repository', 'full_name')` or restricts to commits owned by that repository. Compare this to the base `Handler` class, which does provide a `stacks`/`repository_name` scoping helper used by essentially every other handler: [2](#0-1) 
`StatusHandler` simply doesn't use it.

`create_status_from_github!` then persists the status under the target commit's own `stack_id`, not the webhook's origin stack: [3](#0-2) 
and `Status#state`/`Commit#deployable?` is computed purely from these rows: [4](#0-3) 

Attacker flow: fork the victim's tracked repository (any public repo on GitHub can be forked by anyone; a fork shares identical SHA1 commit objects with the upstream for any un-rewritten commit). The attacker's fork is a distinct GitHub repository they fully control and can install the Shipit GitHub App/webhook on. They send (or GitHub sends, driven by the attacker calling the real GitHub Status API on their own fork) a `status` event whose `repository.full_name` is the attacker's own fork, but whose `sha` equals a commit that is also tracked as a `Commit` row in the victim's Shipit stack (inherited from the shared git history). `WebhooksController#verify_signature` only checks that the payload is validly signed for `repository_owner` (the attacker's own org/login) — it says nothing about whether the `sha` inside belongs to that repo: [5](#0-4) 
This check passes legitimately because the event genuinely originates from GitHub for the attacker's own repository. `StatusHandler#process` then matches the shared `sha` against `Commit` rows belonging to the victim's stack and writes a `success` status there.

That status write triggers `Status#schedule_continuous_delivery` → `Commit#schedule_continuous_delivery`, which enqueues `ContinuousDeliveryJob` once `deployable?` and `stack.continuous_deployment?` and `stack.deployable?` all hold: [6](#0-5) 
and `Stack#trigger_continuous_delivery` selects `next_commit_to_deploy`/`next_expected_commit_to_deploy`, both of which rely solely on `Commit#deployable?`: [7](#0-6) [8](#0-7) 
No code path re-validates that the `Status` rows feeding `deployable?` originated from a webhook naming the stack's own repository. The race window described (forging a status in the gap between `deployed_too_recently?` evaluation and `trigger_deploy`) is not even required — the forged status is durably persisted the moment the webhook is processed, so it simply needs to land before any subsequent `trigger_continuous_delivery`/`ProcessMergeRequestsJob` run (which happens continuously), making the "race" merely a timing convenience, not a hard requirement.

### Impact Explanation
An unprivileged GitHub user who owns a fork of a tracked repository can, without any Shipit credentials, cause an unauthorized deploy of a specific already-existing (shared-ancestry) commit on the victim's stack by flipping that commit's CI status to `success` via a webhook whose declared repository is their own fork. This is a "payload for one repository mutating another's stack/commit" and "unauthorized deploy" — matching the Critical impact category. It's repeatable against any Shipit-tracked repository that has (or ever had) a public fork, i.e., broadly applicable across tenants of a multi-tenant Shipit instance.

### Likelihood Explanation
Preconditions: the victim's repository must be forkable/forked by the attacker (default GitHub behavior for public repos), the shared commit must already be pulled into the victim stack's `commits` table (normal for any commit reachable from the tracked branch), and the Shipit GitHub App/webhook integration must be configured to receive status events from the attacker's fork (typically automatic if the app is installed org/account-wide or if the fork owner installs the app themselves on their own account, which requires no privilege over the victim). Attacker cost is minimal (fork + `POST` a commit status through the real GitHub API on their own repo, or directly to the Shipit webhook endpoint with a validly-signed payload for their own org). This is fully repeatable and does not require any Shipit secrets.

### Recommendation
In `StatusHandler#process`, scope the commit lookup to the repository named in the payload, mirroring the base `Handler#stacks` helper, e.g. restrict to `Commit.joins(stack: :repository).where(sha: params.sha, shipit_repositories: { id: repository.id })` (or equivalent), so a status can only be applied to commits belonging to stacks whose repository matches `payload.dig('repository', 'full_name')`.

### Proof of Concept
```ruby
# test/models/webhooks/status_handler_test.rb (conceptual)
test "process does not apply a status to a commit belonging to another repository" do
  victim_repo = shipit_repositories(:shipit)         # e.g. "shopify/shipit-engine"
  victim_stack = shipit_stacks(:shipit)
  shared_sha = "deadbeef" * 5

  victim_commit = victim_stack.commits.create!(sha: shared_sha, message: "shared", author: shipit_users(:walrus), authored_at: Time.now, committer: shipit_users(:walrus), committed_at: Time.now)
  refute_predicate victim_commit, :deployable?

  # Attacker's own fork repository/stack, unrelated ownership
  attacker_payload = {
    'sha' => shared_sha,
    'state' => 'success',
    'context' => 'ci/travis',
    'repository' => { 'full_name' => 'attacker/shipit-engine-fork', 'owner' => { 'login' => 'attacker' } }
  }

  assert_no_difference -> { victim_commit.statuses.count } do
    Shipit::Webhooks::Handlers::StatusHandler.call(attacker_payload)
  end

  refute_predicate victim_commit.reload, :deployable?
end
```
Under current code, `Commit.where(sha: shared_sha)` matches `victim_commit` regardless of `attacker_payload['repository']`, so the `assert_no_difference` and `refute_predicate` fail — demonstrating the forged cross-repo status is applied and flips `deployable?`, which can then be chained with `victim_stack.trigger_continuous_delivery` to assert `Deploy.count` increases for a commit the victim repository never actually validated.

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

**File:** app/models/shipit/stack.rb (L235-243)
```ruby
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
