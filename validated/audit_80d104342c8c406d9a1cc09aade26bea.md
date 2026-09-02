### Title
`StatusHandler#process` binds `Status` to the wrong stack because `Commit.where(sha:)` is not scoped to the webhook's own repository - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits purely by `sha`, across all stacks in the installation, and never checks that the resolved `Commit#stack_id` corresponds to the `repository.full_name` named in the verified webhook payload. `Status#stack_id` is then set from `commit.stack_id` (correct relative to the commit, but not to the payload), so a `status` event legitimately signed for repository A can write a `Status` — and thus flip `Commit#deployable?` and trigger `Stack#trigger_continuous_delivery` — for a commit that actually belongs to stack B, whenever the two repositories share a commit SHA (e.g., a public fork of the target repo).

### Finding Description
Binding claimed safe: `Status#stack_id (== commit.stack_id) == the stack actually named in the verified webhook payload (repository.full_name)`. This binding is **not** enforced.

- Every other event handler scopes lookups by the payload's own repository via `Handler#stacks`, e.g. `PushHandler#process` uses `stacks.not_archived.where(branch:)` [1](#0-0)  where `stacks` is derived from `Repository.from_github_repo_name(repository_name)` [2](#0-1) .
- `StatusHandler#process`, however, does not use `stacks` at all: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [3](#0-2) . This is a global, cross-stack, cross-repository lookup keyed only on `sha`.
- `Commit#create_status_from_github!` then writes `statuses.replicate_from_github!(stack_id, github_status)` using **the found commit's own `stack_id`** [4](#0-3) , and `Status.replicate_from_github!` persists that `stack_id` verbatim [5](#0-4) .

So `Status#stack_id` always equals `commit.stack_id` (that part of the binding the question describes is intact), but nothing ever checks that `commit.stack_id`'s repository matches `repository.full_name` from the payload that was actually signed and verified. `verify_signature` in `WebhooksController` only checks the HMAC against the secret for `Shipit.github(organization: repository_owner)` [6](#0-5)  — it authenticates that the payload came from GitHub for that installation/org, it does not verify that the `sha` inside the payload belongs to that same repository.

**Exploit flow (unprivileged attacker):**
1. Attacker forks (or otherwise obtains a repository sharing history with) the victim's target repository `victim/app`, which is already tracked as a Shipit stack. Forked commits retain identical SHA-1s to the upstream commits (git content-addressing), including any commit the victim stack has already synced.
2. Attacker's fork is configured to send webhooks to the same Shipit instance (this only requires the attacker to control a repo whose organization/owner is a valid `Shipit.github(organization:)` entry — the webhook HMAC secret is per-app-installation, not per-repository, so a validly signed `status` event can be produced for the attacker's own fork).
3. Attacker sends (or triggers, e.g., via their own CI or a manual `POST /repos/attacker/app-fork/statuses/{shared_sha}`) a `status` webhook with `sha` = the shared commit SHA and `state: "success"`, `repository.full_name: "attacker/app-fork"`.
4. `verify_signature` passes (correctly signed for `attacker/app-fork`'s owner/installation).
5. `StatusHandler#process` finds `Commit` rows with that `sha` in **any** stack, including `victim/app`'s stack, and calls `create_status_from_github!`, writing a `Status` with `stack_id = victim_stack.id`, `state: "success"`.
6. `Status#after_commit :schedule_continuous_delivery` calls `commit.schedule_continuous_delivery` [7](#0-6) , which checks `deployable? && stack.continuous_deployment? && stack.deployable?` and enqueues `ContinuousDeliveryJob` [8](#0-7) .
7. `ContinuousDeliveryJob#perform` calls `stack.trigger_continuous_delivery`, which relies on `next_commit_to_deploy` / `deployable_commits`, which in turn consult the commit's `status` (an aggregate of `statuses`) — the forged status now counts toward marking the victim's commit deployable [9](#0-8) .

`Stack#trigger_continuous_delivery` itself performs no re-check of the origin of the `Status` records feeding `deployable?`; it trusts the aggregated `Commit#status`/`statuses` state entirely, which was writable by an attacker who never authenticated against the victim's repository.

Why existing guards don't catch this: `verify_signature` authenticates the sender's installation/org, not that the `sha` in the payload actually resides in the sender's own repository; `drop_unhandled_event` only checks the event type is registered; the `ExplicitParameters` schema for `StatusHandler` only validates types/presence of `sha`/`state`, not repository ownership; there is no `stacks`-scoped filter analogous to `PushHandler` in `StatusHandler`.

### Impact Explanation
An attacker who owns any repository/fork sharing commit history with a victim repository can inject arbitrary CI status states (`success`, `failure`, `error`, `pending`) onto the victim's tracked commits without any Shipit credentials, session, or victim-repo permission. If `success` is injected on a commit that otherwise satisfies other deployability constraints (unlocked stack, no active task, deployment checks passed), this can cause `Stack#trigger_continuous_delivery` to autonomously trigger a deploy of that commit — an unauthorized deploy driven by a payload belonging to a different repository. This matches the Critical category: "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy." It is repeatable against any stack whose repository has been forked (or otherwise shares commit SHAs with an attacker-controlled repo), and the same technique also pollutes `commit.state`/CI status visible in the UI even where it doesn't trigger an automatic deploy.

### Likelihood Explanation
Preconditions: the victim repository must be forkable/public (typical for open-source Shipit-tracked repos) so an attacker can obtain identical commit SHAs; the attacker needs a GitHub repo capable of emitting a correctly-signed `status` webhook to the Shipit instance (installing the same GitHub App or webhook config used by Shipit on their own repo — a routine, self-service action for any GitHub user, not requiring victim's or operator's secrets). No Shipit session, API token, or team membership is needed. The attack is inexpensive (a few HTTP requests) and repeatable at will against any stack sharing history with an attacker-accessible repo, making it feasible for a broad attacker population.

### Recommendation
In `StatusHandler#process`, scope the commit lookup to the webhook's own repository the same way `PushHandler` does, e.g. only look up commits within `stacks` (derived from `repository_name`) instead of a global `Commit.where(sha:)`:
```ruby
def process
  stacks.find_each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
This ensures `Status#stack_id` is bound to the stack actually named (and cryptographically vouched for) in the verified payload, not merely to whatever stack happens to own a commit with a colliding SHA.

### Proof of Concept
Minitest plan (no live GitHub, following the pattern used by `test/controllers/webhooks_controller_test.rb`):
```ruby
test ":status from an unrelated forked repository writes a Status onto a different stack's commit" do
  victim_stack  = shipit_stacks(:shipit)          # e.g. repo "shopify/shipit-engine"
  victim_commit = shipit_commits(:first)
  victim_commit.update!(stack_id: victim_stack.id)

  # Simulate: attacker's fork shares the same commit sha as victim_commit.
  request.headers['X-Github-Event'] = 'status'
  GithubHook.any_instance.stubs(:verify_signature).returns(true) # signature legitimately verifies for attacker's own repo

  forged_payload = JSON.parse(payload(:status_master)).merge(
    'sha' => victim_commit.sha,
    'state' => 'success'
  )
  forged_payload['repository']['full_name'] = 'attacker/forked-repo'
  forged_payload['repository']['owner']['login'] = 'attacker'

  assert_difference 'victim_commit.statuses.count', 1 do
    post :create, body: forged_payload.to_json, as: :json
  end

  status = victim_commit.statuses.last
  # Binding check: Status.stack_id equals commit.stack_id (victim), NOT the repo named in the payload.
  assert_equal victim_commit.stack_id, status.stack_id
  refute_equal 'attacker/forked-repo', victim_stack.repository.full_name
  # Demonstrates the gap: nothing verified that victim_stack's repository == forged_payload['repository']['full_name']
end
```
This proves `Status.stack_id` derives solely from the pre-existing `Commit#stack_id` looked up by bare `sha`, with no cross-check against the repository actually named (and signed) in the incoming webhook — the binding gap sits at the `Commit.where(sha:)` lookup in `StatusHandler#process`, not at `Status` creation.

### Citations

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
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

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```

**File:** app/models/shipit/status.rb (L24-33)
```ruby
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
