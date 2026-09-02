### Title
Webhook Signature Verified Against `repository.owner.login` While Handlers Act On A Different `repository.full_name` In The Same Payload - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to validate a webhook against using `repository.owner.login` (or `organization.login`) from the JSON body, while every event handler resolves the `Stack`/`Repository` to mutate using the unrelated `repository.full_name` field from the very same body. Because the HMAC only proves "this body was signed with *some* configured organization's secret," not "this body's `repository.full_name` belongs to that organization," anyone who controls a legitimately configured GitHub organization on a multi-tenant Shipit instance can forge a validly-signed webhook whose `repository.full_name` points at a completely different, unrelated repository/stack.

### Finding Description
`verify_signature` picks the verification secret like this: [1](#0-0) 

using: [2](#0-1) 

`Shipit.github(organization: repository_owner)` loads the `GithubApp`/`webhook_secret` configured for whatever organization is named in `repository.owner.login` — an attacker-controlled JSON field, not an authenticated identity. As long as the attacker owns/administers *any* GitHub organization that has been configured in Shipit's `secrets.yml` (a normal, unprivileged-relative-to-Shipit condition on any multi-tenant instance), they know that organization's real `webhook_secret` (they configured the GitHub webhook themselves) and can HMAC-sign an arbitrary raw JSON body with it.

Every default handler, however, resolves the target `Repository`/`Stack` from a *different* field of the same body — `repository.full_name` — never cross-checked against `repository.owner.login`: [3](#0-2) [4](#0-3) 

So a single crafted+signed payload can set `repository.owner.login = "attacker-org"` (satisfies signature verification against the attacker's own secret) while `repository.full_name = "victim-org/victim-repo"` (used by `Repository.from_github_repo_name` to pick the actual target stack). This breaks the equality that should hold: *the organization whose secret authenticated the request* must equal *the repository/organization being written to*.

### Impact Explanation
Via `PushHandler`, the forged webhook drives `stack.sync_github(expected_head_sha:)` on the victim stack: [5](#0-4) 

If the targeted stack has `continuous_deployment` enabled, appending new commits (fetched for real from GitHub for the victim repo) and their CI success statuses can trigger `ContinuousDeliveryJob#perform` → `stack.trigger_continuous_delivery`, which builds and enqueues a real `Deploy`: [6](#0-5) [7](#0-6) 

An attacker with no relationship to the victim repository — only ownership of some unrelated, independently-configured GitHub org on the same shared Shipit instance — can force a deploy/sync/archive/unarchive/status update on a stack they have no authorization over. This is an unauthorized deploy/action on cross-organization repository state, matching the Critical bucket ("cross-repository writes, or an unauthorized deploy, rollback or merge").

### Likelihood Explanation
Any organization admin who has configured (or convinced an operator to configure) a GitHub App/organization entry in Shipit's multi-tenant `secrets.yml` can trivially compute a valid `X-Hub-Signature` for an arbitrary payload using their own known `webhook_secret`, then simply pick any other tracked repository's `owner/name` for `repository.full_name`. No GitHub access to the victim repo, no Shipit session, and no privileged Shipit role is required — this is directly reachable through the public, unauthenticated (session-wise) `WebhooksController#create` endpoint.

### Recommendation
Verify that `repository.full_name`'s owner segment matches the `repository.owner.login`/`organization.login` used to select the webhook secret before dispatching to handlers, or, better, derive the webhook secret/org strictly from `repository.full_name` and reject payloads where these fields diverge.

### Proof of Concept
1. Attacker administers GitHub org `attacker-org`, which is configured in Shipit's `secrets.yml` with its own `webhook_secret`.
2. Attacker crafts a JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<any-sha-attacker-wants>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(attacker-org's webhook_secret, body)>` and POSTs to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-30`) looks up `Shipit.github(organization: "attacker-org")`, verifies successfully against the attacker's own secret.
5. `PushHandler.call` (`app/models/shipit/webhooks/handlers/push_handler.rb`) resolves stacks via `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `stack.sync_github(expected_head_sha: ...)` on the victim's stack — an action the attacker was never authorized to trigger.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-24)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
```

**File:** app/jobs/shipit/github_sync_job.rb (L18-49)
```ruby
    def perform(params)
      @stack = Stack.find(params[:stack_id])
      expected_head_sha = params[:expected_head_sha]
      retry_count = params[:retry_count] || 0
      head_before_sync = spec_cache_target
      appended_commits = []

      handle_github_errors do
        new_commits, shared_parent = fetch_missing_commits { stack.github_commits }

        # Retry on Github eventual consistency: webhook indicated new commits but we found none
        if expected_head_sha && new_commits.empty? && !commit_exists?(expected_head_sha) &&
           retry_count < MAX_RETRY_ATTEMPTS
          GithubSyncJob.set(wait: RETRY_DELAY * retry_count).perform_later(params.merge(retry_count: retry_count + 1))
          return
        end

        stack.transaction do
          shared_parent&.detach_children!
          appended_commits = new_commits.map do |gh_commit|
            append_commit(gh_commit)
          end
          stack.lock_reverted_commits! if appended_commits.any?(&:revert?)
        end
      end
      sync_changed_nothing = appended_commits.empty? &&
                             spec_cache_target == head_before_sync &&
                             stack.cached_deploy_spec.present?
      return if sync_changed_nothing && !params[:force_spec_cache]

      CacheDeploySpecJob.perform_later(stack)
    end
```

**File:** app/jobs/shipit/continuous_delivery_job.rb (L10-21)
```ruby
    def perform(stack)
      return unless stack.continuous_deployment?

      # If there is a schedule defined for this stack, make sure we are within a
      # deployment window before proceeding.
      return if stack.continuous_delivery_schedule && !stack.continuous_delivery_schedule.can_deploy?

      # checks if there are any tasks running, including concurrent tasks
      return if stack.occupied?

      stack.trigger_continuous_delivery
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
