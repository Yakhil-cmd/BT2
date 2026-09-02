### Title
Cross-organization webhook signature confusion allows an attacker with any one org's webhook secret to trigger GitHub syncs / continuous deploys on stacks belonging to a different tracked repository - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate an inbound webhook using an attacker-controlled JSON field, `repository.owner.login` (or `organization.login`), while the actual event processing (`Shipit::Webhooks::Handlers::Handler#stacks`) resolves the target `Stack`/`Repository` using a *different* attacker-controlled field, `repository.full_name`. These two fields are never checked for consistency, so the org whose secret authenticates the request is not bound to the repository that the payload actually acts on.

### Finding Description
`WebhooksController#verify_signature` looks up which `GithubApp`/webhook secret to validate against like this: [1](#0-0) [2](#0-1) 

`repository_owner` is read straight from the raw JSON body (`params.dig('repository','owner','login')`), and `Shipit.github(organization: repository_owner)` is used to pick the webhook secret to HMAC-verify the request against.

Once the signature passes, the actual handler dispatch (`Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`) resolves the affected stacks via the base `Handler` class using a *different* JSON field: [3](#0-2) 

`repository_name` comes from `payload.dig('repository', 'full_name')`, which is never checked against `repository.owner.login` used for signature verification. `Repository.from_github_repo_name` then splits this string on `/` and looks up any repository Shipit tracks, regardless of organization: [4](#0-3) 

Because a single Shipit instance can be configured with several GitHub organizations/apps (as shown in `config/secrets.development.shopify.yml`), an entity that legitimately controls (or has been given) the webhook secret for one configured organization can forge a signed POST to `/webhooks` where:
- `repository.owner.login` = the organization it actually controls (so `verify_webhook_signature` succeeds using a secret it legitimately knows),
- `repository.full_name` = `victim-org/victim-repo` (a completely different, unrelated stack tracked by the same Shipit instance).

`PushHandler#process` will then act on the stacks resolved from the forged `full_name`: [5](#0-4) 

This calls `stack.sync_github(expected_head_sha:)`, enqueuing `GithubSyncJob` for the victim's stack. `GithubSyncJob` re-fetches commits from GitHub using Shipit's own credentials for the real owner and, if nothing changed, still enqueues `CacheDeploySpecJob`: [6](#0-5) 

If the targeted stack has `continuous_deployment` enabled, `Stack#sync_github_if_necessary`/`trigger_continuous_delivery` machinery (invoked from the stack's commit-append/update lifecycle) can be forced to run on demand for a repository the attacker does not control and was never authenticated for, purely by supplying a mismatched `repository.full_name` while signing with a secret for an unrelated org.

### Impact Explanation
This breaks the equality that should hold: `organization authenticated by verify_signature == organization whose repository/stack is acted upon`. An attacker who is a legitimate (even low-privileged) member/admin able to see or set the webhook secret for one org tracked by this Shipit instance can force GitHub-sync and continuous-delivery evaluation cycles against stacks belonging to a completely unrelated organization/repository also tracked by the same instance. This is a cross-repository/cross-organization write path (forcing GithubSyncJob, CacheDeploySpecJob, and potentially triggering continuous deployment) that the attacker has no authorization over, matching the "Critical — cross-repository writes / unauthorized deploy" impact category, since it can force a deploy pipeline to advance (sync + cache + continuous delivery trigger) on a stack outside the attacker's control.

### Likelihood Explanation
Exploitability depends on the attacker knowing/controlling a webhook secret for *any one* organization configured in the same multi-tenant Shipit deployment (a plausible scenario for Shipit installations that onboard multiple GitHub orgs, as explicitly supported and documented by `config/secrets.development.shopify.yml`). No repository write access, GitHub App private key, or Shipit session/API token is required — only the ability to send an HTTP POST to the public `/webhooks` endpoint with a validly-signed payload for the org the attacker legitimately administers. The mismatch between the field used for signature-org lookup and the field used for stack resolution is a pure logic bug with no additional preconditions.

### Recommendation
Bind the field used to select the webhook secret to the same field used to resolve the acted-upon repository/stack. Concretely:
- In `WebhooksController#verify_signature`, derive `repository_owner` from `repository.full_name` (splitting on `/`) rather than the separate `repository.owner.login`/`organization.login` fields, or
- After selecting the `Repository`/`Stack` in `Handler#stacks`, re-verify that `Repository#owner` matches the organization whose secret validated the signature, rejecting the event otherwise.

### Proof of Concept
1. Configure Shipit with two organizations, `org-a` and `org-b`, each with its own tracked repository/stack and its own `webhook_secret` (as in `config/secrets.development.shopify.yml`).
2. As an attacker with knowledge of `org-a`'s webhook secret (e.g., a GitHub App/org admin for `org-a`), craft a `push` event JSON payload with:
   - `repository.owner.login = "org-a"`
   - `repository.full_name = "org-b/victim-repo"`
   - `ref = "refs/heads/<victim-branch>"`, `after = "<any known victim sha>"`
3. Compute `X-Hub-Signature: sha1=<hmac-sha1(org-a-secret, raw_body)>` and POST it to `/webhooks` with `X-Github-Event: push`.
4. `WebhooksController#verify_signature` succeeds because it validates against `org-a`'s secret using `repository.owner.login`.
5. `PushHandler#process` resolves stacks via `repository.full_name` = `org-b/victim-repo`, enqueuing `GithubSyncJob`/`CacheDeploySpecJob` for `org-b`'s stack, which the attacker never authenticated for.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
