### Title
Webhook signature is verified against `repository.owner.login` but the acted-upon repository is taken from `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In a multi-GitHub-App deployment (`config/secrets.yml` keyed by organization), `WebhooksController#verify_signature` selects which organization's `webhook_secret` to validate the HMAC signature against using `repository.owner.login` (or `organization.login`) from the untrusted JSON payload, while the handlers that actually mutate state (e.g. `PushHandler`) resolve the target `Repository`/`Stack` using a *different* field of the same payload: `repository.full_name`. These two fields are never required to agree.

### Finding Description
`WebhooksController#verify_signature` computes: [1](#0-0) 

using `repository_owner`, derived from the payload: [2](#0-1) 

This looks up the corresponding GitHub App config via `Shipit.github(organization: repository_owner)`, and HMAC-verifies the raw body against that organization's `webhook_secret`, as implemented in `GitHubApp#verify_webhook_signature`: [3](#0-2) 

Once the signature check passes, the full raw payload is dispatched unmodified to the registered handlers: [4](#0-3) 

But the base `Handler` class - which every event handler (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, etc.) inherits from - resolves the acted-upon `Repository`/`Stack` using `payload.dig('repository', 'full_name')`, not `repository.owner.login`: [5](#0-4) 

`Repository.from_github_repo_name` splits that `full_name` on `/` to find the owner/name pair used for the DB lookup: [6](#0-5) 

The binding that should hold is: **organization authenticated (`repository.owner.login`, used to pick the `webhook_secret`) == organization whose repository is written (`repository.full_name`'s owner segment, used to resolve the `Stack`)**. Nothing in `WebhooksController` or `Handler` enforces this equality. In a deployment where Shipit manages multiple orgs (this is an explicitly supported and documented configuration — see `docs/setup.md`'s "Using Multiple Github Applications" section and `test/dummy/config/secrets_double_github_app.yml`), each org has its own `webhook_secret`. Anyone who knows (or can guess/leak) *their own* org's `webhook_secret` — which is not a Shipit secret at all, but simply the webhook secret configured on their own GitHub App/organization — can craft an arbitrary payload where:

- `repository.owner.login` = "OrgA" (their own org, used only to pick the HMAC key for verification, and signed with OrgA's own known secret)
- `repository.full_name` = "OrgB/some-repo" (a different, unrelated org/repo tracked by the same Shipit instance)

The signature check succeeds (it's a valid signature for OrgA's secret over the attacker's own chosen body), yet the `PushHandler` (or `StatusHandler`/`CheckSuiteHandler`) will act on stacks belonging to `OrgB/some-repo`: [7](#0-6) 

This queues `GithubSyncJob` for OrgB's stack with an attacker-chosen `expected_head_sha`, and `GithubSyncJob` fetches and appends "missing commits" up to the real head via the GitHub API and refreshes/creates the cached deploy spec: [8](#0-7) 

If continuous deployment is enabled on that stack, newly appended/status-updated commits can trigger an automatic deploy, since `Commit#schedule_continuous_delivery` and `Stack#trigger_continuous_delivery` fire off `ContinuousDeliveryJob`/`trigger_deploy` when a commit becomes deployable: [9](#0-8) [10](#0-9) 

The `status` handler is even more directly abusable: it writes a `Status` record for a specific commit sha under the repository resolved from `full_name`, independent of which org's secret validated the request, potentially flipping CI state to `success` and triggering CD for a stack the attacker does not control.

### Impact Explanation
This breaks the intended per-organization credential isolation of a multi-tenant Shipit deployment: possession of one organization's `webhook_secret` (a value the operator of that org's own GitHub App legitimately knows, not a Shipit-instance-wide secret) allows forging push/status/check_suite events attributed to a completely different organization's repository tracked by the same Shipit instance. This can trigger unauthorized `GithubSyncJob` runs, forged commit statuses, and — when continuous deployment is enabled on the target stack — unauthorized deploys, satisfying the Critical "unauthorized deploy" bar.

### Likelihood Explanation
Requires a Shipit instance configured with the documented multi-org GitHub App setup and the attacker controlling/knowing the `webhook_secret` of at least one org onboarded to that instance (which they legitimately possess as the owner of their own GitHub App installation) plus knowledge that another org/stack is also hosted on the same Shipit instance. Given Shipit explicitly documents and supports hosting many orgs behind one instance, this is a realistic configuration, though it does require the attacker to be a legitimate operator of some organization on the shared instance.

### Recommendation
After signature verification, re-derive the organization from `repository.full_name` (or `organization.login` for org-level events) exactly as the handlers do, and require it to match the `repository_owner` used to select the verifying `webhook_secret`; reject the request (422) on mismatch. Centralize this owner-resolution logic (e.g., in `Handler#repository_name`) so the controller and handlers can never disagree about which organization/repository is authorized to act on a given payload.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` and `OrgB`, each with a distinct `webhook_secret`, as in `test/dummy/config/secrets_double_github_app.yml`, and create a `Stack` for `OrgB/target-repo` with `continuous_deployment: true`.
2. As an attacker who legitimately administers `OrgA`'s GitHub App (and thus knows `OrgA`'s `webhook_secret`), craft a `push` payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-controlled-or-real-sha>",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/target-repo" }
}
```
3. Compute `X-Hub-Signature: sha1=<hmac-sha1(OrgA_webhook_secret, body)>` and POST to `/github/webhooks`.
4. `WebhooksController#verify_signature` resolves `repository_owner` = "OrgA", verifies successfully against `OrgA`'s secret.
5. `PushHandler#process` resolves the stack via `full_name` = `"OrgB/target-repo"`, enqueuing `GithubSyncJob` for `OrgB`'s stack despite the request never being authenticated against `OrgB`'s secret — demonstrating the cross-organization write.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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
