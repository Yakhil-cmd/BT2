### Title
Webhook signature is verified against the GitHub App keyed by attacker-supplied `repository.owner.login`, but the event is dispatched against a different attacker-supplied `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to check the `X-Hub-Signature` against using `repository_owner`, a value read straight out of the unauthenticated JSON body (`params.dig('repository','owner','login')` or `organization.login`). Once the signature check passes, `create` hands the same raw `params` to `Shipit::Webhooks.for_event(event)` handlers, which instead resolve the target `Stack`/`Repository` using an entirely different field of the same body: `payload.dig('repository', 'full_name')` [1](#0-0) . Nothing ties `repository.owner.login` (used for authentication) to `repository.full_name` (used for authorization/target selection).

### Finding Description
`verify_signature` picks the app/secret to check with based on `repository_owner`: [2](#0-1) [3](#0-2) 

`repository_owner` and `repository.full_name` are both read from the same untrusted, attacker-supplied JSON body, but they are never cross-checked against each other: [4](#0-3) 

Once signature verification succeeds, the raw `params` (unmodified) are dispatched to handlers, and every handler resolves the affected `Repository`/`Stack` via `Repository.from_github_repo_name(payload.dig('repository', 'full_name'))`, e.g. in the base `Handler` class used by `PushHandler`: [5](#0-4) [6](#0-5) 

`Repository.from_github_repo_name` does a plain lookup with no ownership constraint tied to the org whose secret validated the request: [7](#0-6) 

The binding that is broken is: **organization authenticated (`repository.owner.login`, used to select the `webhook_secret`) ≠ repository written/acted upon (`repository.full_name`, used to select the `Stack`)**. In a multi-org Shipit deployment (explicitly supported and documented, see `config/secrets.development.shopify.yml` with multiple orgs each with their own `webhook_secret`) [8](#0-7) , an entity that legitimately controls/knows the `webhook_secret` for **their own** installed org (`orgA`) can:
1. Send a POST directly to `/webhooks` (bypassing GitHub entirely) with `X-Github-Event: push`.
2. Set `repository.owner.login = "orgA"` (so `verify_signature` picks `orgA`'s app/secret) and sign the raw body with `orgA`'s known `webhook_secret`.
3. Set `repository.full_name = "orgB/victim-repo"` — a repository/stack that belongs to a completely different, unrelated organization configured on the same Shipit instance, which the attacker does not own or administer.
4. `verify_signature` succeeds (it only validates using `orgA`'s secret over the whole raw body, which the attacker legitimately possesses), and `PushHandler` looks up `orgB/victim-repo`'s `Stack` and calls `stack.sync_github(expected_head_sha: params.after)`, enqueuing `GithubSyncJob` for a stack the attacker has no relationship to [9](#0-8) .

`GithubSyncJob` uses the *target stack's own* GitHub API credentials to fetch real commits, so it cannot be used to inject forged commit content — but it can force an unauthorized, attacker-timed re-sync of `orgB`'s repository state and (if the stack has continuous delivery/auto-merge configured) trigger deploy pipeline advancement for a stack/organization the attacker does not control, using only credentials scoped to their own, unrelated org.

### Impact Explanation
This crosses an organizational trust boundary the signature check is supposed to enforce: possession of `orgA`'s webhook secret should only authorize actions on `orgA`'s repositories, not on `orgB`'s. Being able to force-trigger `GithubSyncJob`/deploy-pipeline advancement on another organization's `Stack` is an unauthorized cross-organization action against a stack the caller has no legitimate authority over, which maps to "unauthorized deploy/rollback" territory (High), contingent on the target stack's continuous-deployment configuration for full deploy-trigger impact.

### Likelihood Explanation
Requires: (a) a Shipit instance configured for multiple GitHub organizations (a documented, supported configuration), and (b) the attacker to hold a legitimate `webhook_secret` for at least one of those organizations (e.g. because they are an admin of their own installed GitHub App/org on that shared Shipit instance). This is a real but non-trivial precondition — it is not exploitable by a fully unauthenticated internet attacker with zero relationship to the target Shipit instance, only by a party with valid credentials for a different, unrelated tenant on the same instance.

### Recommendation
After verifying the signature with the app selected via `repository_owner`, re-validate that every repository-scoped field used later by handlers (`repository.full_name`'s owner segment) matches `repository_owner`/the verified organization before dispatching to handlers; reject the webhook (422) on mismatch instead of trusting `repository.full_name` unconditionally in `Shipit::Webhooks::Handlers::Handler#repository_name`.

### Proof of Concept
1. Configure Shipit with two orgs, `orgA` (secret `SECRET_A`, known to attacker) and `orgB` (contains stack for `orgB/victim-repo`, secret unknown to attacker).
2. Build payload: `{"ref":"refs/heads/master","after":"<any-sha>","repository":{"owner":{"login":"orgA"},"full_name":"orgB/victim-repo"}}`.
3. Compute `X-Hub-Signature: sha1=` HMAC-SHA1 of the raw body using `SECRET_A`.
4. POST to `/webhooks` with `X-Github-Event: push` and the above signature.
5. `verify_signature` selects `orgA`'s app via `repository_owner` = `orgA`, and passes because the signature was computed with `SECRET_A`.
6. `PushHandler`/`Handler#stacks` resolves `Repository.from_github_repo_name("orgb/victim-repo")` and enqueues `GithubSyncJob` for `orgB`'s stack — confirmed reachable via [1](#0-0)  and [6](#0-5) .

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L15-38)
```ruby
        def self.call(params)
          new(params).process
        end

        attr_reader :params, :payload

        def initialize(payload)
          @payload = payload
          @params = self.class.param_parser.parse!(payload)
        end

        def process
          raise NotImplementedError
        end

        private

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
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
