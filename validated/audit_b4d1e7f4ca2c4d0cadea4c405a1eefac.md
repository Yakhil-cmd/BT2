### Title
Cross-organization webhook forgery via mismatched signature-verification owner and repository-routing owner - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects the GitHub App (and therefore the HMAC secret) used to authenticate an inbound webhook based on `repository_owner`, taken from `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`). Every event handler, however, resolves the `Repository`/`Stack` to act on using a *different* field from the very same payload: `payload.dig('repository', 'full_name')` [1](#0-0) . Nothing in the request pipeline checks that `repository.owner.login` (the identity whose secret authenticated the request) matches the owner encoded in `repository.full_name` (the identity whose stack the handler will actually mutate).

### Finding Description
`verify_signature` computes:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
``` [2](#0-1) 
with
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [3](#0-2) 

`verify_webhook_signature` only checks the HMAC of the raw body against the secret configured for that one organization; it makes no assertion about any other field inside the body [4](#0-3) .

Once the signature passes, `Handler#repository_name` and `#stacks` — used by every handler (`PushHandler`, `PullRequest::ClosedHandler`, etc.) — resolve the target purely from `repository.full_name`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [1](#0-0) 
`Repository.from_github_repo_name` simply splits `"owner/name"` and looks up the matching `Repository` record, with no cross-check that `owner` equals `repository_owner` used at signature time [5](#0-4) . `PullRequest::ClosedHandler#repository` reproduces the same pattern independently [6](#0-5) .

This is the same bug class as the referenced report: two computations that are supposed to describe the same value (here, "which organization is this webhook for") are derived from two different, independently attacker-controllable inputs, and the code assumes they agree without enforcing it. `Shipit` explicitly supports hosting **multiple GitHub Apps for multiple organizations** in one instance, each with its own `webhook_secret` [7](#0-6) . Because the entity that signs the request (`repository.owner.login`) is independent of the entity whose stack gets mutated (`repository.full_name`), the owner of any one onboarded GitHub App (who legitimately knows/controls only their own organization's `webhook_secret`, e.g. by configuring the app on the GitHub side) can craft a raw JSON body where:
- `repository.owner.login = "their-own-org"` (so `Shipit.github(organization: "their-own-org")` is selected and their known secret produces a valid `X-Hub-Signature`), while
- `repository.full_name = "victim-org/victim-repo"` (so the handler resolves and mutates a `Stack`/`ReviewStack` that belongs to an entirely different, unrelated tenant organization on the same Shipit instance).

The binding that is broken is:
`organization whose secret authenticated the request == organization whose repository/stack the handler writes to`
which does not hold after crafting the payload as above.

### Impact Explanation
This breaks the cross-tenant isolation the "multiple GitHub Applications" feature is meant to provide. With a forged push payload, an attacker controlling one tenant's App/webhook secret can trigger `stack.sync_github` on another tenant's stack via `PushHandler` → `GithubSyncJob` [8](#0-7) [9](#0-8) , or force-close/archive another tenant's review stack via `PullRequest::ClosedHandler#process` calling `review_stack.archive!` [10](#0-9) , or manipulate labeling/opened/reopened handlers for a stack it has no legitimate authority over. This is an unauthorized cross-repository/cross-organization write on a multi-tenant instance, matching the "cross-repository writes" Critical-impact category.

### Likelihood Explanation
Requires the attacker to already control one legitimate GitHub App integration (and its `webhook_secret`) onboarded onto the same Shipit instance as the victim organization — a realistic scenario for any Shipit deployment that hosts multiple independent organizations/tenants (a use case the engine explicitly documents and supports). No Shipit-privileged account, session, or API token is needed; the attacker only needs their own organization's webhook credential, which they legitimately hold, and knowledge of the victim's `owner/repo` full name (public information on GitHub).

### Recommendation
After `verify_signature` succeeds, assert that `repository_owner` (or `organization.login`) matches the owner segment of `repository.full_name` for every payload before dispatching to handlers, and reject the webhook (422) on mismatch. Alternatively, have `Repository.from_github_repo_name`/`Handler#stacks` re-derive and compare against the verified organization rather than trusting `full_name` unconditionally.

### Proof of Concept
1. Shipit is configured with `github.OrgA` and `github.OrgB` apps, each with distinct `webhook_secret`s, per the multi-org example in `docs/setup.md` [7](#0-6) .
2. Attacker controls OrgA's GitHub App configuration and therefore knows OrgA's `webhook_secret`.
3. Attacker crafts a `push` event JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" }
}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(OrgA_webhook_secret, body)` and POSTs to `/github/webhooks`.
5. `verify_signature` resolves `Shipit.github(organization: "OrgA")` and validates successfully against the attacker-known secret [2](#0-1) .
6. `PushHandler#process` resolves `stacks` via `repository.full_name = "OrgB/victim-repo"` [1](#0-0) , finds OrgB's stack, and enqueues `GithubSyncJob` against OrgB's stack — an action the attacker had no authorization to trigger.

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-45)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
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
