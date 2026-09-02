### Title
Webhook `X-Hub-Signature` verification is bound to `repository.owner.login`, while every event handler dispatches on the independent `repository.full_name` field, allowing a trusted-organization webhook secret to forge events against a different organization's stacks - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/secret to validate a webhook against using `repository_owner`, derived from `params.dig('repository', 'owner', 'login')` (or `organization.login`), but the actual event handlers (`PushHandler`, `CheckSuiteHandler`, `StatusHandler`, etc.) resolve *which repository/stacks to act on* using a completely different field, `payload.dig('repository', 'full_name')`. Nothing ties these two fields together, so a payload can pass signature verification for organization A while acting on organization B's repository.

### Finding Description
`app/controllers/shipit/webhooks_controller.rb` `verify_signature`: [1](#0-0) 
picks the app/secret with: [2](#0-1) 
i.e. `repository_owner = params.dig('repository','owner','login') || params.dig('organization','login')`.

Once the signature is accepted, `create` blindly hands the raw JSON `params` to every registered handler: [3](#0-2) 

Every handler resolves target stacks through `Handler#stacks`, which uses a *different* field of the same payload: [4](#0-3) 
`repository_name = payload.dig('repository', 'full_name')`, then `Repository.from_github_repo_name(repository_name)` looks the repo up purely by string, independent of which org's app/secret verified the request: [5](#0-4) 

`PushHandler#process` then acts on those stacks: `stacks.not_archived.where(branch:).find_each { |stack| stack.sync_github(expected_head_sha: params.after) }` [6](#0-5) 
which enqueues `GithubSyncJob`, fetching commits and triggering `CacheDeploySpecJob`, which for stacks with `continuous_deployment: true` leads to automatic deploys of newly-synced commits. [7](#0-6) 

The equality that should hold but doesn't:
`organization authenticated by X-Hub-Signature (repository.owner.login)` == `organization/repository the handler actually mutates (repository.full_name)`.

This is directly analogous to the reported bug class: a check is performed on one field/sub-state (`amounts[0]`/`amounts[1]` boundary vs. actual position acted upon; here, `repository.owner.login` vs. `repository.full_name`) while the state-changing action is driven by an unrelated/uncontrolled field.

### Impact Explanation
Shipit explicitly supports multiple GitHub Apps, one per organization, each with its own independently-configured `webhook_secret`: [8](#0-7) 

An organization admin who legitimately owns/administers one configured GitHub App (Org A) knows Org A's `webhook_secret` (they configure the GitHub App and hand this secret to the Shipit operator, or can set the delivery destination and observe deliveries). Because `verify_signature` only checks the HMAC against the app selected via `repository.owner.login`, and never checks that `repository.owner.login == repository.full_name`'s owner, this admin can craft an arbitrary payload with:
- `repository.owner.login = "OrgA"` (signature checked/passes with the known Org A secret)
- `repository.full_name = "OrgB/some-private-repo"` (the actual field consumed by every handler)

and submit it to `POST /webhooks`. The push/check_suite/status handlers will then operate on Org B's stacks — for example forcing `GithubSyncJob`/`CacheDeploySpecJob` to run for Org B's stack and, for stacks with `continuous_deployment` enabled, triggering an unauthorized deploy pipeline for a repository the attacker does not control and was never authorized to trigger events for. This crosses an organization/authentication boundary that the signature check was specifically meant to enforce, matching the "unauthorized deploy" / cross-repository-write impact bar.

### Likelihood Explanation
Requires only that the deployment be configured with multiple GitHub organizations (a documented, supported configuration) and that the attacker controls (or is an admin of) one of the trusted organizations' GitHub App — no GitHub App private key, `ApiClient` token, or Shipit session is needed, since the webhook endpoint is unauthenticated apart from the per-organization HMAC check. This is a moderate-likelihood, engine-code root cause (missing cross-field binding), not a third-party gem issue.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler#repository_name`), enforce that the organization used to select/verify the webhook secret matches the organization embedded in `repository.full_name` (and `organization.login`, if present) before dispatching to handlers — reject with 422 on mismatch. Alternatively, thread the verified `repository_owner` through to `Handler#stacks`/`repository_name` and only resolve repositories whose owner equals the organization that authenticated the request.

### Proof of Concept
1. Configure Shipit with two GitHub organizations, `OrgA` and `OrgB`, each with its own `webhook_secret` per `docs/setup.md`'s multi-app example.
2. As an admin of `OrgA` (who knows `OrgA`'s `webhook_secret`), build a push payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<real sha existing on OrgB/target-repo>",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/target-repo" }
}
```
3. Compute `X-Hub-Signature: sha1=<hmac-sha1(OrgA_webhook_secret, raw_body)>` and `POST` it to `/webhooks` with header `X-Github-Event: push`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "OrgA")`, verifies successfully against the attacker-known `OrgA` secret. [1](#0-0) 
5. `PushHandler#process` resolves `stacks` via `repository_name = "OrgB/target-repo"` (from `Handler#repository_name`), matching real stacks belonging to `OrgB`, and enqueues `stack.sync_github(expected_head_sha: ...)` for them, despite the attacker never being authenticated for `OrgB`. [4](#0-3) [6](#0-5)

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
