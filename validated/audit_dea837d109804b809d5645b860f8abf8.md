### Title
Webhook signature verified against `repository.owner.login` while every event handler resolves the target repository from the unchecked `repository.full_name` field, enabling cross-tenant impersonation - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects the GitHub App (and its `webhook_secret`) to verify the HMAC signature using `repository_owner`, computed from `params.dig('repository', 'owner', 'login')` [1](#0-0) [2](#0-1) . Every downstream handler, however, resolves which `Repository`/`Stack` to act on using a *different* field of the same JSON body: `payload.dig('repository', 'full_name')` [3](#0-2) , and `Shipit::Repository.from_github_repo_name` splits that string on `/` to find the target repo record without ever re-checking it against `owner.login` [4](#0-3) . Nothing binds these two fields together, even though both are covered by the same signature.

### Finding Description
Shipit explicitly supports hosting multiple GitHub organizations from a single instance, each with its own `github_app`/`webhook_secret` keyed by organization name in `config/secrets.yml` (documented in `docs/setup.md`, "Using Multiple Github Applications"). In that mode, `Shipit.github(organization: repository_owner)` picks the app/secret to verify with, based solely on `repository.owner.login` in the incoming payload [1](#0-0) .

An attacker who legitimately controls one of the tenant organizations configured on the instance (e.g., "attacker-org", with its own valid `webhook_secret`) can craft an arbitrary JSON payload, set `repository.owner.login = "attacker-org"` (so the signature check resolves and verifies against the attacker's own secret, which the attacker knows/controls) but set `repository.full_name = "victim-org/victim-repo"`. `verify_signature` will pass because it is only checking that the payload came from *some* organization the attacker legitimately controls - it never verifies that `repository.full_name`'s owner segment matches `repository.owner.login`.

The request then flows into `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [5](#0-4) . For a `push` event, `PushHandler#process` looks up stacks via `Handler#stacks`/`#repository_name`, which reads `payload.dig('repository', 'full_name')` [3](#0-2)  and calls `stack.sync_github(expected_head_sha: params.after)` on any non-archived stack matching that (attacker-chosen) full name and branch [6](#0-5) . This enqueues `GithubSyncJob`, which fetches commits from GitHub for the *real* `victim-org/victim-repo` stack and appends them to Shipit's commit history / triggers `CacheDeploySpecJob` [7](#0-6) . The same unchecked-`full_name` pattern is repeated in the pull-request family of handlers (`OpenedHandler`, `ClosedHandler`, `LabelCapturingHandler`, etc.), all of which call `Shipit::Repository.from_github_repo_name(params.repository.full_name)` with no ownership cross-check [8](#0-7) .

The broken binding, expressed as an equality that the code fails to enforce:
`organization authenticated by verify_signature (repository.owner.login)` **should equal** `repository whose Stack/Repository record is written (repository.full_name)`.

### Impact Explanation
This is a confused-deputy / cross-tenant issue on multi-organization Shipit deployments: an attacker who is a legitimate (but low-privilege, non-admin-of-Shipit) member of one tenant org can forge webhook events that are attributed to and acted upon for a completely different tenant's repository/stack, triggering unauthorized syncing of arbitrary commits and, depending on `continuous_deployment` settings and merge/label-driven review-stack automation (`OpenedHandler`, `LabelCapturingHandler`, etc.), can influence review-stack provisioning, archival, or feed a deploy pipeline with attacker-timed data for a repository the attacker does not control. This crosses the "an organization that authenticated versus the repository that is written" trust boundary named in scope and can lead to unauthorized syncs/deploys on another tenant's stack without ever needing that tenant's GitHub credentials, webhook secret, or Shipit session.

### Likelihood Explanation
Exploitability requires the instance to be configured for multiple GitHub organizations (a documented, supported configuration) and requires the attacker to control at least one of the configured tenant orgs (i.e., know/derive that org's own `webhook_secret`, which they can via their own legitimately configured GitHub App or by directly signing a raw POST to `/webhooks`, since `WebhooksController` does not require a Shipit session or ApiClient token — it is a public HTTP endpoint gated only by the HMAC signature). No victim credentials, private keys, or victim-org write access are needed. This is realistic wherever a single Shipit instance intentionally serves several independent GitHub organizations.

### Recommendation
In `WebhooksController#verify_signature` (or in `Shipit::Webhooks::Handlers::Handler`), assert that the owner segment of `payload.dig('repository', 'full_name')` matches `repository_owner`/`params.dig('repository', 'owner', 'login')` before dispatching to any handler, rejecting the request (e.g., `head(422)`) on mismatch. Handlers should not trust `repository.full_name` alone to resolve a `Repository`/`Stack` without re-validating it against the organization whose secret produced a valid signature.

### Proof of Concept
1. Configure Shipit with two tenant orgs in `config/secrets.yml`: `attacker-org` (attacker's own GitHub App/webhook_secret) and `victim-org` (hosting a real Shipit stack, e.g. `victim-org/victim-repo`, branch `master`).
2. Attacker crafts a `push` event JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha-that-exists-on-victim-repo-github>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker signs this exact payload body with `attacker-org`'s own `webhook_secret` (known to the attacker), producing `X-Hub-Signature: sha1=<hmac>`.
4. Attacker `POST`s to `/webhooks` with headers `X-Github-Event: push` and the computed `X-Hub-Signature`.
5. `verify_signature` resolves `repository_owner` = `"attacker-org"`, fetches `Shipit.github(organization: "attacker-org")`, and the signature validates successfully [1](#0-0) .
6. `PushHandler#process` resolves stacks via `repository_name = "victim-org/victim-repo"` [3](#0-2)  and calls `stack.sync_github(expected_head_sha: ...)` on the real victim stack [6](#0-5) , an action the attacker had no legitimate GitHub or Shipit permission to trigger.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
