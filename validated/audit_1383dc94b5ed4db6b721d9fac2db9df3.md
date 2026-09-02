### Title
Webhook signature verified against `repository.owner.login` while routing/stack-lookup uses `repository.full_name`, allowing cross-tenant stack sync triggering - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp`/`webhook_secret` used to authenticate the request based on `payload.dig('repository','owner','login')`, but `Handler#stacks`/`#repository_name` (used by `PushHandler`, `CheckSuiteHandler`) resolves the target `Stack` using `payload.dig('repository','full_name')`. These are two independent, attacker-controlled fields of the same signed body, and nothing checks that `full_name`'s owner segment matches `owner.login`. An attacker who owns a GitHub organization/App configured in this Shipit instance can therefore sign a payload with their own legitimate `webhook_secret` while setting `full_name` to any other tenant's `owner/repo`, causing the handler to act on that other tenant's `Stack`.

### Finding Description
The broken binding: `repository_owner_that_authenticated_bytes` (`payload.dig('repository','owner','login')`, checked in `verify_signature`) is assumed to equal `repository_owner_whose_stack_is_mutated` (derived from `payload.dig('repository','full_name')` in `Handler#repository_name`), but the code never enforces this equality.

Code path:
- `app/controllers/shipit/webhooks_controller.rb:24-30,59-62` — `verify_signature` calls `Shipit.github(organization: repository_owner)` and `github_app.verify_webhook_signature(signature, raw_post)`, where `repository_owner` comes from `params.dig('repository','owner','login')`. [1](#0-0) [2](#0-1) 
- `app/models/shipit/webhooks/handlers/handler.rb:32-38` — `stacks` and `repository_name` derive the target repository from `payload.dig('repository', 'full_name')`, independent of `owner.login`. [3](#0-2) 
- `app/models/shipit/webhooks/handlers/push_handler.rb:12-17` — `PushHandler#process` calls `stacks.not_archived.where(branch:).find_each { |stack| stack.sync_github(expected_head_sha: params.after) }`. [4](#0-3) 
- `app/models/shipit/stack.rb:612-614` — `sync_github` enqueues `GithubSyncJob.perform_later(stack_id: id, expected_head_sha:)`. [5](#0-4) 

Attacker request: `POST /webhooks`, `X-Github-Event: push`, body `{"repository":{"owner":{"login":"attacker-org"},"full_name":"victim-org/victim-repo"},"ref":"refs/heads/master","after":"<sha>"}`, HMAC-signed with `attacker-org`'s own real `webhook_secret`. `verify_signature` looks up `Shipit.github(organization: 'attacker-org')` and validates successfully because the attacker legitimately owns that secret; the handler then resolves the victim's `Stack` via `full_name` and enqueues `GithubSyncJob` with the victim stack's `stack_id`.

Existing guards do not catch this: `verify_signature` only checks HMAC validity against the org named by `owner.login`; it never cross-checks that `full_name`'s owner segment equals `owner.login`. `ExplicitParameters` schema for `PushHandler` (`ref`, `after`) does not constrain `repository.full_name`. `Repository.from_github_repo_name` performs a plain `find_by(owner:, name:)` lookup with no ownership/authentication check tied back to the verifying org. [6](#0-5) 

Important mitigating factor found during tracing: `GithubSyncJob` does not blindly trust the attacker-supplied `expected_head_sha`. It fetches real commits via `stack.github_commits`/`stack.github_api`, which internally resolves `Shipit.github(organization: owner)` using the **victim repository's own `owner` column** (`Repository#github_app` at `app/models/shipit/repository.rb:100-102`), not the attacker's credentials. [7](#0-6)  `expected_head_sha` is only used as a hint for retry/backoff logic (`commit_exists?` check) inside `GithubSyncJob#perform`. [8](#0-7)  This means the attacker cannot force the deploy pipeline to accept an arbitrary, attacker-chosen commit SHA — only commits that genuinely exist in the victim's real GitHub history (fetched with the victim's own credentials) are appended.

### Impact Explanation
The demonstrated, reachable impact is: an attacker who legitimately controls a GitHub organization configured as a separate tenant in the same Shipit deployment can force a `GithubSyncJob` (and thus a premature/duplicate GitHub resync, and potentially cache invalidation) to run against an unrelated tenant's `Stack`, using only their own webhook secret — i.e., a payload authenticated for one repository triggers a job for another repository's stack. This is a genuine cross-tenant confused-deputy authorization gap. However, because `GithubSyncJob` fetches commit data via the victim repository's own configured GitHub App/credentials, the attacker cannot inject an arbitrary/attacker-chosen commit SHA into the victim's deploy history or force deployment of a specific attacker-picked reference — the job only reflects real GitHub state for the victim repo. The severity is therefore bounded to "unauthorized cross-tenant job trigger" rather than the full "unauthorized deploy of an attacker-influenced commit" claimed in the prompt; the latter part of the claim is not substantiated by the code.

### Likelihood Explanation
Exploitation requires the attacker to own/control a GitHub organization that is itself configured with a valid `webhook_secret` in this Shipit instance's `Shipit.github` configuration (i.e., a genuine multi-tenant Shipit deployment where multiple distinct orgs are onboarded). This is a real but narrow precondition — it does not apply to single-tenant Shipit installations, and it requires the attacker to already be a legitimate, provisioned tenant of the same Shipit instance. Given that precondition, the attack is cheap and fully repeatable against any tracked stack whose `owner/name` and `branch` the attacker can guess or discover.

### Recommendation
In `WebhooksController#verify_signature` or in `Shipit::Webhooks::Handlers::Handler`, enforce that the organization used to verify the signature (`params.dig('repository','owner','login')`) matches the owner segment of `params.dig('repository','full_name')` before resolving `stacks`/processing the event; reject the request (e.g. `head(422)`) on mismatch.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb`):
```ruby
test "push payload with mismatched repository.owner.login and repository.full_name is rejected" do
  attacker_org = "attacker-org"
  victim_stack = shipit_stacks(:shipit) # owner/name = victim-org/victim-repo

  payload = JSON.parse(payload(:push_master))
  payload["repository"]["owner"]["login"] = attacker_org
  payload["repository"]["full_name"] = victim_stack.repository.github_repo_name
  body = payload.to_json

  # Signed with attacker-org's own real webhook_secret
  signature = "sha1=" + OpenSSL::HMAC.hexdigest("sha1", attacker_org_webhook_secret, body)

  request.headers['X-Github-Event'] = 'push'
  request.headers['X-Hub-Signature'] = signature

  # Equality under test: repository_owner (attacker-org) == full_name owner segment (victim-org) -- must NOT both pass
  assert_no_enqueued_jobs(only: GithubSyncJob) do
    post :create, body:, as: :json
  end
  assert_response :unprocessable_entity
end
```
Currently this assertion fails (no such guard exists): the request is accepted and `GithubSyncJob` is enqueued with `stack_id: victim_stack.id`, demonstrating the cross-tenant job trigger described above.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/stack.rb (L612-614)
```ruby
    def sync_github(expected_head_sha: nil)
      GithubSyncJob.perform_later(stack_id: id, expected_head_sha:)
    end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/repository.rb (L98-102)
```ruby
    protected

    def github_app
      Shipit.github(organization: owner)
    end
```

**File:** app/jobs/shipit/github_sync_job.rb (L18-33)
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
```
