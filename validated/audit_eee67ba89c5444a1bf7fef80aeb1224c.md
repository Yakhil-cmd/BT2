### Title
Webhook signature bypass via attacker-controlled organization lookup allows unauthenticated triggering of `GithubSyncJob` on unrelated repositories - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to verify against using `repository_owner`, which is read from `params.dig('repository', 'owner', 'login')` [1](#0-0)  — a field that is never checked against the field actually used later by the event handlers to decide *which repository/stack* to mutate: `payload.dig('repository', 'full_name')` [2](#0-1) . Because `GithubApp#verify_webhook_signature` unconditionally returns `true` when no `webhook_secret` is configured for the looked-up organization [3](#0-2) , an attacker who knows of (or can enumerate) an organization configured in the instance without a `webhook_secret` can forge a webhook whose `repository.owner.login` points to that unsecured organization (to pass/bypass signature verification) while `repository.full_name` points to a *different, protected* organization/repository. The handler dispatch never re-validates that these two fields agree.

### Finding Description
The trust binding that should hold is:

`organization used to authenticate the webhook (repository.owner.login)` == `organization/repository actually written to by the handler (repository.full_name)`

`verify_signature` in `WebhooksController` computes the GithubApp/secret to use purely from `repository.owner.login` (or `organization.login`) [4](#0-3) . Once `verified` is (or appears) true, `create` dispatches the **entire raw JSON payload** to every registered handler for the event: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [5](#0-4) .

Handlers such as `PushHandler` never re-derive or cross-check the organization used for authentication. They resolve the target `Repository`/`Stack` purely from `payload.dig('repository', 'full_name')` via `Handler#stacks` / `Handler#repository_name` [6](#0-5) , then call `stack.sync_github(expected_head_sha: params.after)` for every matching, non-archived stack on the matching branch [7](#0-6) .

`GithubApp#verify_webhook_signature` explicitly short-circuits to `true` when the resolved app has no configured secret: `return true unless webhook_secret` [3](#0-2) . The test fixtures confirm this is a supported configuration shape — a second, distinct organization entry with `webhook_secret: # nil` alongside another org that does have a secret [8](#0-7) , i.e. multi-org Shipit deployments can legitimately have some organizations without a webhook secret configured (e.g., mid-setup, GitHub Enterprise installs, or simple misconfiguration) while others are properly secured.

Given this, an attacker (with no credentials, no `ApiClient` token, no GitHub App key) can:
1. Discover/guess that organization `UnsecuredOrg` is registered in this Shipit instance without a `webhook_secret` (this is visible through prior public webhook deliveries, error messages, or trial-and-error against `/github/webhooks`, since a wrong org yields `GithubOrganizationUnknown` distinguishable from a org that exists but has no secret returning normal 200s).
2. POST a forged `push` event to `/github/webhooks` with:
   - `repository.owner.login = "UnsecuredOrg"` (used only to select the verification key, which trivially passes because no secret exists)
   - `repository.full_name = "victim-org/victim-repo"` (used by `PushHandler`/`Handler#stacks` to select the actual `Stack` to mutate)
   - `ref = "refs/heads/<victim-branch>"`, `after = "<attacker-chosen-sha>"`
3. Because signature verification is keyed on the spoofable `owner.login` field, not on the actually-acted-upon `full_name`, the forged payload is accepted, and `Stack#sync_github` / `GithubSyncJob` is triggered against `victim-org/victim-repo`'s stacks — a repository whose organization may have a properly configured, uncompromised `webhook_secret`.

### Impact Explanation
This crosses a repository/organization authorization boundary: an attacker with no relationship to `victim-org` (and no access to its webhook secret) can force `GithubSyncJob` to run against `victim-org`'s stacks. `GithubSyncJob#perform` fetches commits via `stack.github_commits` and, on eventual-consistency retries, keys retry logic off the attacker-supplied `expected_head_sha` [9](#0-8) , and unconditionally invokes `CacheDeploySpecJob` at the end of the run [10](#0-9) . This lets an unauthenticated outsider force unscheduled GitHub API sync/cache-spec activity and repeated retry jobs (rate-limit burn / job queue pressure) against a stack it has no business touching, and, more importantly, demonstrates that webhook authentication is not actually bound to the repository being mutated — the core boundary this component is supposed to enforce. This satisfies the "unauthenticated read/trigger of stack state via a broken authentication binding" class of High severity impact defined in scope.

### Likelihood Explanation
Requires only that the Shipit deployment be configured with at least one organization that has no `webhook_secret` set (a state the test fixtures show is an anticipated/supported configuration, not a hypothetical), and that the attacker can identify that organization's name. No GitHub App key, `ApiClient` token, or repository write access is needed — only network access to the public `/github/webhooks` endpoint, which is unauthenticated by design (`ActionController::Base`, `skip_before_action :verify_authenticity_token`) [11](#0-10) .

### Recommendation
Bind the organization used for signature verification to the repository actually referenced by the event: after selecting `repository_owner` for signature lookup, verify it matches the owner portion parsed from `payload.dig('repository', 'full_name')` (and reject if they differ), or better, resolve the target `Repository`/`Stack` using `repository_owner` (the verified value) rather than the independently-supplied `full_name`. Additionally, treat "organization configured with no `webhook_secret`" as a hard failure (or require explicit opt-in per environment) rather than silently returning `true` from `verify_webhook_signature`.

### Proof of Concept
1. Configure two orgs in `secrets.yml`/`config.github`: `SecureOrg` (with `webhook_secret`) owning `secure-org/secure-repo`, and `UnsecuredOrg` (no `webhook_secret`, e.g. left blank during setup).
2. Send, without any signature header (or an arbitrary bogus one):
```
POST /github/webhooks
X-Github-Event: push

{
  "ref": "refs/heads/master",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "owner": { "login": "UnsecuredOrg" },
    "full_name": "secure-org/secure-repo"
  }
}
```
3. `verify_signature` resolves `Shipit.github(organization: "UnsecuredOrg")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` regardless of the (missing/invalid) `X-Hub-Signature` header [3](#0-2) .
4. `PushHandler` resolves stacks via `Repository.from_github_repo_name("secure-org/secure-repo")` [6](#0-5)  and triggers `sync_github(expected_head_sha: "deadbeef...")` on `secure-org`'s stacks — despite the request never being authenticated against `SecureOrg`'s webhook secret.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L4-6)
```ruby
  class WebhooksController < ActionController::Base
    skip_before_action :verify_authenticity_token, raise: false
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature
```

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
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

**File:** app/jobs/shipit/github_sync_job.rb (L43-49)
```ruby
      sync_changed_nothing = appended_commits.empty? &&
                             spec_cache_target == head_before_sync &&
                             stack.cached_deploy_spec.present?
      return if sync_changed_nothing && !params[:force_spec_cache]

      CacheDeploySpecJob.perform_later(stack)
    end
```
