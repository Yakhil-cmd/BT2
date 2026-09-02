### Title
Webhook signature is verified against the organization named in `repository.owner.login`, but handlers act on the repository named in `repository.full_name` — cross-organization webhook confusion allows an unrelated GitHub-App tenant to trigger actions (including deploy sync) on another organization's stack - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects *which* GitHub App secret to verify a webhook against using `repository.owner.login` (or `organization.login`) taken straight from the unauthenticated request body, before the signature has been checked. Once the signature check passes, every registered `Shipit::Webhooks::Handlers::Handler` resolves the actual `Stack`/`Repository` to operate on using a *different* payload field: `repository.full_name` (see `Handler#repository_name`). These two fields are never cross-checked against each other. In Shipit's supported "multiple GitHub Applications" configuration (`docs/setup.md`, `lib/shipit.rb#github_app_config`), each tenant organization has its own independent `webhook_secret`. An attacker who administers their own tenant organization/app (a completely unprivileged position relative to any other tracked repository) knows their own org's `webhook_secret` and can therefore forge a signature that Shipit will accept for `repository.owner.login = <attacker-org>`, while setting `repository.full_name = <victim-org>/<victim-repo>` inside the same signed payload. Verification passes (because it only checks the attacker's own org's secret), but the handler dispatched afterwards resolves and acts on the victim stack.

### Finding Description
The binding that should hold is:
`organization whose secret authenticated the request == organization that owns the repository the handlers act on`

Before the attacker's request:
- Each org's webhook secret only authorizes events for that org's own repositories, because GitHub itself guarantees `repository.owner.login` and `repository.full_name` are consistent in requests it forwards.

After the attacker's request:
- `verify_signature` calls `Shipit.github(organization: repository_owner)` and `github_app.verify_webhook_signature(signature, raw_post)` [1](#0-0) , where `repository_owner` is `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [2](#0-1) .
- Because the attacker controls the tenant org they name in `repository.owner.login`, they know that org's real `webhook_secret` (it is configured per-organization for this exact self-service multi-tenant use case, see `docs/setup.md:182-209` and `lib/shipit.rb#github_app_config`), so they can compute a signature that `verify_webhook_signature` accepts [3](#0-2) .
- Once past `verify_signature`, `WebhooksController#create` dispatches to `Shipit::Webhooks.for_event(event)` handlers with the raw, attacker-controlled `params` [4](#0-3) .
- Every handler resolves its target stack via `Handler#stacks`, which looks up `Repository.from_github_repo_name(repository_name)` where `repository_name = payload.dig('repository', 'full_name')` [5](#0-4)  — a field that was never used or constrained during signature verification.

So the attacker breaks the equality: the org that authenticated the request (their own) is no longer the org whose repository is written (the victim's), because the two payload fields are independently controllable in a request the attacker crafts directly against the `/webhooks` endpoint rather than one relayed unmodified by GitHub.

### Impact Explanation
The `push` handler calls `stack.sync_github(expected_head_sha: params.after)` for every not-archived stack on the matching branch of the resolved (victim) repository [6](#0-5) , which enqueues `GithubSyncJob` to fetch commits with the *victim* stack's own installed GitHub App credentials and can trigger continuous-deployment auto-deploys once new/expected commits are synced [7](#0-6) . This lets an attacker who only controls an unrelated tenant organization force sync/deploy timing on a victim's stack, i.e., an unauthorized-deploy trigger crossing an organizational trust boundary that Shipit's multi-tenant secret model is explicitly meant to enforce. This is a High/Critical-class impact ("unauthorized deploy" / cross-repository writes) under the stated impact criteria.

### Likelihood Explanation
This requires only that the deployment: (1) uses the documented multi-organization GitHub App configuration (`docs/setup.md`), and (2) the attacker administers one such tenant organization (self-service scenario, zero privilege on the victim). No GitHub session, `ApiClient` token, or victim credentials are needed — only knowledge of the attacker's own configured `webhook_secret`, which they legitimately possess for their own org.

### Recommendation
In `Handler#repository_name`/`Handler#stacks`, cross-validate that the repository's owner (`payload.dig('repository','owner','login')`) matches the organization whose secret verified the request, or have `WebhooksController#verify_signature` derive the organization strictly from `repository.full_name`'s owner segment (the same field the handlers actually trust) rather than a separate, independently-forgeable field.

### Proof of Concept
1. Attacker sets up their own GitHub organization `attacker-org` and installs a Shipit-compatible GitHub App on it per `docs/setup.md`'s "Using Multiple GitHub Applications" instructions, obtaining `webhook_secret_attacker`.
2. Attacker crafts a `push` event JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<victim head sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC_SHA1(webhook_secret_attacker, body)` and POSTs to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` resolves `repository_owner` = `"attacker-org"`, fetches `Shipit.github(organization: "attacker-org")`, and the HMAC check passes because the attacker used their own genuine secret.
5. `Shipit::Webhooks::Handlers::PushHandler` runs `Handler#stacks`, which looks up `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `stack.sync_github(expected_head_sha: ...)` on the victim's stack — an action the attacker had no authorization to trigger.

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
