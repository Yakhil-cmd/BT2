### Title
Webhook signature verification keys off an attacker-controlled `repository.owner.login`/`organization.login` field that is decoupled from the `repository.full_name` actually used to locate and mutate the target stack - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
In multi-organization Shipit deployments (`Shipit.github_organizations`), `WebhooksController#verify_signature` selects *which* organization's `webhook_secret` to HMAC-verify the request against by reading `repository.owner.login` (or `organization.login`) straight out of the unauthenticated JSON body, before the signature has been checked [1](#0-0) [2](#0-1) . Once verification "passes", the actual event handlers (e.g. `PushHandler`, `StatusHandler`) resolve the target `Stack`/`Repository` using a *different* field from the same body, `repository.full_name` [3](#0-2) . Nothing binds `repository.owner.login` to `repository.full_name`; they are independent, attacker-supplied strings in the same JSON payload.

### Finding Description
`GitHubApp#verify_webhook_signature` will HMAC-verify the raw body using whichever organization's `webhook_secret` `Shipit.github(organization:)` returns, but critically **returns `true` unconditionally if that organization's `webhook_secret` is blank/unconfigured**: [4](#0-3) . The double-github-app test fixture demonstrates that it is a supported, real configuration for an organization to have `webhook_secret: # nil` [5](#0-4) [6](#0-5) .

The verified binding that the engine implicitly relies on is:
`organization used to select the webhook_secret for signature verification == organization that owns the repository whose Stack gets mutated by the handler`

Both sides of that equality are derived from the *same unauthenticated payload*, but from *different, independently-controllable fields*:
- LHS: `params.dig('repository','owner','login') || params.dig('organization','login')` [2](#0-1) 
- RHS: `payload.dig('repository', 'full_name')`, parsed independently by `Handler#repository_name` and used to resolve `Repository.from_github_repo_name` / `stacks` [3](#0-2) [7](#0-6) .

If any organization configured on the instance has no `webhook_secret` (a valid, documented configuration state, not a leaked-secret scenario), an attacker can craft a POST to `/webhooks` with:
- `repository.owner.login` (or `organization.login`) = the org with no configured `webhook_secret` → `verify_signature` calls `Shipit.github(organization: that_org)`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` regardless of the actual `X-Hub-Signature` header (no secret to check against at all) [4](#0-3) .
- `repository.full_name` = `"victim-org/some-repo"`, a real repository belonging to a *different*, properly-secured organization on the same instance.

`PushHandler` (or `StatusHandler`, `CheckSuiteHandler`, etc.) then looks up stacks purely from `repository.full_name` [8](#0-7)  and enqueues `GithubSyncJob` for the victim org's real `Stack`, which resyncs commits and updates deploy state using the *victim* org's GitHub App credentials [9](#0-8) . The `check_if_ping`/`drop_unhandled_event`/`verify_signature` before_actions never cross-check that the owner used for verification matches the repository actually processed.

### Impact Explanation
This breaks the "an organization that authenticated versus the repository that is written" binding called out in scope: signature verification authenticates against one organization while the mutation (stack sync / commit ingestion / deploy-state change) is performed against a repository belonging to a completely different organization hosted on the same Shipit instance. This is a cross-repository/cross-organization write achieved without possessing any organization's real `webhook_secret`, satisfying the Critical bar ("cross-repository writes... unauthorized deploy"), because forged `push`/`status`/`check_suite` events can trigger `GithubSyncJob`, commit creation, and downstream automatic deploy/merge flows for a repository the attacker does not control, as long as any other org on the same instance has an unset `webhook_secret`.

### Likelihood Explanation
Requires: (1) a multi-organization Shipit deployment (explicitly supported, as shown by `github_app_config`/`github_organizations`), and (2) at least one configured organization with no `webhook_secret` set — a state the codebase itself ships as a valid example configuration (`webhook_secret: # nil`) rather than an edge case. No possession of any real secret, API token, or session is required; the attacker only needs to know the victim org/repo name (public information) and the name of any laxly-configured sibling organization on the instance. This is a plausible, low-effort misconfiguration-triggered path rather than a purely theoretical one.

### Recommendation
- Do not allow `verify_webhook_signature` to return `true` when `webhook_secret` is blank; instead reject (422) or require every configured GitHub App organization to have a non-blank `webhook_secret`.
- Bind signature verification to the *same* repository identity the handlers act on: derive `repository_owner` from `repository.full_name`'s owner segment (or verify that `repository.owner.login` == the owner segment of `repository.full_name`) before dispatching to handlers, so the org used to select the secret is provably the org whose data is mutated.

### Proof of Concept
1. Configure Shipit with two organizations, `SecureOrg` (valid `webhook_secret`) and `LaxOrg` (no `webhook_secret`, as in `test/dummy/config/secrets_double_github_app.yml`) [10](#0-9) .
2. `SecureOrg/victim-repo` has a tracked `Stack` in Shipit.
3. Attacker POSTs to `/webhooks` with header `X-Github-Event: push`, any `X-Hub-Signature` value, and body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": { "full_name": "SecureOrg/victim-repo", "owner": { "login": "LaxOrg" } }
}
```
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "LaxOrg")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally [4](#0-3) .
5. `PushHandler#process` resolves stacks via `repository.full_name` = `"SecureOrg/victim-repo"` [11](#0-10) [3](#0-2) , and enqueues `GithubSyncJob` for the real victim stack with attacker-supplied `expected_head_sha`, causing Shipit to sync/act on SecureOrg's repository despite the request never being authenticated by SecureOrg's secret.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** test/dummy/config/secrets_double_github_app.yml (L6-7)
```yaml
      bot_login: "shipit[bot]"
      webhook_secret: # nil
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
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
