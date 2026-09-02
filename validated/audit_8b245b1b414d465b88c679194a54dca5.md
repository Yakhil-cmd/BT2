### Title
Webhook signature is verified against an org derived from an unverified payload field, letting an attacker impersonate any repository - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` picks *which* GitHub App / webhook secret to use for HMAC verification based on `repository_owner`, a value read straight out of the still-unauthenticated JSON body. The event handlers, however, resolve the target `Stack`/`Repository` from a *different* field of that same unauthenticated body (`repository.full_name`). Because these two fields are never checked for consistency, and because a multi-org Shipit deployment can legitimately contain an organization with no `webhook_secret` configured, an attacker can pick the "no secret" organization to trivially satisfy the signature check while pointing the actual payload at a completely different, secret-protected organization's repository/stack.

### Finding Description
`verify_signature` computes the organization used to select a `GitHub App` config from the raw, unverified payload: [1](#0-0) [2](#0-1) 

`repository_owner` is `params.dig('repository', 'owner', 'login')`, taken directly from the attacker-supplied JSON, before any signature validation has occurred. This value is then used to fetch a `GitHubApp` instance whose `webhook_secret` is used to verify the `X-Hub-Signature` header: [3](#0-2) 

Critically, `verify_webhook_signature` returns `true` unconditionally when the target organization's `webhook_secret` is blank/unset — a state that is explicitly documented as valid for multi-organization configuration: [4](#0-3) 

Once `verify_signature` passes, `WebhooksController#create` dispatches the *entire* raw payload to the registered handlers: [5](#0-4) 

The handlers, however, determine the *target* repository/stack from a different key of the same payload — `repository.full_name` — with no cross-check against the `repository.owner.login` value used for signature-org selection: [6](#0-5) [7](#0-6) 

This breaks the intended equality: `organization used to authenticate the webhook == organization owning the repository being acted upon`. An attacker who knows (or can trivially satisfy, e.g. via an org with no configured secret) the signature check for organization `A` can submit a payload whose `repository.owner.login = A` (to select `A`'s lenient/no-secret verification path) but whose `repository.full_name = "B/target-repo"` (a repository under organization `B`, which is properly secret-protected). The signature check passes using `A`'s (non-existent) secret, yet the `PushHandler` acts on `B`'s repository, calling `stack.sync_github(expected_head_sha: params.after)` with an attacker-chosen SHA: [8](#0-7) 

This queues `GithubSyncJob`, which fetches commits from GitHub for the target stack and can affect the stack's known commit history/state (`append_commit`, `stack.lock_reverted_commits!`) using attacker-influenced `expected_head_sha`, all without ever having had the payload's authenticity validated by the actual owning organization's secret.

### Impact Explanation
This breaks the deployment-trust binding between "the organization whose secret authenticated the webhook" and "the repository/stack that is actually written to" — one of the explicitly in-scope analog classes. A successful forgery lets an unprivileged network attacker inject forged GitHub webhook events (`push`, `pull_request`, `status`, `membership`, etc.) that are processed by Shipit as if legitimately signed by the target repository's own GitHub App, potentially triggering unintended `GithubSyncJob` runs, spurious commit statuses, or membership/team changes that feed into deploy authorization (`Shipit.github_teams`) — satisfying the High severity bar for "unauthenticated read/write of stack state" and escalation into `Shipit.github_teams` authorization-adjacent state.

### Likelihood Explanation
Exploitability requires only: (1) the deployment to be configured for multiple GitHub organizations (a documented, supported configuration — see `TOP_LEVEL_GH_KEYS` handling in `lib/shipit.rb#github_default_organization`), and (2) at least one configured organization having no `webhook_secret` set (also an explicitly documented/valid state, e.g. `config/secrets.development.shopify.yml`). Given that, no authentication, tokens, or secrets are needed — the attacker only needs to know the org name with no secret and the target repository's `full_name`, both of which are typically public information (org/repo names are public on GitHub).

### Recommendation
Bind signature verification to the same repository/organization identity that handlers act upon: require `repository.owner.login` (or `organization.login`) used for signature verification to match the resolved target `Repository`'s actual owner before dispatching to handlers, and/or refuse to treat a missing `webhook_secret` as an implicit "always verified" pass for any organization other than the single-org legacy configuration. At minimum, reject webhook payloads where the signing organization does not equal the owner embedded in `repository.full_name`.

### Proof of Concept
1. Configure Shipit with two organizations: `orgA` (no `webhook_secret` set) and `orgB` (has a `webhook_secret`, and owns a tracked repository `orgB/target-repo` with an active stack).
2. As an unauthenticated attacker, POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "repository": {
    "owner": { "login": "orgA" },
    "full_name": "orgB/target-repo"
  },
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>"
}
```
No `X-Hub-Signature` needs to be valid for `orgB`; `verify_signature` resolves `repository_owner` = `orgA`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally (`lib/shipit/github_app.rb:76-77`).
3. `WebhooksController#create` dispatches the payload to `Shipit::Webhooks::Handlers::PushHandler`, which resolves the stack via `payload.dig('repository','full_name')` = `orgB/target-repo` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")`, queuing `GithubSyncJob` against `orgB`'s stack despite the request never being authenticated by `orgB`'s secret.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-27)
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

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
    end
  end
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
