### Title
Webhook signature verification is bound to `repository.owner.login`, but stack writes are bound to `repository.full_name` — cross-organization webhook forgery ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to verify a request against using `repository_owner`, taken from `params.dig('repository', 'owner', 'login')` (or `organization.login`) — a field inside the unauthenticated JSON body [1](#0-0) [2](#0-1) . Every event handler, however, resolves the actual `Repository`/`Stack` that gets acted upon using a *different* field from the same body, `payload.dig('repository', 'full_name')` [3](#0-2) . Nothing binds these two fields together, so the organization whose secret authenticated the request is not guaranteed to be the organization that is actually written to.

### Finding Description
Shipit supports multi-tenant GitHub App configuration, where each organization has its own (optional) `webhook_secret` [4](#0-3) . `GitHubApp#verify_webhook_signature` explicitly treats an unset secret as "always verified": [5](#0-4) 

`WebhooksController#verify_signature` picks *which* app/secret to use for verification from the attacker-controlled `repository.owner.login` (or `organization.login`) field of the JSON body: [1](#0-0) [2](#0-1) 

If that instance hosts at least two organizations where one has no `webhook_secret` configured (documented as optional) and another has a real, secret-protected organization with tracked stacks, an attacker can craft a webhook body where:
- `repository.owner.login` = the unprotected organization (so `verify_signature` accepts the request unconditionally, since `verify_webhook_signature` returns `true` when `webhook_secret` is blank), while
- `repository.full_name` = `"<protected-org>/<repo>"`, which is what every handler actually uses to look up the `Repository`/`Stack` to act on: [3](#0-2) [6](#0-5) [7](#0-6) 

This is the exact binding break called out in the rules: "an organization that authenticated versus the repository that is written." The signature-check identity (`repository.owner.login`) and the write-target identity (`repository.full_name`) are two independently attacker-controlled fields in the same unauthenticated payload, and the controller never checks that they refer to the same organization.

### Impact Explanation
By exploiting this decoupling, an unprivileged attacker with no valid signature for a protected organization can force `PushHandler` to run against that organization's real, tracked `Stack`, invoking `stack.sync_github(expected_head_sha:)` via `GithubSyncJob`, which fetches real commits from GitHub using the app's own installation token and calls `CacheDeploySpecJob` [8](#0-7) . For any stack with a continuous-delivery schedule enabled, this attacker-triggered sync can cause an unauthorized deploy to be scheduled/kicked off outside of the legitimate GitHub webhook flow, i.e., at a time and cadence the attacker controls rather than the protected organization's actual GitHub activity — a forged trigger for an unauthorized deploy, matching the "unauthorized deploy" impact category. The same decoupling affects other handlers keyed on `repository.full_name` (`status`, `check_suite`, pull-request handlers), letting an attacker forge commit statuses, provisioning/archival actions, and review-stack lifecycle events against a protected repository while only holding (or having none of) the secret for an unrelated, unprotected organization on the same instance.

### Likelihood Explanation
Requires: (1) a multi-organization Shipit deployment (explicitly documented/supported configuration), (2) at least one configured organization without a `webhook_secret` (explicitly documented as optional), and (3) a target stack under a different, protected organization. This is a realistic operational configuration (e.g., one internal org with an app that hasn't set a webhook secret, alongside a production org that has). No GitHub credentials, Shipit session, or API token are required — only knowledge of the target's `owner/name` full name and the ability to POST to `/webhooks`.

### Recommendation
Verify the webhook signature using the same field the handlers use to select the write target (`repository.full_name`'s owner), not a separately-read `repository.owner.login`/`organization.login`. Additionally, reject (or independently validate) events where `repository.owner.login` does not match the owner segment of `repository.full_name`, and consider disallowing globally unauthenticated webhooks (blank `webhook_secret`) for instances that also host protected organizations.

### Proof of Concept
1. Configure two orgs in `secrets.yml`: `orgA` (no `webhook_secret`) and `orgB` (has `webhook_secret`, has a Shipit stack `orgB/prod-app` tracked).
2. Attacker sends `POST /webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/master",
  "after": "<some sha>",
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/prod-app" }
}
```
without any valid `X-Hub-Signature` (or an arbitrary one).
3. `WebhooksController#verify_signature` resolves `Shipit.github(organization: "orgA")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally [5](#0-4) .
4. `PushHandler#process` resolves the stack via `Repository.from_github_repo_name("orgB/prod-app")` [3](#0-2)  and enqueues `GithubSyncJob` for `orgB`'s protected stack, even though the request was never authenticated against `orgB`'s secret.

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

**File:** docs/setup.md (L20-30)
```markdown
## Creating the GitHub App

Shipit needs a GitHub App to authenticate users, receive Webhooks and access the API.

You can create a new one for your organization at `https://github.com/organizations/<your-org>/settings/apps/new`, or [https://github.com/settings/apps/new](https://github.com/settings/apps/new) for a regular user.

  - Homepage URL: The URL where Shipit will be deployed, e.g. `https://example.com`.
  - User authorization callback URL: It must be set to `<homepage>/github/auth/github/callback`, e.g. `https://example.com/github/auth/github/callback`.
  - Setup URL: Leave it empty.
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
