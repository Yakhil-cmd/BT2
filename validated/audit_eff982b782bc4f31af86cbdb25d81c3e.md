### Title
Webhook signature verification is keyed to the organization named in the (unverified) payload, not to the repository the handlers act on - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App / `webhook_secret` to check against by reading `repository.owner.login` (or `organization.login`) straight out of the still‑unverified JSON body, and then delegates to `GitHubApp#verify_webhook_signature`, which returns `true` unconditionally when that organization has no `webhook_secret` configured. Once "verified", the same raw payload is handed to `Shipit::Webhooks::Handlers::Handler`, whose `repository_name`/`stacks` lookup uses a *different* payload field — `repository.full_name` — via `Repository.from_github_repo_name`, with no cross-check that this repository belongs to the organization that was used to select the signing secret.

### Finding Description
The binding that should hold is: `organization used to authenticate the webhook == owner of the repository the handlers mutate`. This binding is never enforced.

- `repository_owner` is derived from the raw, unauthenticated JSON before any signature check: [1](#0-0) 
- That value selects which `GitHubApp`/secret to verify against: [2](#0-1) 
- `GitHubApp#verify_webhook_signature` returns `true` unconditionally when the selected organization has no `webhook_secret` set (an explicitly supported, optional configuration per the setup docs): [3](#0-2) 
- The handlers dispatched after "verification" resolve the target repository/stack from a *different* JSON field, `repository.full_name`, with no relation back to `repository_owner`: [4](#0-3)  and via `Repository.from_github_repo_name`, which does a global lookup across all owners: [5](#0-4) 

Because Shipit supports multiple GitHub Apps/organizations simultaneously (`docs/setup.md`'s "Using Multiple GitHub Applications" section, and `Shipit.github_organizations`/`github_app_config` in `lib/shipit.rb`), an attacker only needs to know of, or guess, one organization in the installation that has no `webhook_secret` configured (webhook secret is documented as optional) — they do not need any secret at all. They then craft a POST to `/webhooks` where:
- `repository.owner.login` (or `organization.login`) = the unsecured organization → `verify_signature` passes unconditionally.
- `repository.full_name` = `victim-org/victim-repo`, a repository actually tracked by Shipit under a *different*, properly secured organization.

The push handler then acts on that forged payload: [6](#0-5) , calling `stack.sync_github(expected_head_sha: params.after)`, which enqueues `GithubSyncJob` to fetch commits/spec state for the victim's stack using the app's real GitHub credentials against `victim-org/victim-repo`: [7](#0-6) . Other handlers (pull_request `opened`/`labeled`/`reopened`, etc.) similarly resolve `repository` purely from `full_name` with no ownership cross-check: [8](#0-7) , [9](#0-8) .

Before/after comparison of the broken equality:
- Before (intended): `authenticated_org(payload) == owner(repository acted upon)` for every processed event.
- After (actual): `authenticated_org(payload)` is only used to pick a secret (which may not even exist), while `owner(repository acted upon)` is read from an independent, unchecked field (`repository.full_name`). The two are never compared.

### Impact Explanation
This lets an unprivileged attacker force Shipit to re-sync/process events for a repository/stack they do not control, using an org they picked purely because it lacks a configured webhook secret. Depending on which handler fires, this can trigger stack archive/unarchive, PR-label-driven review-stack provisioning, or forced re-sync of commit history/spec cache (`GithubSyncJob` → `CacheDeploySpecJob`) for an arbitrary tracked repository — i.e., cross-repository state manipulation without possessing any of that repository's credentials. This matches the "cross-repository writes" / "unauthorized deploy-adjacent action" impact class, since sync/cache-spec results feed directly into what `MainVault`-equivalent deploy machinery in Shipit (stack deploy pipeline) later trusts as the current head/spec.

### Likelihood Explanation
Requires only: (a) the Shipit instance configured with multiple GitHub organizations (a documented, supported configuration), and (b) at least one of those organizations left without a `webhook_secret` (explicitly documented as optional). No GitHub App private key, session, or `ApiClient` token is required — purely an unauthenticated HTTP POST to the public `/webhooks` endpoint. This is a realistic misconfiguration given the docs literally mark `webhook_secret` as optional per-organization.

### Recommendation
After resolving the target repository/stack from `repository.full_name`, verify that its `owner` matches the organization that was used to select/validate the webhook signature (i.e., bind `repository_owner` from `WebhooksController` into the handler dispatch and reject/drop events where they diverge). Additionally, consider requiring `webhook_secret` to be present for every configured organization, or refusing unsigned events entirely when multiple organizations are configured.

### Proof of Concept
1. Configure Shipit with two orgs in `config/secrets.yml`: `secure-org` (with `webhook_secret` set) tracking repo `secure-org/app`, and `insecure-org` (no `webhook_secret`, or omitted) with no tracked repos.
2. Have Shipit track a stack for `secure-org/app`.
3. POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": { "owner": { "login": "insecure-org" }, "full_name": "secure-org/app" }
}
```
No `X-Hub-Signature` header (or any value) is required — `verify_signature` looks up `insecure-org`, which has no secret, so `verify_webhook_signature` returns `true` (`lib/shipit/github_app.rb:76-77`).
4. `PushHandler` resolves stacks via `repository.full_name = "secure-org/app"` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`, `app/models/shipit/webhooks/handlers/push_handler.rb`) and enqueues `GithubSyncJob` for the `secure-org/app` stack — an event the attacker was never authorized to send for that organization.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-54)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L41-68)
```ruby
          def process
            return unless respond_to_label_change?

            handle
          end

          private

          def handle
            if archive?
              stack.archive!
            elsif unarchive?
              stack.unarchive!
            end

            stack
          end

          def stack
            @stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end

          def repository
            @repository ||= Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
                            Shipit::NullRepository.new
          end
```
