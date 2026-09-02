### Title
Webhook signature is verified against `repository.owner.login`-selected secret while the repository that is actually written/synced is resolved from the unauthenticated `repository.full_name` field - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
In multi-organization deployments, `WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to HMAC-verify the request against using `repository_owner`, taken from `params.dig('repository', 'owner', 'login')` (or `organization.login`) [1](#0-0) , [2](#0-1) . But the handler that actually resolves the target `Repository`/`Stack` and performs writes (queuing `GithubSyncJob`, creating commits, statuses, etc.) resolves it from a different field, `repository.full_name`, via `Handler#repository_name`/`stacks` [3](#0-2)  and `Repository.from_github_repo_name` [4](#0-3) . Nothing enforces that the owner segment of `repository.full_name` matches `repository.owner.login`.

### Finding Description
`Shipit.github(organization:)` supports per-organization GitHub App configs, each with its own `webhook_secret`, looked up via `github_app_config(organization)` [5](#0-4) . The webhook signature check binds "the organization whose secret was used to authenticate this HTTP request" to `repository_owner` (`repository.owner.login`/`organization.login`), which is attacker-controlled JSON in the request body itself, not something derived from the verified GitHub App installation identity [6](#0-5) .

Once the HMAC check passes, `WebhooksController#create` dispatches the entire raw JSON body to the event handler [7](#0-6) . `PushHandler` (and other handlers derived from `Handler`) resolve the target stacks purely from `repository.full_name`, ignoring `repository.owner.login` entirely [8](#0-7) , [3](#0-2) .

This is exactly the class of "binding break" called out in the rules: **an organization that authenticated versus the repository that is written**. The field consumed for choosing/validating the cryptographic secret (`owner.login`) is not the same field consumed for the write-side repository resolution (`full_name`). An attacker who legitimately controls one organization's webhook secret (e.g., they operate their own org onboarded to this multi-tenant Shipit instance, and know/derive their own `webhook_secret`) can compute a valid HMAC over a crafted payload where:
- `repository.owner.login` = their own org (so `Shipit.github(organization: repository_owner)` picks their own, known, `webhook_secret`, and the signature check passes), while
- `repository.full_name` = `"victim-org/victim-repo"` (so the handler resolves and acts on a `Stack` belonging to a completely different organization that they have no legitimate webhook relationship with).

### Impact Explanation
This lets an attacker who is a legitimate tenant of one organization on a shared Shipit instance forge webhook events (push, status, check_suite, membership, pull_request, etc.) that are processed as if they originated from GitHub for an unrelated victim organization's repository/stack, causing:
- Spurious `GithubSyncJob` enqueues and commit ingestion against a victim's `Stack` [9](#0-8) .
- Injection of fabricated commit `Status`/`check_suite` state, or `pull_request`/`membership` mutations against a repository the attacker does not control, all gated only by their own org's secret rather than the victim org's secret.

This crosses the "cross-repository writes" impact bar defined in the rules, since the write path (repository/stack resolution and downstream job enqueue/commit/status creation) is bound to a different, unauthenticated field than the one the signature actually authenticates.

### Likelihood Explanation
Requires:
1. A multi-organization Shipit deployment (config keyed by organization with distinct `webhook_secret`s per `github_app_config`) [10](#0-9) .
2. The attacker to be a legitimate onboarded tenant/organization on that instance possessing a valid `webhook_secret` for their own org — not a random external attacker, but also not requiring compromise of the victim org's secret, GitHub App private key, or Shipit session/API token.

Given that requirement, the exploit itself is a single crafted HTTP POST with a valid HMAC computed against the attacker's own secret; no race condition, no GitHub-side cooperation needed.

### Recommendation
Do not derive the trust boundary from attacker-supplied JSON fields alone. Bind webhook processing to the GitHub App installation identity that actually delivered the webhook (e.g., verify against `X-GitHub-Hook-Installation-Target-ID`/App installation, or re-derive `repository_owner` strictly for secret selection and then re-validate, post-verification, that the resolved `Repository`/`Stack` for `repository.full_name` belongs to that same authenticated organization before dispatching to handlers). At minimum, add a check in `WebhooksController#verify_signature`/`#create` (or centrally in `Handler`) asserting `repository.full_name.split('/').first == repository_owner` (case-insensitively) before processing, and reject/`head(422)` on mismatch.

### Proof of Concept
1. Deploy this engine in multi-org mode with two orgs configured, e.g. `attacker-org` (webhook_secret `S_A`, known to the attacker because they administer that org's GitHub App/webhook config) and `victim-org` (webhook_secret `S_V`, unknown to the attacker), both onboarded to the same Shipit instance, `victim-org/victim-repo` has an existing `Stack`.
2. Attacker crafts a JSON push payload body:
   ```json
   {
     "ref": "refs/heads/master",
     "after": "<attacker-chosen sha>",
     "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
   }
   ```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(S_A, body)>` using their own known secret `S_A`.
4. POST to `/github/webhooks` with `X-Github-Event: push`.
5. `verify_signature` calls `Shipit.github(organization: "attacker-org")`, which resolves to the attacker's own `GitHubApp` config, whose `verify_webhook_signature` succeeds because the attacker used their own valid secret `S_A` over the exact body [6](#0-5) , [11](#0-10) .
6. `Shipit::Webhooks.for_event("push")` dispatches to `PushHandler`, which calls `stacks` → `Repository.from_github_repo_name("victim-org/victim-repo")` → the victim's `Stack`, and enqueues `sync_github(expected_head_sha: ...)` against it [12](#0-11) , [3](#0-2) .
7. Result: the attacker, authenticated only under their own organization's secret, has caused writes (job enqueue, commit ingestion) against the victim organization's stack — confirming the cross-organization write.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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

**File:** lib/shipit.rb (L170-200)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```
