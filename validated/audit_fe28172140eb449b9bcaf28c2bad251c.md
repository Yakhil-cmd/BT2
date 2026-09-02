### Title
Cross-organization webhook signature/action mismatch allows unauthorized sync of arbitrary stacks - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
`WebhooksController` selects the GitHub App/webhook secret used to *verify* an inbound webhook based on `repository.owner.login` (or `organization.login`), but the event handlers (e.g. `PushHandler`) subsequently select *which stack to act on* based on the unrelated `repository.full_name` field of the same payload. Because these two fields are never checked for consistency, a party who legitimately knows the `webhook_secret` for one onboarded GitHub organization in a multi-tenant Shipit deployment can forge a signed webhook whose `owner.login` matches their own organization (so it passes signature verification) while its `full_name` points at a completely different, victim organization's tracked repository — causing Shipit to sync/act on the victim's stack.

### Finding Description
`WebhooksController#verify_signature` computes the verifying key from `repository_owner`: [1](#0-0) [2](#0-1) 

`repository_owner` is `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`. This is used only to pick which per-organization `GitHubApp`/`webhook_secret` (`Shipit.github(organization: ...)`) validates `X-Hub-Signature` over the raw body: [3](#0-2) [4](#0-3) 

Once the signature is accepted, the entire raw JSON body is handed unchanged to the registered handler, e.g. `PushHandler`: [5](#0-4) [6](#0-5) 

But the handler determines *which repository/stacks to operate on* from a different field, `repository.full_name`, via the shared `Handler#stacks`/`#repository_name` helper: [7](#0-6) 

Nothing ties `repository.owner.login` (the field used to select the signing key) to `repository.full_name` (the field used to select the acted-upon `Repository`/`Stack`). This is the exact bug-class analog from the report: a value is verified/authorized under one identity/type, while an unrelated value in the same object drives the actual privileged action ("Convex specifies `rewardContract` to be a `VirtualBalanceRewardPool`... but ... uses it as an ERC20 token" — here, Shipit authenticates the *organization* but acts on the *repository field*, which is never bound to that authenticated organization).

In a multi-tenant Shipit instance (`Shipit.github_organizations`/`secrets.github` keyed per-org, each with its own `webhook_secret`), any org that is onboarded is handed its own `webhook_secret` to configure on its GitHub webhook. That org's administrator is, from Shipit's perspective, an "unprivileged" actor with respect to every other org's stacks — they hold no Shipit session, `ApiClient` token, or the victim org's `webhook_secret`, only their own.

### Impact Explanation
Using only their own organization's `webhook_secret` (a credential they are expected to hold to operate a legitimate integration), an attacker can craft and correctly sign a payload whose `repository.owner.login` is their own org (satisfies `verify_signature`) but whose `repository.full_name` names any other tracked repository in the same Shipit instance. This is dispatched to `PushHandler`, which resolves `stacks` for the victim's `Repository.from_github_repo_name(repository_name)` and calls `stack.sync_github(expected_head_sha:)`, enqueuing `GithubSyncJob` for the victim stack: [8](#0-7) 

This job writes new `Commit` records into the victim stack (`stack.commits.create_from_github!`) and can trigger `CacheDeploySpecJob`, all without any credential belonging to the victim organization — an unauthorized cross-repository write triggered purely by presenting a payload signed with a different (attacker-controlled) organization's secret. If the victim stack has continuous deployment enabled, forcing a resync can also force premature discovery/deploy of already-pushed commits outside the intended trust boundary.

### Likelihood Explanation
Exploitability requires only knowledge of one legitimate, already-onboarded organization's `webhook_secret` (which that org's own administrators possess by design, to configure their GitHub webhook) plus the ability to send an arbitrary HTTP POST to the public `/webhooks` endpoint — no Shipit session, `ApiClient` token, or victim credentials are needed. In any multi-organization Shipit deployment this is directly reachable by any onboarded organization against any other tracked repository.

### Recommendation
Bind the field used for signature-key selection to the field used for the actual action: after verifying the signature, re-derive (or double-check) that `repository.full_name`'s owner matches the `repository_owner`/organization whose secret validated the request, and reject the webhook otherwise. Alternatively, resolve the target `Repository`/`Stack` strictly through the same organization identity that was cryptographically verified, rather than through an independent, unauthenticated payload field.

### Proof of Concept
1. Attacker legitimately administers GitHub organization `attacker-org`, which is onboarded into a shared Shipit instance with its own `webhook_secret_A` (`secrets.github[:attacker_org][:webhook_secret]`).
2. Attacker crafts a push payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(webhook_secret_A, body)` and POSTs to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` calls `Shipit.github(organization: "attacker-org")` and validates successfully against `webhook_secret_A`.
5. `PushHandler.call(params)` resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and enqueues `GithubSyncJob` for the victim's stack, causing Shipit to fetch and persist new commits for a stack the attacker has no authorization over.

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
