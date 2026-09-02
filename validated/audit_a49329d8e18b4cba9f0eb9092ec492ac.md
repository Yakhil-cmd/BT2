## Title
Cross-organization webhook signature confusion allows triggering deploy sync for a stack in a different GitHub organization than the one whose secret signed the request - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects *which* organization's `webhook_secret` to check the HMAC signature against using the `repository.owner.login` (or `organization.login`) field of the incoming payload. The handler that actually acts on the payload (`Shipit::Webhooks::Handlers::Handler#repository_name` / `PushHandler`) instead uses the unrelated `repository.full_name` field to resolve which `Repository`/`Stack` to operate on. Because these are two independent, attacker-controlled JSON fields inside the same signed payload, and neither is cross-checked against the other, an attacker who legitimately knows one organization's webhook secret can forge a payload whose "verified organization" is their own org while the "acted-upon repository" belongs to a different, unrelated organization/stack.

### Finding Description
`verify_signature` derives the organization used to pick the GitHub App/webhook secret: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: ...)` is looked up per-organization from `secrets.github`, confirming multi-tenant configuration with **distinct webhook secrets per organization** is a supported, first-class configuration: [3](#0-2) 

Once signature verification passes for *some* organization, the raw payload is dispatched unchanged to handlers: [4](#0-3) 

The handler base class and `PushHandler`, however, determine which repository/stack to mutate using an entirely different field, `repository.full_name`, with no relation enforced to the `repository.owner.login`/`organization.login` used for signature verification: [5](#0-4) [6](#0-5) 

This breaks the trust binding: `organization whose secret authenticated the request` should equal `organization/repository being written to`, but the engine never enforces that equality.

### Impact Explanation
An attacker who knows the webhook secret of Organization A (e.g., because they are the GitHub App admin/owner for their own org onboarded onto a shared multi-tenant Shipit instance, as documented in `docs/setup.md`'s "Webhook secret (optional)" per-app setup) can:
1. Set `repository.owner.login` (or `organization.login`) to `"OrgA"` so `verify_signature` selects OrgA's secret and the HMAC computed with OrgA's known secret passes.
2. Set `repository.full_name` to `"OrgB/some-repo"` — a repository/stack belonging to a completely unrelated organization the attacker has no access to.
3. Sign the crafted `push` payload with OrgA's secret and submit it to `/webhooks`.

`verify_signature` succeeds (OrgA's secret matches), and the request is routed to `PushHandler`, which resolves stacks via `Repository.from_github_repo_name("OrgB/some-repo")` and calls `stack.sync_github(expected_head_sha: params.after)`, enqueuing `GithubSyncJob` for OrgB's stack: [7](#0-6) 

This job fetches commits from GitHub using OrgB's own credentials and appends them to OrgB's stack, and — if `continuous_deployment` is enabled on that stack — can trigger `CacheDeploySpecJob` and downstream automatic deploy logic for a stack the attacker has no authorization over. This is an unauthorized cross-organization write / unauthorized deploy trigger: the attacker crosses an organizational trust boundary using only their own (authorized) organization's webhook credential, without any GitHub write access, App installation, or session on the victim organization/repository.

### Likelihood Explanation
This requires the deployment to run shared multi-tenant Shipit with multiple `github` organization entries each holding a distinct `webhook_secret` — an explicitly documented/supported configuration (`lib/shipit.rb#github_app_config`, `TOP_LEVEL_GH_KEYS`). Any tenant/organization onboarded onto that shared instance, by definition, knows its own webhook secret, satisfying the "unprivileged attacker with respect to the victim org" requirement. No GitHub write access, App private key, or Shipit session is needed — only knowledge of one's own configured webhook secret and the ability to send an HTTP POST to the public `/webhooks` endpoint.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler#repository_name`), enforce that the organization used to select/verify the webhook secret matches the organization segment of `repository.full_name` (and `organization.login` for org-scoped events) before dispatching to handlers. Reject the webhook (422) if `repository.full_name.split('/').first` does not case-insensitively match the verified `repository_owner`.

### Proof of Concept
1. Configure Shipit with two orgs in `secrets.github`, e.g. `OrgA` (attacker's own tenant, secret known to attacker) and `OrgB` (victim tenant, stack `OrgB/victim-repo` tracked by Shipit).
2. Attacker crafts payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha-that-exists-on-github>",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=` HMAC-SHA1 of the raw JSON body using OrgA's known `webhook_secret`.
4. POST to `/webhooks` with header `X-Github-Event: push`.
5. `verify_signature` resolves `Shipit.github(organization: "OrgA")`, verifies successfully using OrgA's secret.
6. `PushHandler` resolves `Repository.from_github_repo_name("OrgB/victim-repo")` and enqueues `GithubSyncJob` for the victim's stack, causing Shipit to sync/deploy activity on `OrgB`'s stack triggered entirely by an OrgA-signed request.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-31)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-24)
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
