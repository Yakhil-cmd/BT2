### Title
Webhook signature verification authenticates the payload's `repository.owner.login` organization but write actions are keyed on the unrelated `repository.full_name` field, allowing cross-organization triggering of stack syncs - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`Shipit::WebhooksController` selects which GitHub App/webhook secret to verify a webhook against using the organization name found in the *unverified* JSON body, but every event handler resolves the target `Repository`/`Stack` to act on using a *different* field of that same unverified body. In a multi-tenant Shipit install (multiple GitHub Apps/orgs configured), this breaks the intended binding "organization whose signature was verified" == "repository that gets written to."

### Finding Description
`WebhooksController#verify_signature` picks the `GitHubApp` (and thus the secret used for HMAC verification) using `repository_owner`, itself read straight from the raw, not-yet-verified request body: [1](#0-0) [2](#0-1) 

Shipit supports multiple independently configured GitHub Apps/organizations, each with its own `webhook_secret` (`Shipit.github(organization:)`, confirmed by the multi-org secrets fixture): [3](#0-2) [4](#0-3) 

Once the signature is accepted, every handler resolves *which repository/stack to act on* not from the verified `repository.owner.login`, but from `repository.full_name` (owner+name), a sibling field of the same unverified JSON body: [5](#0-4) [6](#0-5) 

`Repository.from_github_repo_name` does a direct DB lookup by owner/name with no relation whatsoever to which organization's secret validated the request: [7](#0-6) 

Because HMAC verification only proves "this exact byte blob was signed with organization X's secret," and organization X is picked from a field inside that same attacker-influenced blob, an actor who legitimately administers their *own* GitHub organization/App integration (and therefore legitimately knows their own org's `webhook_secret`, without needing any Shipit session, ApiClient token, or GitHub App private key belonging to the target) can hand-craft an arbitrary JSON payload, set `repository.owner.login`/`organization.login` to their own org (so `verify_signature` succeeds using their own known secret), but set `repository.full_name` to any other tenant's repository (e.g. `push_handler.rb`'s `repository_name`). That payload is accepted as valid and dispatched to handlers that act on the named victim repository/stack.

### Impact Explanation
A push-event payload crafted this way causes `PushHandler#process` to enqueue `GithubSyncJob` for a completely unrelated stack: [8](#0-7) 
`GithubSyncJob` then writes `Commit` records into that victim stack and can mark it as accessible/inaccessible: [9](#0-8) 

This is a write into a stack/repository the calling organization has no authorized relationship with, purely because the "authenticated organization" binding and the "repository that gets written" binding are decoupled — matching the analog class of "an organization that authenticated versus the repository that is written." If the targeted stack has continuous deployment enabled, forcing an out-of-band/early sync can also force premature deploy pipeline activity for a stack outside the caller's own organization.

### Likelihood Explanation
Requires only knowledge of one's *own* legitimately configured webhook secret in a Shipit instance that hosts multiple GitHub Apps/organizations — no Shipit session, ApiClient token, or victim-org credentials are needed. Multi-tenant configuration is a supported, documented mode (see `secrets_double_github_app.yml`), so the precondition is realistic wherever Shipit is deployed to serve more than one GitHub organization.

### Recommendation
Bind the entire handler dispatch — not just secret selection — to the same organization that was cryptographically verified. Concretely: after `verify_signature` succeeds for organization `repository_owner`, require that `repository.full_name`'s owner segment matches `repository_owner` (or `organization.login`) before invoking any handler, and reject/drop the webhook otherwise.

### Proof of Concept
1. Configure Shipit with two GitHub App tenants, `OrgAttacker` and `OrgVictim`, each with distinct `webhook_secret`s (as in `test/dummy/config/secrets_double_github_app.yml`).
2. As the administrator of `OrgAttacker` (who legitimately knows `OrgAttacker`'s webhook secret, with no access to Shipit or `OrgVictim`), craft a `push` event JSON body:
   ```json
   {
     "ref": "refs/heads/main",
     "after": "<any_sha>",
     "repository": {
       "owner": { "login": "OrgAttacker" },
       "full_name": "OrgVictim/some-repo"
     }
   }
   ```
3. Compute `X-Hub-Signature` as `sha1=HMAC-SHA1(OrgAttacker_webhook_secret, raw_body)`.
4. POST to `/github/webhooks` with header `X-Github-Event: push`.
5. `verify_signature` resolves `repository_owner` = `"OrgAttacker"`, looks up `Shipit.github(organization: "OrgAttacker")`, and the signature validates successfully.
6. `PushHandler#process` resolves the target stack via `repository.full_name` = `"OrgVictim/some-repo"`, and enqueues `GithubSyncJob` for `OrgVictim`'s stack — an action the `OrgAttacker` administrator has no legitimate authorization to trigger.

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

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
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

**File:** app/jobs/shipit/github_sync_job.rb (L18-53)
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

    def append_commit(gh_commit)
      stack.commits.create_from_github!(gh_commit)
    end
```
