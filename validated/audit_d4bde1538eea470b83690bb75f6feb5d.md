### Title
Webhook signature verified against the payload's `repository.owner.login` organization while the acted-upon repository is selected by the independent `repository.full_name` field, enabling cross-organization webhook forgery in multi-app deployments - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
This is the same class of bug as the M-04 finding: a signature/authorization check is bound to one field of an attacker-supplied structure while a *different* field of that same structure is what actually gets acted upon downstream, and nothing enforces that the two fields are consistent.

### Finding Description
`WebhooksController#verify_signature` selects which GitHub App (and thus which HMAC `webhook_secret`) is used to validate the inbound webhook based on `repository_owner`, which is read straight from the untrusted JSON body: [1](#0-0) [2](#0-1) 

Shipit explicitly supports configuring **multiple independent GitHub Apps for multiple organizations**, each with its own `webhook_secret`, selected by `Shipit.github(organization:)`: [3](#0-2) [4](#0-3) 

Once the signature is accepted, every event handler resolves the **repository/stack to act on** from a *different* JSON field — `repository.full_name` — with no re-check that it belongs to the same organization whose secret was used to verify the signature: [5](#0-4) 

The equality that must hold, and is not enforced, is:

`org(repository.owner.login used for HMAC key selection) == org(repository.full_name used to resolve the Stack that is written to)`

Because both values live in the same attacker-controlled JSON body (only the raw bytes are HMAC'd, not any semantic binding between these two sub-fields), an actor who legitimately administers **any one** of the organizations configured in a multi-org Shipit instance (and therefore legitimately knows that organization's `webhook_secret`) can sign a payload as their own org while setting `repository.full_name` to point at a stack belonging to a **different** configured organization. `PushHandler`, `StatusHandler`, and the `PullRequest::*` handlers all key off `repository.full_name` (via `Handler#stacks`/`#repository_name`) to decide which `Stack`/`Repository` record to mutate, e.g.: [6](#0-5) [7](#0-6) 

### Impact Explanation
`PushHandler` triggers `GithubSyncJob`, which fetches commits from GitHub and appends them to the target stack's commit history, and can subsequently drive automatic/continuous deployment of whatever the attacker-forged `after` SHA implies: [8](#0-7) 

`PullRequest::OpenedHandler`/`ClosedHandler` can provision or archive review stacks on a repository the forging organization does not own: [9](#0-8) 

This crosses the "cross-repository writes" / "unauthorized deploy" impact bar: an attacker who controls one tenant's GitHub App/webhook secret in a multi-org Shipit deployment can inject fabricated push/PR/status events that mutate a completely different organization's repository state and deploy pipeline.

### Likelihood Explanation
This requires a Shipit installation configured with **more than one** GitHub organization (the documented "Using Multiple GitHub Applications" setup), and requires the attacker to legitimately control one of those configured orgs (i.e., know that org's own `webhook_secret`, which they are entitled to as an admin of their own org's GitHub App). No stolen secret, no privileged Shipit-side credential, and no GitHub-repo write access to the *victim* org is required — only administration of their own, separately configured org. This matches the multi-tenant misuse scenario Shipit's own docs describe as supported, making it a realistic configuration for shared Shipit instances serving multiple organizations.

### Recommendation
After verifying the HMAC signature with the app selected via `repository_owner`, re-validate that the organization implied by `payload.dig('repository', 'full_name')`'s owner segment matches `repository_owner` before dispatching to any handler (or, better, always derive the "owning org" from a single, consistently-parsed field and reject payloads where `repository.full_name`'s prefix and `repository.owner.login` diverge). Equivalently, `Handler#stacks`/`#repository_name` should scope lookups by the organization whose key verified the signature, not blindly trust `full_name`.

### Proof of Concept
1. Configure Shipit with two GitHub orgs, `OrgOne` and `OrgTwo`, each with its own `webhook_secret` (as in `test/dummy/config/secrets_double_github_app.yml`).
2. As an administrator of `OrgOne`'s GitHub App, know `OrgOne`'s `webhook_secret`.
3. Craft a `push` webhook JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "full_name": "OrgTwo/victim-repo",
    "owner": { "login": "OrgOne" }
  }
}
```
4. Compute `X-Hub-Signature: sha1=...` using `OrgOne`'s `webhook_secret` over the raw body.
5. POST to `/github/webhooks` with `X-Github-Event: push`.
6. `verify_signature` calls `Shipit.github(organization: "OrgOne")` and the signature verifies successfully.
7. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("OrgTwo/victim-repo")`, and triggers `GithubSyncJob` for a stack belonging to `OrgTwo`, despite the request only being authenticated as `OrgOne`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-46)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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
