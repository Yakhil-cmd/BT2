### Title
Webhook signature verification key is selected using an attacker-controlled `repository.owner.login` field that is never cross-checked against the `repository.full_name` the handlers actually act on, allowing cross-organization webhook forgery in multi-tenant deployments - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which GitHub App/webhook secret to validate a payload against using `repository_owner`, which is read straight out of the untrusted JSON body (`params.dig('repository', 'owner', 'login')`). The event handlers, however, resolve the target `Repository`/`Stack` from a *different* field of the same body, `repository.full_name` (`Handler#repository_name`). Nothing ties these two fields together. In a multi-organization Shipit deployment (`Shipit.github_organizations`, `github_app_config`), any party who legitimately possesses the `webhook_secret` for *one* onboarded organization can sign an arbitrary payload with that secret while setting `repository.full_name` to point at a completely different organization's repository, and the signature check will pass.

### Finding Description
`Shipit.github(organization:)` supports a config schema keyed by organization, each with its own `webhook_secret` [1](#0-0) . `WebhooksController#verify_signature` selects the app/secret used for HMAC verification purely from the claimed `repository.owner.login` (or `organization.login`) inside the payload body itself: [2](#0-1) 

Once the signature passes, `create` dispatches to `Shipit::Webhooks::Handlers::Handler`, which independently derives the target repository from `payload.dig('repository', 'full_name')`: [3](#0-2) 

Because `repository_owner` (used to pick the verification key) and `repository.full_name` (used to pick the acted-upon `Stack`) are two independently attacker-suppliable fields inside the same signed blob, an attacker who knows the `webhook_secret` for organization A can craft a body where `repository.owner.login = "org-a"` (so the signature checks out against org A's secret) but `repository.full_name = "org-b/victim-repo"`, causing Shipit to act on org B's stack using a signature that was never authorized by org B.

This is the direct analog of the reported bug class: the entity that is cryptographically authenticated (`repository_owner` → the signing organization) is not the entity that ends up being written to (`repository.full_name` → the target repository/stack), exactly mirroring "msg.sender is bound to the wrong party."

### Impact Explanation
For events like `push`, this enqueues `GithubSyncJob` for the victim's real `Stack`, which pulls the true GitHub commit history via `stack.github_api` [4](#0-3) . On stacks with continuous deployment/delivery enabled, this out-of-band, unauthorized trigger can force a deploy task to run against a victim repository that the attacker's organization has no legitimate relationship to — an unauthorized deploy triggered across an organizational trust boundary, using credentials (the attacker's own org's webhook secret) that were never granted authority over the victim organization's repositories.

### Likelihood Explanation
This only applies to Shipit instances configured with the multi-organization `github` config schema (`Shipit.github_organizations` returning more than `[nil]`), which is a documented, supported configuration (`lib/shipit.rb#github_app_config`). Any actor who holds a valid `webhook_secret` for one onboarded organization (which, per this engine's own multi-tenant design, is not privileged over other tenant organizations) can mount the attack directly against the public `/webhooks` endpoint without needing a Shipit session or any Shipit-issued credential.

### Recommendation
After signature verification succeeds using the organization inferred from `repository.owner.login`/`organization.login`, verify that the resolved `Repository` (via `repository.full_name`) actually belongs to that same organization/login before dispatching to handlers, e.g. reject the request if `repository.full_name.split('/').first.casecmp(repository_owner) != 0`.

### Proof of Concept
1. Deploy Shipit with multi-org config: `secrets.github` keyed by `org-a` and `org-b`, each with distinct `webhook_secret`s, both installed as GitHub Apps by their respective (mutually distrusting) organizations.
2. Attacker, who administers `org-a`'s GitHub App installation and therefore knows `org-a`'s `webhook_secret`, crafts a `push` payload:
```json
{
  "repository": { "owner": { "login": "org-a" }, "full_name": "org-b/victim-repo" },
  "ref": "refs/heads/main",
  "after": "<real-latest-sha-of-org-b/victim-repo>"
}
```
3. Attacker computes `X-Hub-Signature` using `org-a`'s `webhook_secret` and POSTs directly to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` resolves `repository_owner == "org-a"`, fetches `Shipit.github(organization: "org-a")`, and the HMAC check succeeds because the attacker signed with the correct (org-a) secret. [5](#0-4) 
5. `PushHandler`/`Handler#repository_name` resolves the target stack from `repository.full_name == "org-b/victim-repo"`, enqueueing `GithubSyncJob` for org B's real stack — even though org B's webhook secret was never used or known by the attacker. [6](#0-5)

### Citations

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

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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
