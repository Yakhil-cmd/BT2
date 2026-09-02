### Title
Cross-organization webhook forgery bypasses signature binding, triggering unauthorized sync/deploy actions on unrelated stacks - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
In a multi-tenant Shipit deployment (multiple entries under `secrets.github`, each with its own `webhook_secret`), `WebhooksController#verify_signature` selects which organization's secret to verify the HMAC signature against using a payload field (`repository.owner.login`, or `organization.login` as fallback) that is **not itself covered by any cross-check against the field the event handlers actually act on** (`repository.full_name`). This breaks the equality "organization that authenticated == repository that is written."

### Finding Description
`WebhooksController#verify_signature` picks the `GitHubApp` used to verify the HMAC signature purely from attacker-supplied JSON in the request body: [1](#0-0) [2](#0-1) 

```
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`Shipit.github(organization: repository_owner)` resolves a **per-organization** `webhook_secret` from `secrets.github`, keyed by organization name: [3](#0-2) 

Once `verify_webhook_signature` passes (using whichever org's secret matched `repository_owner`), the raw JSON body is dispatched unchanged to the relevant `Shipit::Webhooks::Handlers::*`. Those handlers do **not** re-check `repository.owner.login`; instead they resolve the target `Repository`/`Stack` from a *separate* field of the same body, `repository.full_name`: [4](#0-3) [5](#0-4) 

Because `repository.owner.login` (used for signature/secret selection) and `repository.full_name` (used for the actual write target) are two independent JSON fields inside the same attacker-controlled payload, and neither is cross-validated against the other, an entity that legitimately controls a webhook secret for **one** organization registered in the multi-tenant `secrets.github` config can:
1. Set `repository.owner.login` (or `organization.login`) to their own org, so `Shipit.github(organization: "their-org")` is selected and the HMAC verifies successfully using the secret they legitimately know.
2. Set `repository.full_name` to any other repository registered in the same Shipit instance (e.g. `"victim-org/victim-repo"`).

The handler then acts on the victim repository's stacks — e.g. `PushHandler#process` calls `stack.sync_github(expected_head_sha: params.after)`, enqueuing `Shipit::GithubSyncJob` for the victim stack with an attacker-chosen `expected_head_sha`, which fetches and appends attacker-referenced commits into the victim stack's commit history: [6](#0-5) 

If the victim stack has `continuous_deployment` enabled, syncing new commits can lead this pipeline toward triggering an actual deploy of attacker-influenced state, i.e. an unauthorized deploy on a repository the attacker does not control and never proved ownership of via signature.

### Impact Explanation
This is a cross-repository write: an actor who only holds credentials/secrets for organization A can cause webhook-driven side effects (sync, commit ingestion, potential downstream continuous-deployment triggering, pull-request/review-stack archive/unarchive, status writes) against organization B's/repo's stacks, purely because the signature-selection field and the write-target field are not bound together. This matches the "High/Critical" class of unauthorized cross-repository writes/deploys called out in scope.

### Likelihood Explanation
Requires the deployment to use the multi-organization `secrets.github` schema (more than one org configured, each with its own webhook secret) — a supported, documented configuration in this engine, not a hypothetical one. Any tenant/organization owner in such a shared Shipit instance can exploit this without any additional privilege, simply by sending a crafted HTTP POST to the public webhooks endpoint.

### Recommendation
In `WebhooksController#verify_signature` (or in `Shipit::Webhooks::Handlers::Handler`), require that the organization used to resolve `verify_webhook_signature`'s secret matches the organization portion of `repository.full_name` (or the `repository.owner.login`) that handlers subsequently use to resolve the target `Repository`. Reject (422) any request where these two identities diverge, so a verified signature for org A can never be used to act on a repository belonging to org B.

### Proof of Concept
1. Configure Shipit with multiple GitHub orgs in `secrets.github`, e.g. `attacker-org` and `victim-org`, each with distinct `webhook_secret`s.
2. As the owner of `attacker-org`, compute a valid `X-Hub-Signature` HMAC using `attacker-org`'s known `webhook_secret` over a `push` payload body where:
   - `repository.owner.login` (or `organization.login`) = `"attacker-org"`
   - `repository.full_name` = `"victim-org/victim-repo"`
   - `ref` = `"refs/heads/<victim-branch>"`, `after` = attacker-chosen sha.
3. POST this body with `X-Github-Event: push` and the computed signature to `/github/webhooks`.
4. `verify_signature` resolves `Shipit.github(organization: "attacker-org")` and successfully verifies the signature.
5. `PushHandler#process` resolves the target stack via `Repository.from_github_repo_name("victim-org/victim-repo")` and enqueues `GithubSyncJob` for the victim's stack, causing it to sync/ingest attacker-referenced commit history — despite the request never being authenticated for `victim-org`.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
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
