### Title
Webhook signature is verified against the organization derived from `repository.owner.login`, but the repository acted upon is selected from the unbound `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In a multi-GitHub-App Shipit deployment (`Shipit.github(organization:)` supports one App/webhook secret per GitHub organization), `WebhooksController#verify_signature` picks which organization's webhook secret to verify the HMAC signature against using `repository_owner`, computed from `params.dig('repository', 'owner', 'login')`. Once the signature check passes, the entire raw JSON payload is handed to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` unmodified, and the handlers independently resolve which `Repository`/`Stack` to mutate using `payload.dig('repository', 'full_name')`. The engine never checks that `full_name`'s owner segment matches the organization whose secret validated the signature.

### Finding Description
`verify_signature` computes the signing organization like this: [1](#0-0) [2](#0-1) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`Shipit.github(organization:)` looks up a distinct `webhook_secret` per organization key in `secrets.github` (see the "Using Multiple Github Applications" configuration documented for exactly this scenario) [3](#0-2) , and `GitHubApp#verify_webhook_signature` does an HMAC comparison using that organization-specific secret [4](#0-3) .

After the signature is accepted, `create` passes the *entire, unfiltered* JSON body to every registered handler: [5](#0-4) 

Handlers resolve the target repository from a *different* JSON field, `repository.full_name`, with no cross-check against `repository.owner.login`/`repository_owner` used for signature verification: [6](#0-5) [7](#0-6) 

The equality this design implicitly assumes but never enforces is:

`org(repository.owner.login) == org(repository.full_name.split('/').first)`

Nothing in `WebhooksController`, `Handler`, or `PushHandler` enforces this. An attacker who legitimately administers a GitHub App installation for **their own organization** (`org-attacker`) in a shared, multi-tenant Shipit instance knows `org-attacker`'s `webhook_secret`. They can:
1. Craft an arbitrary JSON body with `repository.owner.login = "org-attacker"` (so `verify_signature` selects and validates against `org-attacker`'s secret, which they control) and `ref`/`after` set to any value.
2. Set `repository.full_name = "org-victim/some-repo"` (any repo already registered as a Stack in the shared Shipit instance, belonging to a different tenant/org).
3. Sign the raw body with `org-attacker`'s webhook secret and POST it to `/webhooks`.

`verify_signature` succeeds (the secret used matches the org that HMAC-signed the request), but `PushHandler#process` resolves the target `Stack` via `Repository.from_github_repo_name("org-victim/some-repo")` and calls `stack.sync_github(expected_head_sha: params.after)`, which enqueues `GithubSyncJob` against the victim's stack. `GithubSyncJob` then fetches commits via `stack.github_api` (the org-victim App's own credentials, since that flows through `Stack#github_api`/`Shipit.github(organization: stack repo owner)`, not the attacker's) and, if the victim stack has `continuous_deployment` enabled, an eventual sync of new commits can advance `next_commit_to_deploy` and trigger `trigger_continuous_delivery` → `trigger_deploy`, i.e., an unauthorized deploy driven entirely by a forged webhook whose signature was only proven for a *different* organization. [8](#0-7) [9](#0-8) [10](#0-9) 

Other handlers (`AssignedHandler`, `LabeledHandler`, `OpenedHandler`, `ReopenedHandler`, `LabelCapturingHandler`) have the same pattern: they trust `params.repository.full_name` to look up the acted-upon `Repository`/`ReviewStack`, independent of `repository_owner` used for signature verification. [11](#0-10) 

### Impact Explanation
This breaks the binding "organization that authenticated == repository that is written." A tenant that legitimately controls one organization's webhook secret in a shared Shipit deployment can forge webhook events that are dispatched against a completely different organization's repositories/stacks, causing cross-tenant repository sync and, via continuous deployment, an unauthorized deploy — matching the Critical-tier "cross-repository writes / unauthorized deploy" impact category.

### Likelihood Explanation
Requires: (a) a Shipit instance configured with multiple GitHub Apps for multiple organizations (a documented, supported configuration — see `docs/setup.md` "Using Multiple Github Applications"), and (b) the attacker legitimately controlling at least one such org's webhook secret while targeting a repository belonging to a different org in the same instance. This is a realistic scenario for shared/self-hosted multi-tenant Shipit installs but not applicable to single-organization deployments (the common case), which somewhat limits likelihood.

### Recommendation
In `WebhooksController#verify_signature`/`create`, after determining `repository_owner` used to select the signing GitHub App, validate that every repository reference used by downstream handlers (`repository.full_name`, and any `organization.login` field) is consistent with that same organization before dispatching to handlers. Alternatively, have `Handler#repository_name` cross-check that the resolved `Repository`'s owner matches the verified `repository_owner`, and reject/no-op otherwise.

### Proof of Concept
1. Configure Shipit with two orgs in `secrets.github`: `org-attacker` (secret `S1`) and `org-victim` (secret `S2`), each with its own installed GitHub App, matching the documented multi-org setup.
2. As the administrator of `org-attacker`'s GitHub App, craft a push payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": { "owner": { "login": "org-attacker" }, "full_name": "org-victim/some-repo" }
}
```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(S1, body)>` using `org-attacker`'s known secret `S1`.
4. POST to `/webhooks` with header `X-Github-Event: push`.
5. `verify_signature` resolves `Shipit.github(organization: "org-attacker")` and validates successfully against `S1`.
6. `PushHandler` resolves `Repository.from_github_repo_name("org-victim/some-repo")` and enqueues `GithubSyncJob` for `org-victim`'s stack, causing a sync (and potentially a continuous-deployment trigger) without ever having proven possession of `org-victim`'s webhook secret.

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

**File:** app/models/shipit/stack.rb (L210-229)
```ruby
    def trigger_continuous_delivery
      return if cached_deploy_spec.blank?

      commit = next_commit_to_deploy

      if should_resume_continuous_delivery?(commit)
        continuous_delivery_resumed!
        return
      end

      if should_delay_continuous_delivery?(commit)
        continuous_delivery_delayed!
        return
      end

      begin
        trigger_deploy(commit, Shipit.user, env: cached_deploy_spec.default_deploy_env)
      rescue Task::ConcurrentTaskRunning
      end
    end
```

**File:** app/models/shipit/stack.rb (L612-614)
```ruby
    def sync_github(expected_head_sha: nil)
      GithubSyncJob.perform_later(stack_id: id, expected_head_sha:)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
