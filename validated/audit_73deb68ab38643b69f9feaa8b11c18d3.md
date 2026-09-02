### Title
Cross-tenant webhook forgery via organization/repository binding mismatch in `WebhooksController#verify_signature` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to use for HMAC verification based on `repository.owner.login` in the JSON payload, but every webhook `Handler` resolves the actual `Repository`/`Stack` to act on from a *different* field, `repository.full_name`. Nothing enforces that the owner encoded in `full_name` matches the `owner.login` used to pick the verifying secret. In a multi-organization Shipit deployment (explicitly documented and supported), this lets an attacker who legitimately controls one tenant's GitHub App installation forge a webhook whose signature is valid for their own organization but whose payload targets another tenant's repository, causing Shipit to sync commits, and archive/unarchive/deprovision review stacks for a repository they do not own.

### Finding Description
`Shipit.github(organization:)` looks up a per-organization config (`app_id`, `installation_id`, `webhook_secret`, ...) as documented in `docs/setup.md` ("Using Multiple Github Applications") and implemented in `lib/shipit.rb#github` / `#github_app_config` [1](#0-0) . Each tenant organization therefore has its own independently-configured `webhook_secret`.

`WebhooksController#verify_signature` uses only `repository_owner` (derived from `params.dig('repository', 'owner', 'login')`, falling back to `params.dig('organization', 'login')`) to decide *which* organization's `webhook_secret` verifies the HMAC signature of the raw payload: [2](#0-1) [3](#0-2) 

Once the signature is accepted, event handlers never re-check `repository.owner.login`; instead they resolve the target repository from an unrelated JSON field, `repository.full_name`: [4](#0-3) 

This same pattern (`Repository.from_github_repo_name(params.repository.full_name)`) is repeated in every pull-request handler (`opened_handler.rb`, `labeled_handler.rb`, `unlabeled_handler.rb`, `reopened_handler.rb`, `label_capturing_handler.rb`, `assigned_handler.rb`), each of which drives real state changes (creating/archiving/unarchiving/deprovisioning `ReviewStack`s) purely from `full_name`: [5](#0-4) [6](#0-5) 

The push handler resolves stacks the same way and immediately schedules a background sync against the resolved stack: [7](#0-6) 

which enqueues `GithubSyncJob`, fetching real commits from GitHub for the *resolved* repository and appending them to the stack, using the app's own GitHub credentials for that (correct) repository owner (`stack.github_api` → `Shipit.github(organization: repository.owner)`): [8](#0-7) [9](#0-8) 

**Binding that should hold (equality):**
`organization_whose_secret_verified_signature (params.repository.owner.login)` == `owner_of_repository_acted_upon (owner segment of params.repository.full_name)`

**Before an attacker's forged request:** for genuine GitHub-originated webhooks these two are always consistent, because GitHub itself populates both fields from the same repository object and signs with the installation's real secret.

**After the attacker's forged request:** an attacker who administers their own tenant organization's GitHub App installation on the same Shipit instance (and therefore knows their own org's `webhook_secret`, since that secret is exchanged between the app owner and the Shipit operator when the org config is set up) can submit a raw JSON body where:
- `repository.owner.login = "attacker-org"` (so `verify_signature` selects `attacker-org`'s secret, which the attacker knows, and the HMAC check passes), and
- `repository.full_name = "victim-org/victim-repo"` (an entirely independent string, used by every handler to resolve the actual `Stack`/`Repository` to mutate).

Because no code cross-validates that these two fields describe the same repository, the equality is broken and the attacker can drive state changes on a repository/organization they do not administer.

### Impact Explanation
This is a cross-tenant / cross-repository write: an attacker with legitimate control over one organization's GitHub App configuration can forge push and pull-request events attributed to a different organization's repository. Concrete effects include:
- Forcing `GithubSyncJob` runs against a victim stack (`push_handler.rb` → `stack.sync_github`), pulling in commits and potentially interacting with continuous-delivery scheduling logic in `Stack` (`schedule_merges_if_necessary`, `sync_github_if_necessary`, referenced in `app/models/shipit/stack.rb`), which can influence when the victim's automatic deploys are scheduled.
- Archiving/unarchiving/deprovisioning victim `ReviewStack`s via forged `pull_request` `labeled`/`unlabeled`/`reopened` events (`labeled_handler.rb`, `unlabeled_handler.rb`, `reopened_handler.rb`), causing unauthorized environment teardown or unwanted re-provisioning for repositories the attacker doesn't own.

This matches the required "cross-repository writes / unauthorized deploy" high/critical impact class, though I was not able to fully trace the exact conditions under which `sync_github` alone (without a genuine CI-green status event) results in an *automatic* deploy being kicked off — that would require reading the full continuous-delivery scheduling logic in `app/models/shipit/stack.rb`, which I could not fully inspect in this pass. At minimum, the finding is a confirmed cross-tenant state-mutation primitive (forced sync, forced archive/unarchive/deprovision) gated only by an unrelated organization's credential.

### Likelihood Explanation
Requires the attacker to legitimately operate one organization/tenant configured on the shared multi-org Shipit instance (a supported, documented deployment mode) — i.e., they must know or control their *own* org's `webhook_secret`, which is normal for any GitHub App owner. No Shipit session, `ApiClient` token, or GitHub write access to the *victim* repository is required; only crafting a raw JSON HTTP POST to `/webhooks` with a valid HMAC computed from the attacker's own known secret.

### Recommendation
In `WebhooksController#verify_signature`, or in the base `Handler`, enforce that the organization implied by `repository.full_name` (or `organization.login`) matches `repository_owner` used to select the verifying `webhook_secret`; reject the request (422) otherwise. Alternatively, verify the signature using the secret associated with the resolved `Repository`'s actual owner (looked up from Shipit's own DB) rather than trusting an attacker-controlled field in the unauthenticated payload to select which secret validates the payload.

### Proof of Concept
1. Deploy Shipit configured for two organizations, `attacker-org` and `victim-org`, each with its own GitHub App/`webhook_secret` (per `docs/setup.md`'s "Using Multiple Github Applications").
2. As the administrator of `attacker-org`'s GitHub App, compute `X-Hub-Signature` (`sha1=` HMAC-SHA1) over a crafted push payload using `attacker-org`'s known `webhook_secret`.
3. Set the payload's `repository.owner.login` to `"attacker-org"` and `repository.full_name` to `"victim-org/victim-repo"` (an existing Shipit stack owned by `victim-org`), and `ref`/`after` to a target commit SHA.
4. POST to `/webhooks` with header `X-Github-Event: push` and the computed signature.
5. `verify_signature` selects `Shipit.github(organization: 'attacker-org')` and validates successfully against the attacker's own secret (`app/controllers/shipit/webhooks_controller.rb:24-30`).
6. `PushHandler` resolves `stacks` via `Repository.from_github_repo_name("victim-org/victim-repo")` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`) and calls `stack.sync_github(expected_head_sha: ...)`, enqueuing `GithubSyncJob` against the victim's stack — despite the request never being signed by `victim-org`'s secret.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L49-68)
```ruby
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

**File:** app/models/shipit/stack.rb (L434-440)
```ruby
    def github_api
      github_app.api
    end

    def github_app
      Shipit.github(organization: repository.owner)
    end
```
