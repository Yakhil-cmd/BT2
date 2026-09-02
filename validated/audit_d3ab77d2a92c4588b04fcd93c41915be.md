### Title
Webhook signature is verified against an attacker-selected organization while the acted-upon repository is read from an unauthenticated field of the same payload - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks *which* GitHub App configuration (and therefore which `webhook_secret`) to validate the HMAC signature against by reading `repository.owner.login` straight out of the still-unauthenticated JSON body. Every downstream `Webhooks::Handlers::Handler` instead resolves the target `Repository`/`Stack` using a different field of the same body, `repository.full_name` (`app/models/shipit/webhooks/handlers/handler.rb:36-38`). Nothing enforces that these two independently-attacker-controlled fields agree, so the "organization whose secret authenticated the request" and "the repository the request is applied to" are never bound together.

### Finding Description
`verify_signature` does:
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
``` [1](#0-0) 

`Shipit.github(organization:)` looks up a **per-organization** app config, each with its own optional `webhook_secret`: [2](#0-1) 

`GitHubApp#verify_webhook_signature` returns `true` unconditionally when that organization's config has no `webhook_secret` set:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [3](#0-2) 

Meanwhile, every event handler resolves the actual repository/stack to mutate using a **different** JSON field of the exact same payload:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [4](#0-3) 

Because `repository.owner.login` (used to select which secret authenticates the request) and `repository.full_name` (used to select which repo/stack is acted on) are two unrelated keys inside the same attacker-supplied JSON, an attacker who can produce a request that passes signature verification for *any one* configured organization (e.g. an org whose `webhook_secret` is unset/blank, which `verify_webhook_signature` explicitly treats as always-valid) can set `repository.full_name` to point at an entirely different, fully-protected organization/repository. The controller's authentication decision is bound to `repository.owner.login`, but the mutation the handlers perform is bound to `repository.full_name` — these two are never checked for equality, breaking exactly the "organization that authenticated versus the repository that is written" trust binding.

This lets a request that is only "authenticated" for org `A` (with no `webhook_secret` configured — a supported, documented configuration per `docs/setup.md`, not a hypothetical) drive `push` (→ `GithubSyncJob`, fetching commits into org `B`'s stack) [5](#0-4) , `status`, `check_suite`, `membership`, or `pull_request` events against org `B`'s stacks, teams and commits, even though org `B` has a properly configured `webhook_secret` and the raw payload was never signed by GitHub for org `B`.

### Impact Explanation
This crosses the "cross-repository writes" / "unauthorized deploy" bar explicitly listed as Critical impact: an attacker who only needs knowledge of one organization slug configured without a webhook secret (a legitimate, documented configuration state, not a leaked credential) can forge events that create commits, alter commit statuses, trigger `GithubSyncJob` syncs, and manipulate team membership for a completely unrelated, properly-secured organization's stacks. No `webhook_secret`, `ApiClient` token, or repository write access is required for the "victim" organization — the attacker only needs the "authenticating" organization to have no secret configured, which is entirely within the scope of unprivileged-attacker prerequisites.

### Likelihood Explanation
Requires the operator to run a multi-tenant Shipit deployment (the `github_organizations`/per-org config path in `lib/shipit.rb:190-200`) where at least one configured organization has no `webhook_secret` set — an explicitly optional field per `docs/setup.md`. Given that likelihood precondition, exploitation is a single crafted HTTP POST with no additional secrets, tokens, or privileged access.

### Recommendation
After selecting the app config by `repository_owner` and verifying the signature, re-derive the repository/organization the handlers will act on (`repository.full_name`) and assert that its owner segment equals `repository_owner` (or, more robustly, iterate/verify against the app config matching `repository.full_name` directly and reject the request if the two disagree), before invoking any `Webhooks::Handlers`.

### Proof of Concept
1. Deploy Shipit with two configured GitHub organizations: `org-a` (no `webhook_secret` set) and `org-b` (properly configured with a Shipit-managed stack and `webhook_secret`).
2. Attacker sends:
```
POST /webhooks
X-Github-Event: push
X-Hub-Signature: sha1=anything
Body: {
  "repository": { "owner": { "login": "org-a" }, "full_name": "org-b/protected-repo" },
  "after": "<attacker-chosen sha>"
}
```
3. `verify_signature` calls `Shipit.github(organization: "org-a")`; `verify_webhook_signature` returns `true` immediately because `org-a` has no `webhook_secret` (`lib/shipit/github_app.rb:76-77`) — no signature is actually checked.
4. `WebhooksController#create` dispatches to the `push` handler with the full payload; the handler resolves `payload.dig('repository', 'full_name')` = `org-b/protected-repo` and enqueues `GithubSyncJob` for `org-b`'s stack, even though `org-b`'s webhook secret was never presented or validated.

### Citations

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
