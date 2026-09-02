### Title
Webhook signature verification is bound to the payload's `repository.owner.login`, not to the `repository.full_name` the event actually mutates - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In multi-organization deployments, `WebhooksController#verify_signature` selects which GitHub App config (and therefore which `webhook_secret`) to use for HMAC verification based on `repository.owner.login` (or `organization.login`) taken from the untrusted JSON body. Once the signature check passes, the event is dispatched to handlers that resolve the actual `Repository`/`Stack` to act on using a *different* field of the same payload: `repository.full_name`. Nothing binds these two fields together, so a signature that is valid for organization A does not guarantee the event content is actually about organization A's repositories.

### Finding Description
`WebhooksController#verify_signature` picks the app/secret to verify against like this: [1](#0-0) [2](#0-1) 

`repository_owner` is derived purely from the request body (`params.dig('repository', 'owner', 'login')`), and `Shipit.github(organization: repository_owner)` looks up that organization's `webhook_secret` for HMAC verification: [3](#0-2) 

After the signature is accepted, the raw JSON body is dispatched unchanged to handlers: [4](#0-3) 

Handlers, however, resolve the target `Repository`/`Stack` from a *different* payload field — `repository.full_name` — with no cross-check against `repository.owner.login`: [5](#0-4) 

The `PushHandler` then acts on whatever stacks match that `full_name`, using an attacker-supplied `after` SHA as the "expected head": [6](#0-5) 

`GithubSyncJob` then re-syncs and, when nothing new is found but `expected_head_sha` doesn't already exist locally, retries; if a resync happens it triggers `CacheDeploySpecJob` and downstream continuous-delivery evaluation: [7](#0-6) 

This mirrors the report's bug class exactly: the "vote" (the cryptographic signature) is computed over data that is not sufficient to constrain the effect of the message. In the TSS case, the hash didn't cover the public key being agreed upon; here, the HMAC secret selection is keyed on `repository.owner.login`, but the code that decides *which repository/stack is mutated* trusts a sibling field (`repository.full_name`) that is never tied back to the verified organization. An entity that legitimately possesses one organization's `webhook_secret` (e.g., an admin of a low-trust org "org-a" onboarded onto a shared/multi-tenant Shipit instance) can forge a POST directly to `/github/webhooks` with:
- `repository.owner.login = "org-a"` (so the correct, known secret is used to compute a valid `X-Hub-Signature`)
- `repository.full_name = "org-b/high-value-repo"` (a completely different, higher-trust organization's repository that org-a has no relationship to)

This passes `verify_signature` and is routed to handlers operating on `org-b`'s stacks.

### Impact Explanation
This breaks the trust binding "an organization that authenticated versus the repository that is written." An attacker who only controls org-a's webhook secret can force Shipit to process events (push, status, check_suite, membership, pull_request, etc.) as if they came from an arbitrary other organization's repository configured on the same instance, driving stack syncs and — via `sync_github` → `CacheDeploySpecJob` → continuous delivery evaluation — potentially triggering an unauthorized deploy on a stack belonging to an organization the attacker has no legitimate relationship with. This satisfies the "unauthorized deploy" impact criterion for multi-tenant Shipit deployments (the documented and supported multi-org config schema keyed by `TOP_LEVEL_GH_KEYS`/`github_app_config`).

### Likelihood Explanation
Exploitability requires the deployment to run Shipit in the multi-organization configuration (multiple entries in `secrets.github`, each with its own `webhook_secret`) and for the attacker to legitimately hold (or otherwise obtain) the `webhook_secret` of at least one configured, lower-trust organization — which is an expected, unprivileged-relative-to-other-orgs capability in a shared instance, not requiring any Shipit session, API token, or GitHub App private key. This is a realistic misconfiguration-adjacent scenario for any shared/multi-tenant Shipit deployment, since nothing in the code prevents it — the class of bug is structural, not incidental.

### Recommendation
In `WebhooksController#verify_signature`, after computing `repository_owner` for secret lookup, verify the same field is consistent with any `repository.full_name` present in the payload before allowing the event to be dispatched to a handler (e.g., reject if `full_name.split('/').first.casecmp(repository_owner) != 0`). Alternatively, resolve the target `Repository`/`Stack` using the organization that was cryptographically authenticated instead of trusting `repository.full_name` in isolation.

### Proof of Concept
1. Configure Shipit with two organizations, `org-a` and `org-b`, each with distinct `webhook_secret`s (multi-org schema per `lib/shipit.rb`'s `github_app_config`).
2. As an entity holding `org-a`'s `webhook_secret` (e.g. an org-a admin), craft a JSON push payload:
```json
{
  "repository": { "owner": { "login": "org-a" }, "full_name": "org-b/high-value-repo" },
  "ref": "refs/heads/master",
  "after": "deadbeef"
}
```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(org-a webhook_secret, payload)>` and `X-Github-Event: push`, then POST directly to the Shipit engine's `/github/webhooks` endpoint.
4. `WebhooksController#verify_signature` resolves `repository_owner` to `"org-a"`, loads `org-a`'s app, and the HMAC check succeeds.
5. `PushHandler` then resolves stacks via `Repository.from_github_repo_name("org-b/high-value-repo")` and calls `stack.sync_github(expected_head_sha: "deadbeef")`, forcing a sync/deploy pipeline for `org-b`'s stack despite the request being authenticated only against `org-a`'s secret.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L7-17)
```ruby
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
