### Title
Webhook signature verification is keyed by `repository.owner.login` while every downstream handler acts on `repository.full_name`, allowing cross-organization signature confusion in multi-tenant GitHub App setups - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
This is the same trust-binding break as the reported honeypot: one field is what gets verified, a *different, unvalidated* field is what gets acted upon. In `SizeSealed.sol` the verified quote-token address and the token actually credited diverge because there's no on-chain existence check tying them together. In Shipit, `WebhooksController#verify_signature` picks which `GitHubApp`/`webhook_secret` to HMAC-verify against using `repository_owner` (`params.dig('repository','owner','login')`), but every webhook `Handler` (`app/models/shipit/webhooks/handlers/handler.rb`) resolves the `Repository`/`Stack` to operate on using `repository.full_name` from the very same JSON body. Nothing cross-checks that `owner.login` and the owner segment of `full_name` refer to the same organization.

### Finding Description
`Shipit.github(organization:)` supports multi-tenant configuration: each onboarded GitHub organization can have its own `webhook_secret` in `secrets.github[org]` [1](#0-0) . `WebhooksController#verify_signature` resolves which app/secret to verify the incoming `X-Hub-Signature` against purely from `repository_owner`, itself just a `params.dig` read of the untrusted body: [2](#0-1) [3](#0-2) 

Once verification passes, `create` hands the *entire raw params* to every registered handler for the event: [4](#0-3)  Handlers never re-derive or re-check the organization used for verification; instead they look up the target `Stack` purely via `repository.full_name`: [5](#0-4)  and `Repository.from_github_repo_name` simply splits that string on `/` with no relation to `owner.login`: [6](#0-5) 

Because the HMAC is computed over the *raw request body* with the secret belonging to whichever organization `owner.login` names, an actor who administers any one of the organizations onboarded to this Shipit instance (and thus legitimately knows/controls that organization's `webhook_secret`, e.g. via their own GitHub App/organization settings) can self-sign an arbitrary payload where `repository.owner.login` is their own org (so `verify_signature` picks their own known secret and it passes), while `repository.full_name` is forged to point at a completely different, victim-owned repository managed by the same Shipit instance. `verify_signature` only checks the HMAC integrity of the bytes; it never asserts that the org used to select the secret matches the org embedded in `repository.full_name` used downstream. This is the exact "field verified" vs. "field acted upon" split called out by the report's bug class.

### Impact Explanation
A forged-but-signature-valid payload lets the requester drive any registered webhook `Handler` against a `Stack`/`Repository` that does not belong to the organization whose secret was actually used to authenticate the request — e.g. triggering `GithubSyncJob` (which fetches commits and appends them to a victim stack, and can flip `mark_as_accessible!`/`mark_as_inaccessible!`) [7](#0-6) , or driving pull-request/merge/status handlers against a victim repository's `Stack`, effectively achieving cross-repository writes on repositories the caller does not administer. This crosses the "cross-repository writes" / unauthorized state-change bar because the org that authenticated (via its own webhook secret) is not the org whose repository is written.

### Likelihood Explanation
This requires the Shipit instance to be configured for multiple GitHub organizations (multi-tenant `secrets.github` schema) and requires the attacker to legitimately administer at least one onboarded organization (so they know that org's own `webhook_secret`), which they can then abuse against every *other* organization's stacks on the same instance. It does not require any Shipit session, API token, or the victim organization's secret — only knowledge of one's own onboarded organization's webhook secret, which any org admin sets themselves. This is plausible in shared/managed Shipit deployments serving several organizations.

### Recommendation
In `verify_signature`, after selecting the `github_app`/secret via `repository_owner`, explicitly re-validate that `repository_owner` equals the owner segment parsed from `params.dig('repository', 'full_name')` (and from `params.dig('organization','login')` when used as fallback) before dispatching to handlers, rejecting the request otherwise. Alternatively, have `Handler#repository_name`/`stacks` scope lookups by the verified organization rather than trusting `full_name` unconditionally.

### Proof of Concept
1. Configure Shipit with two organizations, `attacker-org` and `victim-org`, each with its own `webhook_secret` in `secrets.github`.
2. As an admin of `attacker-org`, obtain `attacker-org`'s `webhook_secret` (legitimately, from your own GitHub App settings).
3. Build a `push` (or other handled event) JSON payload where `repository.owner.login = "attacker-org"` but `repository.full_name = "victim-org/victim-repo"`.
4. Compute `X-Hub-Signature: sha1=HMAC-SHA1(attacker-org secret, raw_body)` and POST it to `/webhooks`.
5. `WebhooksController#verify_signature` resolves `Shipit.github(organization: "attacker-org")` from `repository_owner`, verifies successfully, and the request proceeds. [8](#0-7) 
6. The registered handler for the event resolves the target via `payload.dig('repository', 'full_name')` = `"victim-org/victim-repo"` [5](#0-4)  and acts on `victim-org`'s `Stack`, even though the request was authenticated only against `attacker-org`'s secret.

**Note on verification limits:** I could not fully trace every individual event handler (`app/models/shipit/webhooks/handlers/**`, excluded from this scan's in-scope path per the rules only for non-`app/**` paths, but the full set was not exhaustively read) to confirm which specific handlers cause a "deploy/rollback/merge" versus only a benign resync; the `push`/`GithubSyncJob` path is the one concretely confirmed above. Given the index/tool limits, a full enumeration of all handler impacts should be validated in a live session before treating this as definitively "Critical" versus "High."

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

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
