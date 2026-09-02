### Title
Webhook signature verification is keyed on `repository.owner.login`, while all event handlers act on the unrelated `repository.full_name` field, allowing a tenant with their own GitHub App/webhook secret to trigger syncs and deploy pipelines for a different organization's stacks - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and therefore which `webhook_secret`) to use for HMAC verification based on `repository.owner.login` (or `organization.login`) taken directly from the untrusted request body, then verifies the raw body against that organization's secret. [1](#0-0) [2](#0-1) 

Once the signature check passes, `create` dispatches the exact same raw payload to the event handlers, which never re-check `repository.owner.login`. Instead every handler resolves the target `Repository`/`Stack` using a completely different field: `repository.full_name`. [3](#0-2) [4](#0-3) 

Because Shipit explicitly supports multi-organization deployments (each organization having its own GitHub App and `webhook_secret` in `secrets.yml`), a tenant/admin who legitimately owns one organization's GitHub App configuration knows that organization's `webhook_secret`. That party can craft a payload where `repository.owner.login` equals their own organization (satisfying signature verification against their known secret) but `repository.full_name` names a repository belonging to a *different* tenant organization also hosted on the same Shipit instance. [5](#0-4) [6](#0-5) 

### Finding Description
The verified binding is: `organization that authenticated (repository.owner.login used to pick the webhook_secret)` == `repository that is written (repository.full_name used to locate the Stack/Repository that gets acted upon)`. These are two independent fields inside the same JSON body and are never cross-checked against each other.

- `repository_owner` (used only for choosing which `GitHubApp`/secret to verify with) is read from `params.dig('repository', 'owner', 'login')` or `params.dig('organization', 'login')`. [2](#0-1) 
- `repository_name` (used by every handler to resolve the actual `Repository`/`Stack` records to mutate) is read from `payload.dig('repository', 'full_name')`. [4](#0-3) 
- `PushHandler` uses that resolved stack set to enqueue `GithubSyncJob`, which syncs commits and, via `CacheDeploySpecJob`, feeds the deploy-spec pipeline, and can drive continuous delivery. [7](#0-6) [8](#0-7) 

`verify_webhook_signature` simply confirms the raw body is HMAC-signed by *some* organization's secret — it does not confirm that the signing organization is the owner of the repository the handlers subsequently operate on: [6](#0-5) 

Because Shipit is designed to host multiple organizations side by side, each with its own GitHub App/`webhook_secret` (as documented in `config/secrets.development.shopify.yml` and `lib/shipit.rb#github_organizations`), a party that operates their own tenant organization's GitHub App knows their own webhook secret and can produce a validly-signed request whose `repository.owner.login` matches their own org but whose `repository.full_name` points at a stack belonging to an entirely different tenant. [5](#0-4) [9](#0-8) 

This is the direct structural analog of the MixOracle bug: the verification step is bound to a value (`token1`/`repository.owner.login`) that is not guaranteed to correspond to the value actually acted upon by downstream logic (`token0`'s intended asset/`repository.full_name`), so the trust check silently authorizes actions outside the actor's actual scope.

### Impact Explanation
An organization that only administers its own GitHub App on the shared Shipit instance can trigger `GithubSyncJob`/`CacheDeploySpecJob` (and, depending on branch/continuous-delivery configuration, downstream deploy triggers) for stacks that belong to a different, unrelated organization's repository, despite never having any credential, installation, or write access on that repository. This is a cross-tenant / cross-repository action, matching the "cross-repository writes" / "unauthorized deploy" High/Critical impact categories, since the sync can advance the deployed head/commit history and feed the continuous-delivery pipeline for a stack the attacker does not own.

### Likelihood Explanation
This requires a multi-organization Shipit deployment (explicitly supported and documented via `secrets.yml`'s per-organization `github:` keys), and the attacker only needs to control/administer one of the configured GitHub Apps (which they are entitled to do as a legitimate tenant) — no compromise of the target organization's credentials, `GITHUB_TOKEN`, or Shipit account is required. The likelihood is moderate: it applies specifically to shared/multi-tenant Shipit installations rather than single-organization deployments.

### Recommendation
After signature verification, re-validate that `repository.owner.login` (the field used to select the verifying `webhook_secret`) matches the owning organization of the repository named in `repository.full_name` before dispatching to handlers, or resolve/verify the target `Repository` record's `owner` against the authenticated organization prior to invoking any handler in `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`.

### Proof of Concept
1. Shipit is configured with two tenants, e.g. `somegithuborg` and `someothergithuborg`, each with its own GitHub App and `webhook_secret`, tracking repositories `somegithuborg/app-a` and `someothergithuborg/app-b` respectively (per `config/secrets.development.shopify.yml`).
2. The administrator of `somegithuborg` (who knows their own `webhook_secret`) crafts a `push` event JSON body:
   - `repository.owner.login = "somegithuborg"`
   - `repository.full_name = "someothergithuborg/app-b"`
   - `ref = "refs/heads/master"`, `after = "<attacker-chosen or current head sha>"`
3. They compute `X-Hub-Signature: sha1=HMAC(somegithuborg_webhook_secret, body)` and POST to `/webhooks`.
4. `WebhooksController#verify_signature` computes `repository_owner = "somegithuborg"`, loads `Shipit.github(organization: "somegithuborg")`, and the HMAC check succeeds because the attacker used the correct secret for that org. [1](#0-0) 
5. `create` dispatches the payload to `PushHandler`, which resolves `stacks` via `Repository.from_github_repo_name("someothergithuborg/app-b")` — a repository the attacker does not own — and enqueues `GithubSyncJob` against it. [4](#0-3) [7](#0-6) 
6. `GithubSyncJob` syncs the target stack's commit history and triggers `CacheDeploySpecJob`, affecting a stack outside the attacker's authorized organization. [8](#0-7)

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
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

**File:** lib/shipit.rb (L190-200)
```ruby
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
