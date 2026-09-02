### Title
Cross-organization webhook signature confusion allows forged sync/deploy triggers on repositories outside the authenticating organization - (File: app/controllers/shipit/webhooks_controller.rb)

### Finding Description
In multi-tenant configurations, `Shipit.github(organization:)` resolves a distinct `GitHubApp` (and thus a distinct `webhook_secret`) per onboarded GitHub organization, keyed by the organization name in `config/secrets.yml` [1](#0-0) .

`WebhooksController#verify_signature` selects which organization's secret to use for HMAC verification purely from the JSON body, via `repository_owner`, which reads `params.dig('repository', 'owner', 'login')` and falls back to `params.dig('organization', 'login')`: [2](#0-1) [3](#0-2) 

Once the signature check passes, the request body is dispatched to the registered handlers via `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [4](#0-3) . Every handler resolves the repository/stack to actually act on from a **different** field of the same body — `payload.dig('repository', 'full_name')` — via the shared base class: [5](#0-4) 

`repository.owner.login` (used to pick the verifying secret) and `repository.full_name` (used to pick the repository/stack that is actually written to) are never cross-checked against each other. For example, `PushHandler` uses `stacks` (derived from `repository.full_name`) to look up stacks and immediately calls `stack.sync_github(expected_head_sha: params.after)`: [6](#0-5) 

`verify_webhook_signature` only proves the raw body was HMAC-signed with *some* configured organization's secret; it does not prove that the `repository`/`organization` object embedded in that body belongs to that same organization: [7](#0-6) 

This breaks the intended binding: `organization that authenticated (repository.owner.login / organization.login) == organization that owns the repository actually written to (repository.full_name)`. An entity onboarded to a shared Shipit instance as organization A (and therefore in possession of A's `webhook_secret`, since that secret is provisioned per-organization by whoever configures that org's GitHub App) can sign an arbitrary payload with A's secret while setting `repository.full_name` (and/or `organization.login` for the `membership` event) to point at organization B's repository/stack. `verify_signature` succeeds because it only checks the signature against A's secret and A's login, but the handler that processes the event operates on B's data.

### Impact Explanation
The most concretely reachable consequence in-scope is forcing `PushHandler` to invoke `stack.sync_github` on a victim organization's stack that the forging tenant has no legitimate access to, using an attacker-chosen `expected_head_sha`. Because git content is still fetched through the victim stack's own `github_app` (`Shipit.github(organization: repository.owner)`), the attacker cannot inject arbitrary commit content, but they can force out-of-band synchronization of a foreign stack at a time and head-sha of their choosing. On stacks with continuous delivery enabled, driving a sync of new commits is the trigger that leads into automatic deployment, so this path can result in triggering a deploy on a repository the caller does not own, purely by possessing a webhook secret for an unrelated, self-onboarded organization. I was not able to fully trace `Stack#sync_github` / `GithubSyncJob` to a deploy dispatch within my remaining tool budget, so the full chain from forged sync to an actual unauthorized deploy is not conclusively confirmed and should be validated further (e.g., whether `sync_github` alone can enqueue a deploy for stacks with `continuous_delivery_schedule`).

### Likelihood Explanation
Exploitability requires the attacker to be an administrator of some organization that is itself legitimately onboarded to the same multi-tenant Shipit instance (so they know that organization's `webhook_secret`), and for the instance to host at least one other organization's stacks. This is a realistic operating condition for any shared/multi-org Shipit deployment as documented by the multi-org configuration schema in `lib/shipit.rb`. No GitHub App private key, `api_clients_secret`, or session is required — only a webhook secret the attacker already legitimately possesses for their own tenant.

### Recommendation
In `WebhooksController#verify_signature`/`create`, and in `Shipit::Webhooks::Handlers::Handler#repository_name`/`#stacks`, cross-validate that the organization used to select the verifying `GitHubApp` (`repository_owner`) matches the owner embedded in `repository.full_name` (and, for organization-scoped events, `organization.login`) before dispatching to handlers. Reject the webhook (422) on mismatch rather than trusting the two fields independently.

### Proof of Concept
1. Operator onboards organization `attacker-org` to a multi-org Shipit instance and, as its legitimate admin, knows `attacker-org`'s configured `webhook_secret`.
2. Craft a `push` webhook body:
   ```json
   {
     "ref": "refs/heads/main",
     "after": "<attacker-chosen-sha>",
     "repository": {
       "owner": { "login": "attacker-org" },
       "full_name": "victim-org/victim-repo"
     }
   }
   ```
3. Compute `X-Hub-Signature` as `sha1=HMAC-SHA1(attacker-org_webhook_secret, raw_body)`.
4. POST to `/webhooks` with `X-Github-Event: push`. `verify_signature` resolves `Shipit.github(organization: "attacker-org")` and successfully verifies the signature [8](#0-7) .
5. `PushHandler` resolves stacks from `repository.full_name = "victim-org/victim-repo"` (unrelated to the verified `attacker-org`) and calls `stack.sync_github(expected_head_sha: params.after)` on the victim's stack [6](#0-5) [5](#0-4) .

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```
