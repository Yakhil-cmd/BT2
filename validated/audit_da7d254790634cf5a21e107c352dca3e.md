This is a critical finding — a signature-authenticated-organization vs. acted-upon-repository binding break in `WebhooksController`, exactly matching the class of bug requested.

### Title
Webhook signature is verified against `repository.owner.login`, but handlers act on the unverified `repository.full_name` field, allowing cross-organization forgery in multi-tenant configurations - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
Shipit supports hosting multiple, mutually untrusted GitHub organizations behind a single install, each with its own `webhook_secret` [1](#0-0) . `WebhooksController#verify_signature` picks which organization's `webhook_secret` to validate the HMAC signature against using `repository_owner`, which reads `params.dig('repository', 'owner', 'login')` (or `organization.login`) [2](#0-1) . However, every webhook `Handler` locates the actual `Repository`/`Stack` to mutate using a **different** field of the same JSON body: `payload.dig('repository', 'full_name')` [3](#0-2) .

### Finding Description
The binding that should hold is:
`organization whose webhook_secret authenticated the request == organization that owns the repository being mutated`

Instead, the code checks:
`Shipit.github(organization: payload['repository']['owner']['login']).verify_webhook_signature(sig, raw_body)`

and then acts on:
`Repository.from_github_repo_name(payload['repository']['full_name'])`

Both `repository.owner.login` and `repository.full_name` are attacker-controlled JSON fields inside the same signed body — nothing forces them to refer to the same repository. An attacker who legitimately controls (or is an administrator of) one onboarded organization's GitHub App — and therefore knows that organization's `webhook_secret` — can HMAC-sign a payload where `repository.owner.login` is set to their own organization (satisfying `verify_webhook_signature`) while `repository.full_name` is set to a **different, victim organization's repository** that is also configured on the same Shipit instance. Multiple independent `webhook_secret`s per organization are only meaningful as a trust boundary if the field validated by the signature matches the field acted upon by the handler; here they diverge, so the compartmentalization between tenants is defeated. See `lib/shipit.rb#github_app_config`/`#github` for how organizations are resolved to distinct secrets [4](#0-3) .

This is a direct structural analog of `approveAndCall` approving `max` regardless of the caller-supplied amount: the field that is checked (`repository.owner.login`) is not the field that is acted on (`repository.full_name`).

### Impact Explanation
Once the forged, signature-valid webhook is accepted, any handler can be abused against the victim org's repository:
- `StatusHandler#process` finds `Commit` rows purely by `sha` (global, not scoped to the signing organization) and calls `commit.create_status_from_github!(params)`, letting the attacker inject arbitrary CI statuses (e.g. forged "success") for commits belonging to a victim stack it does not own [5](#0-4) . If deploy/merge gating in Shipit relies on such statuses, this can enable an **unauthorized deploy**.
- `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name(repository_name)` (the forgeable field) and triggers `stack.sync_github(expected_head_sha: params.after)` for a stack outside the attacker's org, forcing unwanted GitHub syncs against a victim's stack [6](#0-5) .
- Pull-request handlers (`opened_handler.rb`, `closed_handler.rb`, `labeled_handler.rb`, etc.) all resolve the target `Repository` from `params.repository.full_name` and archive/unarchive or provision review stacks accordingly, again governed by the forgeable field rather than the authenticated organization.

This satisfies the "High" bar: escalation across `Shipit.github_teams`/organization authorization boundaries and unauthorized triggering of deploy-adjacent state (commit statuses feeding into `merge_status`/`deployable_status`), reachable purely from an attacker who legitimately controls one tenant's webhook secret but not the victim tenant's repository.

### Likelihood Explanation
Requires the operator to run Shipit in the documented multi-organization configuration (`secrets.github` keyed by organization, each with its own `webhook_secret`, as shown in `config/secrets.development.shopify.yml`) and to onboard at least one organization whose webhook administrator is not fully trusted with respect to other tenants. Given that this multi-tenant schema is explicitly documented/supported, and the only thing an attacker needs is knowledge of their own org's webhook secret plus the ability to send an arbitrary HTTP POST to the shared `/webhooks` endpoint, likelihood is moderate-to-high for any multi-org deployment.

### Recommendation
Bind the signature-verifying organization to the same field used by handlers for repository resolution. Concretely, `repository_owner` in `WebhooksController` should be derived from `repository.full_name`'s owner segment (not `repository.owner.login`), or — more robustly — every `Handler` should validate that `payload.dig('repository','owner','login')` matches the owner segment of `payload.dig('repository','full_name')` before resolving/mutating a `Repository`, rejecting the webhook otherwise.

### Proof of Concept
1. Shipit is configured with two tenants, `orgA` and `orgB`, each with distinct `webhook_secret`s (per `config/secrets.development.shopify.yml` schema).
2. Attacker, an administrator of `orgA`'s GitHub App, knows `orgA`'s `webhook_secret`.
3. Attacker crafts a `status` (or `push`) event JSON body with:
   - `repository.owner.login = "orgA"`
   - `repository.full_name = "orgB/victim-repo"`
   - `sha` = a real commit sha belonging to a stack under `orgB/victim-repo`
   - `state = "success"`
4. Attacker computes `X-Hub-Signature` using `orgA`'s `webhook_secret` over the raw body and POSTs to `/webhooks`.
5. `WebhooksController#verify_signature` calls `Shipit.github(organization: "orgA").verify_webhook_signature(...)`, which succeeds because the signature was computed with `orgA`'s real secret [7](#0-6) .
6. `StatusHandler#process` (or `PushHandler#process`) looks up state using fields from the same body (`sha`, or `repository.full_name`) that reference `orgB`'s repository, and mutates `orgB`'s `Commit`/`Stack` state despite the request never being authenticated by `orgB`'s secret [5](#0-4) .

### Citations

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
