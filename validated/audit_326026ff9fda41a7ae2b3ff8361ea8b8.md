### Title
Webhook signature verified against attacker-chosen organization while payload-driven repository lookup uses a different, unchecked field, allowing cross-organization stack writes - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
Shipit's multi-tenant GitHub App support (`Shipit.github(organization:)`) lets a single Shipit instance host multiple organizations, each with its own `webhook_secret`. `WebhooksController#verify_signature` selects which organization's secret to verify the HMAC signature against using a field taken directly from the unauthenticated JSON body, while the handlers that actually act on the payload (e.g. `PushHandler`) resolve the target `Stack`/`Repository` using a *different* field of that same unauthenticated body. Because the two fields are never cross-checked, a request signed with organization A's webhook secret can direct the resulting `Stack#sync_github` action (or other webhook side effects) at any organization B's repository configured on the same Shipit instance.

### Finding Description
`WebhooksController#verify_signature` determines the "authenticating" organization from the raw JSON body: [1](#0-0) [2](#0-1) 

It then verifies the HMAC using `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`, where each organization has an independently configured `webhook_secret`: [3](#0-2) [4](#0-3) 

Once the signature check passes, the raw JSON body is dispatched unmodified to the matching handler: [5](#0-4) 

Handlers, however, resolve which repository/stack to act on using a **different key** of the same JSON body — `repository.full_name` — not `repository.owner.login`/`organization.login` used for signature selection: [6](#0-5) [7](#0-6) [8](#0-7) 

The equality that should hold but is never enforced is:
`organization used to select the webhook_secret for HMAC verification == owner prefix of repository.full_name used to resolve the Repository/Stack that gets acted upon`.

Before the attacker's request: an organization's webhook secret only authorizes events for that organization's own repositories, because a genuine GitHub delivery always has consistent `repository.owner.login` and `repository.full_name` fields.

After the attacker's request: an attacker who is entitled to install/administer a Shipit-connected GitHub App/webhook for organization A (and therefore legitimately knows or can generate a validly-signed payload with organization A's `webhook_secret`) can set `repository.owner.login`/`organization.login` to `"orgA"` (so `verify_signature` fetches and matches against orgA's secret) while setting `repository.full_name` to `"orgB/victim-repo"` (a repository belonging to a completely different tenant hosted on the same Shipit instance). The signature check passes because it is computed only over `repository_owner = orgA`, but `PushHandler` (and other handlers keyed off `full_name`, e.g. `status`, `check_suite`) will look up and act on `orgB/victim-repo`'s `Stack`, e.g. triggering `stack.sync_github(expected_head_sha:)` for a target the attacker does not control at all.

### Impact Explanation
This breaks a hard organization/tenant isolation boundary: possession of a legitimate webhook credential for organization A becomes sufficient to inject and process forged webhook events (push, status, check_suite, membership, pull_request, etc.) against organization B's stacks. Depending on the handler this can trigger unauthorized `GithubSyncJob` runs, spurious commit statuses, or fabricated pull-request/membership state for a repository the attacker has no legitimate relationship to — a cross-tenant/cross-repository write achieved purely by an unprivileged-w.r.t.-org-B attacker. This matches the "cross-repository writes" High/Critical impact category defined for this analysis.

### Likelihood Explanation
Exploitability requires the deployment to be multi-tenant (multiple organizations configured under `secrets.github`, each with distinct `webhook_secret`, matching Shipit's documented multi-org support). Given that configuration — which is a supported and documented deployment mode, not a misconfiguration — any tenant who legitimately controls one organization's GitHub App/webhook secret can immediately forge cross-tenant payloads with no further access needed; there is no additional secret or session required beyond what that org's admin already legitimately possesses.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler#repository_name`), require that the organization used to select/validate the webhook secret match the owner segment of `repository.full_name` (and `organization.login` when present) before dispatching to handlers; reject the request (422) on mismatch. Alternatively, scope handler repository/stack lookups to only the verified organization rather than trusting the payload's `full_name` in isolation.

### Proof of Concept
1. Deploy Shipit with two organizations configured, e.g. `secrets.github["orgA"]` (webhook_secret `sA`) and `secrets.github["orgB"]` (webhook_secret `sB`), each with a Stack, e.g. `orgB/victim-repo`.
2. As an entity that legitimately administers `orgA`'s GitHub App (and thus knows `sA`), craft a `push` event JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "orgA" },
    "full_name": "orgB/victim-repo"
  }
}
```
3. Compute `X-Hub-Signature: sha1=<hmac-sha1(sA, body)>` and POST to `/webhooks` with `X-Github-Event: push`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "orgA")` and the signature validates successfully against `sA`.
5. `PushHandler#process` resolves `Repository.from_github_repo_name("orgB/victim-repo")` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen sha>")` on `orgB`'s stack — a write triggered by an entity with no legitimate relationship to `orgB`, using only `orgA`'s credentials.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
