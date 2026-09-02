I found a concrete binding mismatch in the multi-organization GitHub webhook handling that matches the requested analog class: "an organization that authenticated versus the repository that is written."

### Title
Webhook signature is verified against the organization named in the payload, but the repository written to is a different field never covered by that check - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to use for HMAC verification based on `repository_owner`, which is read from the JSON payload itself. The actual write target (which `Stack`/`Repository` gets updated) is determined later, independently, from a different payload field (`repository.full_name`) inside the handler. Because the field used to select the verification key and the field used to select the write target are not cryptographically bound together, in a multi-organization Shipit deployment (`Shipit.github_organizations`, `github_app_config`) a payload can be crafted so the signature check passes using one organization's `webhook_secret` while the mutation is applied to a repository under a different organization/tenant.

### Finding Description
`verify_signature` computes the signing organization purely from attacker-controlled JSON: [1](#0-0) 
This value is used only to look up `Shipit.github(organization: repository_owner)` and thus which `webhook_secret` HMAC to verify against: [2](#0-1) 
`Shipit.github` resolves the app config, including `webhook_secret`, purely by the organization name string with no further tie to a specific repository: [3](#0-2) 

After signature verification succeeds, the raw JSON body is dispatched unmodified to handlers: [4](#0-3) 
Handlers resolve which repository/stacks to mutate from a *different* payload key, `repository.full_name`, not `repository.owner.login`: [5](#0-4) 
`PushHandler` then uses that repository's stacks to trigger a GitHub sync against an attacker-supplied `after` SHA: [6](#0-5) 

The equality that should hold is:
`organization whose secret authenticated the signature == organization owning the repository that gets written`

In the current code this is actually:
`repository_owner (from payload.repository.owner.login OR payload.organization.login)` is used only for **key selection**, while `repository.full_name` (also fully attacker-controlled JSON, and not required to belong to the same organization) is used for **the actual write**. Nothing forces `repository.owner.login` to match the owner prefix of `repository.full_name`, nor is `repository.full_name` covered by any check that ties it to the organization that supplied the valid HMAC.

### Impact Explanation
In a Shipit installation configured for multiple GitHub organizations (each with its own `webhook_secret` under `secrets.github.<org>.webhook_secret`), an attacker who can forge/replay a validly-signed webhook for their own organization (e.g., because they administer that org's GitHub App/webhook, or because a malicious/compromised org is one of the configured tenants) can set `repository.full_name` to a repository belonging to a *different*, unrelated organization/tenant configured on the same Shipit instance. Signature verification succeeds (it only checked the attacker's own org's secret), yet `PushHandler` (and other handlers keyed off `repository.full_name`) will enqueue `GithubSyncJob`/mutate `Stack` state for the victim organization's repository — a cross-tenant write despite passing authentication for a different tenant. This crosses the "cross-repository writes" / "unauthorized ... deploy" impact bar for multi-org deployments.

### Likelihood Explanation
Requires a Shipit deployment configured with multiple GitHub organizations (the `github_default_organization`/per-org `webhook_secret` scheme in `lib/shipit.rb`), and requires the attacker to control (or have compromised) the webhook secret/signing capability for at least one of the configured organizations — which is a documented, supported multi-tenant configuration, not merely a hypothetical. No repository write access, GitHub App private key, or Shipit session is needed; only knowledge of one tenant's `webhook_secret`, which is explicitly weaker than access to another tenant's data.

### Recommendation
After verifying the HMAC using the organization resolved from the payload, re-derive the same organization from `repository.full_name`'s owner segment and require it to match `repository_owner` before dispatching to handlers; reject the webhook (422) on mismatch. Equivalently, bind signature verification to the exact `repository.full_name` (not just the org) so the signed organization and the mutated repository are the same authenticated identity.

### Proof of Concept
1. Shipit is configured with two orgs in `secrets.github`: `victim-org` and `attacker-org`, each with its own `webhook_secret`.
2. Attacker computes a valid `X-Hub-Signature` using `attacker-org`'s `webhook_secret` over a JSON body where `organization.login` / `repository.owner.login` = `attacker-org`, but `repository.full_name` = `"victim-org/private-repo"`.
3. `WebhooksController#verify_signature` calls `Shipit.github(organization: 'attacker-org')` and successfully verifies the signature against `attacker-org`'s secret (`app/controllers/shipit/webhooks_controller.rb:24-30`, `lib/shipit.rb:170-181`).
4. `create` then dispatches the raw params to `Handlers::PushHandler`, which looks up stacks via `Repository.from_github_repo_name('victim-org/private-repo')` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`) and enqueues `sync_github(expected_head_sha: <attacker-chosen sha>)` for `victim-org`'s stack (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`) — a write to a repository never covered by the verified signature's organization.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
