### Title
Webhook signing-organization confused with acted-upon repository, enabling cross-organization webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret used to authenticate an inbound webhook based on `repository_owner`, which is read from `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`). The event handlers that subsequently act on the payload, however, resolve the target repository/stack from a *different* field: `payload.dig('repository', 'full_name')` in `Handler#repository_name`. Because these two payload fields are never bound together by the signature check, the organization whose secret authenticated the request is not guaranteed to be the organization that owns the repository actually mutated.

### Finding Description
`verify_signature` in `app/controllers/shipit/webhooks_controller.rb` does: [1](#0-0) 
`repository_owner` is derived purely from the JSON body: [2](#0-1) 
`Shipit.github(organization: repository_owner)` looks up the per-organization app config (secret, etc.) via `github_app_config`: [3](#0-2) 
and `verify_webhook_signature` HMAC's the raw body with that organization's `webhook_secret`: [4](#0-3) 

Once the signature check passes, `Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches to handlers such as those under `app/models/shipit/webhooks/handlers/**`, all of which extend `Handler` and resolve the target stacks via: [5](#0-4) 

Nothing ties `repository.owner.login` (the field used to select the verifying secret) to `repository.full_name` (the field used to select the repository actually mutated). An attacker who possesses the webhook secret for *any one* organization configured in `Shipit.secrets.github` (multi-organization deployments select the secret per-org key, see `github_app_config`) can send a POST to `/webhooks` with `repository.owner.login` set to their own (secret-holding) organization but `repository.full_name` set to an arbitrary other org/repo tracked by the same Shipit instance. The signature check passes (it only proves knowledge of the attacker's own org's secret), yet the handler acts on a repository belonging to a different, victim organization — e.g. queuing `GithubSyncJob`, creating `Status`, or mutating `Commit`/`Task` state for a stack the attacker has no legitimate relationship with.

### Impact Explanation
This breaks the equality that should hold: `organization authenticated by the webhook signature == organization owning the repository/stack mutated by the resulting handler`. In a multi-organization Shipit deployment, this allows a party who administers/owns the webhook configuration for one tracked GitHub organization to forge events (pushes, statuses, check-suite completions, membership changes, etc.) that are attributed to and act upon a completely different organization's repositories and stacks — a cross-organization write with no repository-level authorization on the victim side. This matches the High/Critical category of "cross-repository writes" via a broken trust binding.

### Likelihood Explanation
Exploitability depends entirely on the deployment running Shipit with more than one entry under `secrets.github` (per-organization app configs, each with its own `webhook_secret`) — a supported, documented configuration path (`github_app_config`, `github_organizations`). In such multi-tenant setups, likelihood is Medium: the attacker only needs legitimate control of one tracked org's webhook secret (something a GitHub org admin normally can see/rotate for their own org's app installation) to attack every other org monitored by the same Shipit instance. In single-organization deployments this specific confusion is not exploitable since there is only one secret.

### Recommendation
Bind the field used to select the verifying secret to the field used to determine the acted-upon repository: verify that `payload.dig('repository', 'owner', 'login')` matches the owner segment of `payload.dig('repository', 'full_name')` before dispatching to handlers, or better, derive the resolved `Repository`/`Stack` and re-check that its owning organization equals `repository_owner` used for signature verification, rejecting the request (422) on mismatch.

### Proof of Concept
1. Configure Shipit with two organizations in `secrets.github`, e.g. `attacker-org` and `victim-org`, each with a distinct `webhook_secret`.
2. As an attacker who knows `attacker-org`'s webhook secret (e.g. because they administer that org's GitHub App/webhook settings), craft a `push` (or other handled) event payload where:
   - `repository.owner.login = "attacker-org"`
   - `repository.full_name = "victim-org/some-tracked-repo"`
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(attacker-org secret, raw_body)>` and POST to `/webhooks` with header `X-Github-Event: push`.
4. `verify_signature` resolves `Shipit.github(organization: "attacker-org")` and successfully verifies the signature against the attacker-controlled secret.
5. `Handler#repository_name` resolves `"victim-org/some-tracked-repo"`, and the corresponding handler (e.g. queuing `GithubSyncJob`) acts on the victim organization's stack, even though the attacker never proved control of `victim-org`.

### Citations

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
