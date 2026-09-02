### Title
Webhook signature verified against `repository.owner.login`'s app config while handlers act on the unrelated `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
In multi-tenant Shipit deployments (`secrets.github` keyed by organization, as documented for `github.oauth.teams`/per-org configs), the webhook controller selects *which* GitHub App/webhook secret to verify a delivery against using one field of the untrusted JSON body (`repository.owner.login`), while every webhook handler subsequently resolves *which repository/stack to mutate* using a different, independently-read field of the same body (`repository.full_name`). Nothing ties these two fields together, so a valid signature for organization A's own webhook secret can be attached to a payload that names organization B's repository as the target.

### Finding Description
`WebhooksController#verify_signature` picks the app config to verify against from the payload itself, not from any authenticated context: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` looks the config (and its `webhook_secret`) up per-organization from `secrets.github`, supporting multiple tenants each with their own registered GitHub App/secret: [3](#0-2) 

`GitHubApp#verify_webhook_signature` only HMACs the raw body against whichever `webhook_secret` was selected for that organization: [4](#0-3) 

Once the request is accepted, every handler (`PushHandler`, the `pull_request/*` handlers, etc.) determines the target repository/stacks from a *different* JSON field, `repository.full_name`, read independently from the same attacker-controlled body: [5](#0-4) [6](#0-5) 

The equality that should hold but doesn't:
`organization whose secret authenticated the request (repository.owner.login)` == `organization/repository whose stacks are mutated (repository.full_name)`

Before the attack: an org's own webhook secret can only be used to sign events for that org's own repositories, because GitHub itself binds the delivery to the installation.
After the attack: a party who legitimately knows one tenant's `webhook_secret` (e.g., because they registered/administer that org's GitHub App in a multi-tenant Shipit instance, as documented in `docs/setup.md`) can HMAC-sign an arbitrary JSON body with `repository.owner.login` set to their own org (so `verify_signature` succeeds) but `repository.full_name` set to `victim-org/victim-repo`. `verify_signature` passes because it only checks the HMAC against the attacker's own known secret; the handler then loads and mutates `victim-org/victim-repo`'s stacks via `Repository.from_github_repo_name(repository_name)`.

### Impact Explanation
This breaks the isolation between tenants/organizations in a multi-org Shipit deployment: a party who is fully unprivileged with respect to `victim-org` (no GitHub write access there, no Shipit account there) can forge webhook events accepted as authentic for `victim-org`'s repositories. Depending on the handler abused:
- `PushHandler` triggers `stack.sync_github(expected_head_sha:)`, letting the attacker assert an arbitrary "latest pushed" SHA for the victim's stack/branch, influencing what Shipit considers deployable.
- The `pull_request/*` handlers (`opened`, `labeled`, `closed`, etc.) manipulate merge-queue/merge-status state and PR labels/status on the victim's stacks.

This is a cross-tenant/cross-repository write achieved purely by mismatching two fields inside a signed payload — matching the "cross-repository writes" / "unauthorized deploy, rollback or merge" impact class.

### Likelihood Explanation
Requires a multi-tenant Shipit configuration where multiple organizations each have their own entry (and `webhook_secret`) under `secrets.github`, which is an explicitly documented and supported configuration shape (`docs/setup.md`, `Shipit.github_organizations`/`github_app_config`). Any admin of one configured tenant organization can mount the attack against any other tenant sharing the same Shipit instance without needing that victim's credentials.

### Recommendation
When resolving the target repository/stack in `Shipit::Webhooks::Handlers::Handler#repository_name` (and everywhere `repository.full_name` is trusted), assert that the repository's owner matches the organization whose key verified the signature (`repository_owner` computed in `WebhooksController`), rejecting/discarding events where they diverge. Alternatively, thread the authenticated organization through to the handler and scope `Repository.from_github_repo_name` lookups to stacks belonging to that organization only.

### Proof of Concept
1. Configure Shipit with two tenants in `secrets.github`, e.g. `attacker-org` and `victim-org`, each with their own `webhook_secret`.
2. As the admin of `attacker-org` (who legitimately knows `attacker-org`'s `webhook_secret`), craft a JSON payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Sign the raw body with `attacker-org`'s `webhook_secret` using HMAC-SHA1 to produce `X-Hub-Signature`, and POST it to `/github/webhooks` with `X-Github-Event: push`.
4. `verify_signature` calls `Shipit.github(organization: "attacker-org")` (derived from `repository.owner.login`), verifies successfully against the attacker's own secret.
5. `PushHandler#process` resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen sha>")` on the victim's stacks, despite the attacker never having authenticated as, or received a signed webhook from, `victim-org`.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
