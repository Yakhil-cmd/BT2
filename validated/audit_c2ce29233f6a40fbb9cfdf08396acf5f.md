### Title
Cross-organization webhook forgery via unauthenticated "no-secret" GitHub App entry — signature verification org selection is decoupled from the repository/commit actually mutated ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks *which* configured GitHub App's `webhook_secret` to validate the request against using a value taken straight from the unauthenticated JSON body (`repository.owner.login`, or `organization.login`), while the code that actually executes the webhook (`StatusHandler`, `PushHandler`, etc.) trusts other body fields (`sha`, `repository.full_name`) that are never cross-checked against that same organization. In a multi-organization Shipit deployment where any one configured organization has `webhook_secret` unset (a documented, normal configuration state), an attacker can pick that organization as the "verifying" identity to skip signature validation entirely, while still writing state for a completely different, protected organization/stack.

### Finding Description
`WebhooksController#verify_signature` derives the "authenticating organization" purely from the request body: [1](#0-0) [2](#0-1) 

That organization is then used to select a `GitHubApp` config via `Shipit.github(organization:)`, and in `GitHubApp#verify_webhook_signature`, if that organization's config has no `webhook_secret` set, verification is unconditionally treated as successful, with no signature comparison at all: [3](#0-2) 

`webhook_secret: nil` is a normal, documented configuration value — every secrets template in this repo ships with it commented out/nil, including a multi-organization example with two orgs, both `webhook_secret: # nil`: [4](#0-3) [5](#0-4) 

`Shipit.github` looks up per-organization config by the attacker-controlled organization key and only rejects genuinely unconfigured organizations: [6](#0-5) 

Once the (fake) signature check passes, `WebhooksController#create` dispatches the *entire, attacker-controlled* JSON body to the event handlers, unrelated to which organization "verified" it: [7](#0-6) 

Critically, `StatusHandler` (and other handlers) never re-validate that the payload's `repository`/`organization` field matches the organization used for signature verification. `StatusHandler` in particular does not scope by repository at all — it finds any `Commit` in the entire database by raw `sha` and writes a GitHub status onto it: [8](#0-7) 

This is a direct analog of the reported bug class: an input value (`repository.owner.login` / `organization.login`) is accepted purely to select a verification context, but the strict equality that should bind "the organization whose credentials verified this request" to "the repository/commit this request is allowed to mutate" is never enforced. The binding that should hold is:

`organization used to verify signature == organization owning the repository/commit acted upon`

but the code allows these to diverge because the two lookups (`repository_owner` for auth selection vs. `repository.full_name`/`sha` for mutation) are read from independent, unauthenticated fields of the same forgeable JSON body.

### Impact Explanation
An attacker with no credentials at all can:
1. Send a POST to `/webhooks` claiming `X-Github-Event: status`, with `repository.owner.login` (or `organization.login`) set to any organization configured in Shipit's `secrets.github` that has no `webhook_secret` set — this is common in multi-org setups where an org has not yet completed webhook configuration.
2. Include an arbitrary `sha` matching a commit that belongs to a *different*, protected stack, and `state: "success"`.
3. `verify_webhook_signature` returns `true` unconditionally (no `X-Hub-Signature` needed), and `StatusHandler` writes a forged "success" CI status onto that commit — with zero relation between the "verifying" org and the org whose commit is mutated.

Forged commit statuses can unblock deploy-safety gating (blocking statuses are used by Shipit to gate/allow deploys and merge-queue progression), enabling an unauthorized deploy of a target stack the attacker has no access to. The same organization-selection flaw also lets an attacker trigger `PushHandler`/`CheckSuiteHandler` processing (forcing syncs/refreshes) against arbitrary repositories tracked by Shipit, again by "authenticating" as an unrelated, secret-less org while acting on a different org's repository via `repository.full_name`.

### Likelihood Explanation
Exploitability depends entirely on server configuration: it requires that the Shipit deployment manages more than one GitHub organization and that at least one configured organization has no `webhook_secret` set. This is explicitly the default/documented state in every secrets template shipped in this codebase (`config/secrets.development.example.yml`, `config/secrets.development.shopify.yml`, `docs/setup.md`), making it a realistic, low-effort misconfiguration rather than a contrived edge case — no GitHub App private key, webhook secret, or repository access is required by the attacker at all.

### Recommendation
Enforce the binding explicitly: derive the verifying organization from the same field the handler will act upon (or vice versa), and reject any request where `repository.full_name`'s owner does not match the organization whose secret validated the signature. Additionally, `StatusHandler` (and any handler resolving records without going through `Handler#stacks`/`repository_name`) should scope lookups (e.g. `Commit.where(sha:)`) by the repository/organization actually present in the verified webhook, not merely by a globally-unique `sha`. Also consider disallowing organizations with no `webhook_secret` from a "trivially trusted" bypass path when multiple organizations are configured, or require an explicit opt-in flag for unauthenticated webhook orgs.

### Proof of Concept
Given a Shipit deployment configured with two GitHub orgs in `secrets.github`, e.g. `OrgA` (no `webhook_secret` configured) and `VictimOrg` (has `webhook_secret` configured, hosts a protected stack requiring a passing "ci" status before deploy):

```
POST /webhooks
X-Github-Event: status
Content-Type: application/json
(no X-Hub-Signature header required)

{
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgA/unrelated-repo" },
  "sha": "<sha of a commit belonging to VictimOrg/protected-repo>",
  "state": "success",
  "context": "ci/required-check",
  "created_at": "2026-09-01T00:00:00Z"
}
```

`verify_signature` selects `Shipit.github(organization: "OrgA")`; since `OrgA` has no `webhook_secret`, `verify_webhook_signature` returns `true` without checking any signature. `StatusHandler#process` then finds the commit purely by `sha` (no ownership check) and marks it as passing, even though the request was never authenticated by `VictimOrg`'s GitHub App/secret at all.

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

**File:** docs/setup.md (L119-119)
```markdown
**`github.webhook_secret`** If you've set a webhook secret during the App creating, you should copy it here.
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
