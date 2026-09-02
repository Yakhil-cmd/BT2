### Title
Signature verification selects the HMAC secret from an unverified payload field, allowing a forged `X-Hub-Signature` to be accepted when any configured organization has no `webhook_secret` set - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks *which* GitHub App / webhook secret to validate a request against by reading `repository.owner.login` (or `organization.login`) straight out of the still-unverified JSON body, and only then checks the signature with that secret. Because `GitHubApp#verify_webhook_signature` treats a missing `webhook_secret` as automatic success, an attacker who simply claims to be an organization that Shipit has configured *without* a webhook secret bypasses signature verification entirely for that request, while the rest of the (also unverified-at-that-point) payload — the actual `repository.full_name`, commit sha, statuses, or team/member data — is processed as trusted GitHub input.

### Finding Description
The controller resolves the signing secret before verifying anything: [1](#0-0) [2](#0-1) 

`repository_owner` is taken directly from `params.dig('repository','owner','login')` or `params.dig('organization','login')`, i.e. from attacker-controlled JSON, before the HMAC has been checked. This value is used to look up per-organization config: [3](#0-2) 

The resolved `GitHubApp` then "verifies" the signature, but if that organization's config has no `webhook_secret`, verification is unconditionally `true`: [4](#0-3) 

Multi-organization deployments are an explicitly documented, supported configuration shape, and the shipped example/test fixtures show `webhook_secret` left blank per-organization is a normal state (not an edge case): [5](#0-4) [6](#0-5) 

**The broken binding, stated as an equality that should hold but doesn't:**
`organization whose secret validated the HMAC` == `organization Shipit believes actually originated the event and whose stack/team data is trusted downstream`.

Before the fix, an attacker only needs `repository.owner.login` (or `organization.login`) to equal the name of *any* org configured on the instance with a blank `webhook_secret`. The signature check passes regardless of the actual `X-Hub-Signature` header content, and the entire raw body — including `repository.full_name`, commit SHAs, statuses, check-suite conclusions, or team/membership fields for a `membership` event — is then dispatched to the real handlers as if it came from GitHub.

### Impact Explanation
This crosses the "High" bar explicitly listed as in-scope: escalation into `Shipit.github_teams` authorization. `Shipit::Team` has a `membership` webhook requirement used to add/remove team members that gate deploy authorization: [7](#0-6) 

A forged `membership` event (accepted once its claimed org lacks a `webhook_secret`) lets an unprivileged attacker add an arbitrary GitHub login to a `Team`, which is consumed by `Shipit.github_teams` / the OAuth authorization check (`lib/shipit.rb`, `app/controllers/concerns/shipit/authentication.rb`) to grant Shipit access — i.e., unauthorized escalation into the app's authorization model. The same bypass also lets the attacker forge `push`, `status`, or `check_suite` events for any stack tracked by Shipit, an unauthenticated write of stack/commit/check state.

### Likelihood Explanation
Medium-to-High: exploitation requires only that the deployment (a) uses the documented multi-organization `github:` config format and (b) leaves `webhook_secret` unset for at least one configured organization — a configuration explicitly shown as valid/default in the shipped example and test fixtures. No secret, token, or session is needed by the attacker; only knowledge of the target org's name (public information) and the ability to POST to `/github/webhooks` (or the mounted webhook path).

### Recommendation
Do not select the verification secret from unverified request data. Either:
1. Verify the signature against every configured organization's secret (or a single well-known instance-wide secret) before trusting any field of the payload to choose behavior, or
2. Require `webhook_secret` to be present for every configured organization and fail closed (reject the request) rather than accepting an unsigned payload when a secret is absent, and
3. Only use the (now-verified) payload's repository/organization fields after signature validation succeeds using a secret whose selection did not depend on attacker-controlled input.

### Proof of Concept
1. Configure Shipit with two organizations per the documented multi-org format, where `OrgVictim` has a real `webhook_secret` and `OrgNoSecret` has none set (as shown in `config/secrets.development.shopify.yml`).
2. Attacker sends `POST /github/webhooks` with header `X-Github-Event: membership`, an arbitrary/garbage `X-Hub-Signature`, and a JSON body:
```json
{
  "organization": { "login": "OrgNoSecret" },
  "action": "added",
  "team": { "id": 1, "name": "Admins", "slug": "admins", "url": "https://example.com" },
  "member": { "login": "attacker" }
}
```
3. `repository_owner` resolves to `"OrgNoSecret"`; `Shipit.github(organization: "OrgNoSecret")` returns a `GitHubApp` with `webhook_secret == nil`; `verify_webhook_signature` returns `true` unconditionally (`lib/shipit/github_app.rb:76-77`), regardless of the bogus signature.
4. The request proceeds to `create`, and the `membership` handler adds `attacker` to team `admins`, granting whatever access `Shipit.github_teams` maps to that team — without ever presenting a valid GitHub-issued signature.

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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-10)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
      # Randomly generated
      private_key: |
        -----BEGIN RSA PRIVATE KEY-----
```

**File:** app/models/shipit/team.rb (L5-15)
```ruby
    REQUIRED_HOOKS = %i[membership].freeze

    has_many :memberships
    has_many :members, class_name: :User, through: :memberships, source: :user

    has_many :github_hooks,
             -> { where(event: REQUIRED_HOOKS) },
             foreign_key: :organization,
             primary_key: :organization,
             class_name: 'GithubHook::Organization',
             inverse_of: false
```
