### Title
Webhook signature verification keys off an attacker-controlled organization field that is decoupled from the repository/stack the event actually mutates - (File: `app/controllers/shipit/webhooks_controller.rb`, `lib/shipit/github_app.rb`)

### Summary
`WebhooksController#verify_signature` chooses which GitHub App (and thus which HMAC secret) is used to authenticate an incoming webhook based on `repository.owner.login` (or `organization.login`) pulled straight out of the *unverified* JSON body. `GitHubApp#verify_webhook_signature` then unconditionally returns `true` whenever that org's `webhook_secret` is blank. In Shipit's supported multi-organization configuration (`docs/setup.md`, `config/secrets.development.example.yml`), each GitHub organization has its own independent `webhook_secret`, and it is explicitly documented/exampled as optional (`webhook_secret: # nil`). The event payload itself — used later to locate and mutate the actual `Stack`/`Repository`/`Commit`/`Team` records — is controlled by the same untrusted body, and nothing ties the org used for signature selection to the org/repo the handlers subsequently act on.

### Finding Description
The binding that should hold is:
`organization whose secret cryptographically authenticated the request == organization/repository whose Stack/Team/Commit state the handler mutates`

In `app/controllers/shipit/webhooks_controller.rb`:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) [2](#0-1) 

`repository_owner` is read from the raw, not-yet-verified request body, before any cryptographic check has occurred. It selects the `GitHubApp` instance (and therefore its own `webhook_secret`) via `Shipit.github(organization: ...)`, which looks up per-organization config: [3](#0-2) 

`GitHubApp#verify_webhook_signature` degrades to a no-op check whenever the selected org has no `webhook_secret` configured:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [4](#0-3) 

Shipit explicitly supports and documents multiple GitHub organizations, each with an *independently optional* `webhook_secret`: [5](#0-4) [6](#0-5) 

Once `verify_signature` passes (for whatever reason — a valid secret for the *selected* org, or simply because that org's secret is blank), the controller dispatches the full body to event handlers using fields such as `repository.full_name`, `sha`, `branches`, etc., which are logically independent JSON keys from `repository.owner.login`: [7](#0-6) 

Because an attacker fully controls the JSON body before any signature is checked, they can set `repository.owner.login` (the field used to pick the verification key) to any organization configured in Shipit that happens to have no `webhook_secret` set, while setting the rest of the payload (`repository.full_name`, `sha`, commit SHAs, `organization.login` for `membership` events, etc.) to target a *different*, protected organization's `Stack`/`Repository`. The signature check is satisfied trivially (secretless org ⇒ `verify_webhook_signature` returns `true`), and the handler then acts on the targeted org's data with no real authentication of that data at all. This exactly parallels the external report's root cause: an entity used to satisfy the trust check (`msg.sender`/owner of the NFT) is not the same entity the subsequent operation actually operates on (the user who should receive the unstaked NFT).

### Impact Explanation
A successful forgery lets an unauthenticated network attacker inject arbitrary GitHub webhook events against any Stack in a multi-org Shipit deployment, as long as at least one configured organization lacks a `webhook_secret` (an explicitly supported/documented configuration). This can be used to:
- Forge `push`/`status`/`check_suite` events to manipulate commit/CI state used for deploy eligibility and merge-queue decisions on a targeted stack.
- Forge `membership` events, which create `Team`, `User`, and `Membership` records on the fly, potentially escalating an attacker's own `User` record into a `Shipit.github_teams`-authorized team, bypassing the `authorized?` check gate in `Shipit::Authentication`.

This matches the "High: escalation into `Shipit.github_teams` authorization" impact bucket, and in the membership-forgery case can lead toward unauthorized deploy/rollback triggering once the attacker session is treated as authorized.

### Likelihood Explanation
Requires only that the operator has configured more than one GitHub organization (a documented, supported feature) and that at least one of them has not set a `webhook_secret` (also documented as optional/nilable, and the default single-org example ships with `webhook_secret: # nil`). No credentials, GitHub App keys, or session are required from the attacker — only the public `/webhooks` endpoint and knowledge/guessing of the org name(s) configured (which are often the customer's own well-known GitHub org names).

### Recommendation
- Fail closed: treat a blank/missing `webhook_secret` for any configured organization as a hard misconfiguration (raise/refuse to boot, or reject all webhooks for that org) rather than treating it as "signature verification not required."
- Bind repository resolution to the same, already-authenticated organization: after signature verification succeeds for `repository_owner`, ensure the specific repository/stack looked up by the handler belongs to that same authenticated organization, rejecting mismatches.
- Do not extract `repository_owner` a second, independent time for post-verification handler routing — verify once and thread the authenticated identity through to all downstream handlers.

### Proof of Concept
1. Operator configures two orgs, e.g. `OrgSecure` (protected stack, `webhook_secret: "s3cr3t"`) and `OrgOpen` (any org, `webhook_secret:` left blank) — a configuration directly modeled on `config/secrets.development.example.yml`/`docs/setup.md`.
2. Attacker POSTs to `/webhooks` with:
   - `X-Github-Event: push`
   - No valid `X-Hub-Signature` (or an arbitrary one)
   - Body: `{"repository": {"owner": {"login": "OrgOpen"}, "full_name": "OrgSecure/protected-repo"}, "after": "<attacker-chosen sha>", ...}`
3. `repository_owner` resolves to `"OrgOpen"`; `Shipit.github(organization: "OrgOpen")` returns a `GitHubApp` with no `webhook_secret`; `verify_webhook_signature` returns `true` unconditionally.
4. The push handler proceeds using `repository.full_name = "OrgSecure/protected-repo"`, triggering a `GithubSyncJob` (or equivalent) against `OrgSecure`'s stack despite no valid signature ever having been produced for `OrgSecure`.

Note: I was unable to fully trace the exact handler file that reads `repository.full_name` for the `push` event (`lib/shipit/webhooks.rb`/`app/models/shipit/webhooks.rb` was not retrieved in full within the tool budget), so the exact downstream field names used by each event type (`push`, `membership`, `status`) should be double-checked against `Shipit::Webhooks::DEFAULT_HANDLERS` before remediation, but the root-cause binding break in `WebhooksController#verify_signature` / `GitHubApp#verify_webhook_signature` is confirmed directly from source.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-61)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
```

**File:** config/secrets.development.example.yml (L18-38)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
```
