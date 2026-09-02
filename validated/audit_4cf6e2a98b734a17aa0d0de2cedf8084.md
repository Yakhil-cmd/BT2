### Title
Webhook Signature Verification Selects GitHub App by `repository.owner.login`, But Payload Processing Trusts `repository.full_name` — Cross-Organization Webhook Forgery - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` picks which configured GitHub App/secret to validate a webhook against using `repository_owner` (derived from `repository.owner.login`, falling back to `organization.login`), but the actual event handlers that mutate state operate on `repository.full_name` from the same unauthenticated JSON body. Nothing ties these two payload fields together, and in the documented multi-organization configuration it is normal for some organizations to have `webhook_secret: nil`. An attacker can pick any org name that has no configured `webhook_secret` for the "owner" field (bypassing signature verification entirely) while setting `repository.full_name` to a *different*, protected organization/repository, letting them forge webhook events (push, status, deploy, pull_request, etc.) against that other repository without ever holding a valid HMAC signature for it.

### Finding Description
`verify_signature` resolves the GitHub App config solely from `repository_owner`: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` trivially returns `true` when the resolved app has no `webhook_secret` configured: [3](#0-2) 

Shipit explicitly supports (and documents/ships example config for) multiple GitHub Apps keyed by organization, resolved case-insensitively via `Shipit.github(organization:)` / `github_app_config`: [4](#0-3) 

and the shipped example/dummy configs default `webhook_secret` to `nil` for one or more organizations: [5](#0-4) [6](#0-5) 

After (possibly trivially) passing `verify_signature`, `WebhooksController#create` dispatches the same raw params to handlers, which look up the target repository/stack using an entirely different field, `repository.full_name`, not `repository.owner.login`: [7](#0-6) [8](#0-7) 

The binding being broken is:
`organization authenticated by verify_signature (repository.owner.login / organization.login)` ≠ `repository acted on by handlers (repository.full_name)`

Because the JSON body is fully attacker-controlled and unsigned at this point, an attacker can submit:
```json
{
  "repository": {
    "owner": { "login": "org-with-no-secret" },
    "full_name": "victim-org/victim-repo"
  },
  ...
}
```
`repository_owner` resolves to `"org-with-no-secret"`. If that organization is configured in `Shipit.secrets.github` with `webhook_secret: nil` (a valid, documented configuration state), `verify_webhook_signature` returns `true` unconditionally — no signature needed at all. Processing then proceeds using `repository.full_name = "victim-org/victim-repo"`, which can belong to a *different*, security-sensitive, properly-secreted organization. Any handler keyed off `full_name` (push → `GithubSyncJob`, status updates, pull_request handlers, deploy/merge-related webhook events) is now invocable by an unauthenticated attacker for that victim repository.

### Impact Explanation
This crosses the "unauthorized deploy/rollback/merge" impact bar: an attacker with no credentials can forge GitHub webhook events for any repository configured in Shipit, as long as at least one other configured GitHub organization on the same Shipit instance lacks a `webhook_secret` (a supported and documented deployment state, not a misconfiguration outside the code's own design). Depending on which webhook handlers exist for the target `full_name` (e.g., push triggering `GithubSyncJob`, status/check_suite handlers, pull_request label/merge handlers), this can influence deploy eligibility, merge-queue state, or CI status entirely under attacker control, breaking the deployment-trust binding between "who GitHub says signed this" and "which repository the action is applied to."

### Likelihood Explanation
Likelihood is High in any multi-org Shipit deployment where not every configured organization sets a `webhook_secret` — a state the codebase's own example/dummy configs and setup docs present as normal. No credentials, tokens, or repository access are required; only a plain unauthenticated HTTP POST to `/webhooks` with a crafted mismatched `repository.owner.login` / `repository.full_name` pair.

### Recommendation
Bind signature verification to the same repository identity the handlers act on. Concretely, `WebhooksController#verify_signature` should resolve the GitHub App using `repository.full_name`'s owner segment (or otherwise ensure the org used to fetch `github_app_config` is provably the org that owns the `full_name` being processed by handlers), or require an explicit, mandatory `webhook_secret` per configured organization (removing the `return true unless webhook_secret` bypass in `GitHubApp#verify_webhook_signature`) so an unsigned/absent-secret org can never be used to smuggle actions against another org's repositories.

### Proof of Concept
1. Configure Shipit with two organizations, e.g. `OrgOne` (no `webhook_secret`) and `VictimOrg` (has a `webhook_secret` and a real stack for `VictimOrg/victim-repo`), matching the supported multi-app schema shown in `docs/setup.md` lines 182-209 and `config/secrets.development.example.yml` lines 18-34.
2. POST to `/webhooks` with header `X-Github-Event: push` and no valid `X-Hub-Signature`, body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-controlled sha>",
  "repository": { "owner": { "login": "OrgOne" }, "full_name": "VictimOrg/victim-repo" }
}
```
3. `repository_owner` resolves to `"OrgOne"`; `Shipit.github(organization: "OrgOne").verify_webhook_signature` returns `true` because `OrgOne` has no `webhook_secret` (`lib/shipit/github_app.rb` lines 76-83), so `verify_signature` passes with no valid signature required.
4. `Shipit::Webhooks.for_event('push')` handlers run using the same JSON body, resolving the target repository via `payload.dig('repository', 'full_name')` = `"VictimOrg/victim-repo"` (`app/models/shipit/webhooks/handlers/handler.rb` lines 36-38), acting on `VictimOrg`'s stacks despite the request never being authenticated for `VictimOrg`.

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

**File:** config/secrets.development.example.yml (L18-34)
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```
