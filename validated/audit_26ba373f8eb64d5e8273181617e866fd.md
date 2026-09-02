### Title
Cross-organization / cross-repository state manipulation via mismatched signature-scope and write-scope fields in `WebhooksController` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects *which* GitHub App/organization secret to validate a webhook against using `repository.owner.login` (falling back to `organization.login`), but every event handler that actually mutates state resolves the target `Repository`/`Stack` using the independent `repository.full_name` field. Nothing ties these two fields together, so the organization whose signature is checked is not necessarily the organization whose repository gets written to.

### Finding Description
`verify_signature` computes the signing organization purely from attacker-supplied JSON: [1](#0-0) 
That organization is used to pick the `GitHubApp` (and its `webhook_secret`) used for HMAC verification: [2](#0-1) 

Meanwhile, `Shipit::Webhooks::Handlers::Handler#stacks` (the base class used by `PushHandler` and others) and every `PullRequest::*Handler` resolve the affected `Repository`/`Stack` from a *different* field, `repository.full_name`: [3](#0-2) [4](#0-3) 

`Shipit.github_app_config`/`Shipit.github` looks up a per-organization config keyed by whatever organization string appears in the payload (supported multi-org schema): [5](#0-4) 

`GitHubApp#verify_webhook_signature` trivially returns `true` when no `webhook_secret` is configured for that organization — a first-class, documented configuration state (see the shipped multi-org example configs where `webhook_secret:` is left blank/nil): [6](#0-5) [7](#0-6) [8](#0-7) 

**Binding that should hold:** `organization_that_authenticated(repository.owner.login) == organization_that_owns(repository.full_name)`.

**Before the attack:** an operator running Shipit against multiple GitHub organizations configures at least one organization without (yet) setting `webhook_secret` (a state explicitly supported by `lib/shipit.rb`'s multi-org schema and the shipped example secrets files), while other organizations tracked by the same Shipit instance have properly configured, secret-protected GitHub Apps and real tracked repositories/stacks.

**After the attack:** an unauthenticated, unprivileged party (no `webhook_secret`, no `ApiClient` token, no GitHub write access) POSTs directly to `/webhooks` with:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": { "full_name": "trusted-org/production-repo", "owner": { "login": "unsecured-org" } }
}
```
`repository_owner` resolves to `unsecured-org`, whose `GitHubApp#verify_webhook_signature` unconditionally returns `true` (no secret configured), so `verify_signature` passes. `PushHandler#process` then resolves `stacks` via `Repository.from_github_repo_name("trusted-org/production-repo")` — a real, unrelated, secured stack — and calls `stack.sync_github(expected_head_sha: params.after)` with an attacker-chosen SHA, and the same field-mismatch pattern applies identically to every `PullRequest::*Handler` (`OpenedHandler`, `LabeledHandler`, `ClosedHandler`, `ReopenedHandler`, `UnlabeledHandler`), all of which key off `params.repository.full_name` for stack resolution and `archive!`/`unarchive!`/provisioning actions.

### Impact Explanation
This crosses an organization/repository trust boundary that the code's own webhook authentication model is meant to enforce: signature verification is supposed to prove the request originates from the GitHub App installed for the organization owning the target repository, but the org used for verification and the repository actually acted upon are read from two independently attacker-controlled JSON fields with no cross-check. This allows an unauthenticated party to trigger sync/archive/unarchive/provisioning state transitions on stacks belonging to a completely different, fully-secured organization, satisfying the "unauthorized deploy/rollback" and cross-repository-write class of High/Critical impact defined in scope.

### Likelihood Explanation
Requires only that the Shipit instance track more than one GitHub organization and that at least one configured organization currently has no `webhook_secret` set — a state the engine's own documentation and shipped example configs (`docs/setup.md`, `config/secrets.development.shopify.yml`) present as a normal/expected multi-org configuration, not a misconfiguration unique to a careless operator (e.g., during initial onboarding of a new org before the webhook secret has been generated). No credential, session, or repository write access of any kind is needed by the attacker — a bare unauthenticated HTTP POST to `/webhooks` suffices.

### Recommendation
Bind signature verification to the same field used for state mutation: derive `repository_owner` from `repository.full_name`'s owner segment (or otherwise validate that `repository.owner.login` matches the owner segment of `repository.full_name`) before dispatching to handlers, and reject the request if they disagree. Additionally, consider treating a missing `webhook_secret` for one organization in a multi-org deployment as a configuration error rather than an implicit "always verified" bypass, since it currently allows that organization's unauthenticated identity to be used as a lever against every other configured organization's repositories.

### Proof of Concept
1. Configure Shipit with two organizations: `trusted-org` (webhook_secret set, tracks stack for `trusted-org/production-repo`) and `unsecured-org` (webhook_secret left nil, per supported multi-org schema).
2. As an unauthenticated attacker, send:
```
POST /webhooks
X-Github-Event: push
Content-Type: application/json

{
  "ref": "refs/heads/master",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "full_name": "trusted-org/production-repo",
    "owner": { "login": "unsecured-org" }
  }
}
```
3. `WebhooksController#verify_signature` resolves `repository_owner` to `unsecured-org`; `Shipit.github(organization: "unsecured-org").verify_webhook_signature(...)` returns `true` because `webhook_secret` is nil (`lib/shipit/github_app.rb:76-83`), so the request is accepted with `head(:ok)` in `create`.
4. `PushHandler#process` resolves `stacks` from `repository.full_name` = `"trusted-org/production-repo"` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`), an entirely unrelated, secured repository, and invokes `stack.sync_github(expected_head_sha: "deadbeef...")` on it — a write triggered without ever validating a signature scoped to `trusted-org`.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
