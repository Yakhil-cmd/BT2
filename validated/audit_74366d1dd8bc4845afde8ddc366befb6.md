### Title
Cross-organization webhook forgery bypasses per-organization signature binding, enabling unauthorized writes to another organization's stacks - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate against based on `repository.owner.login` (or `organization.login`) in the JSON payload, but every webhook `Handler` subclass resolves the actual `Repository`/`Stack` it acts on using a completely different field, `repository.full_name`. Because the field used to pick the verifying secret is never checked against the field used to pick the target repository, an attacker who controls one configured GitHub organization's webhook secret can forge a signed webhook whose body claims to belong to their own organization (for signature purposes) while pointing `repository.full_name` at a different organization's repository, causing Shipit to process privileged events (status updates, pushes, membership changes, PR events) against a repository the attacker never authenticated for.

### Finding Description
`verify_signature` derives which GitHub App/secret to use from the payload itself: [1](#0-0) [2](#0-1) 

`repository_owner` is read straight from the untrusted JSON body (`params.dig('repository', 'owner', 'login')`). In multi-organization deployments, `Shipit.github(organization: repository_owner)` looks up that organization's own app config and its own `webhook_secret`: [3](#0-2) 

The signature is verified with `OpenSSL::HMAC` against that organization's secret: [4](#0-3) 

However, once the signature check passes, every event handler resolves the target repository/stack using an entirely different, unverified field of the same payload: [5](#0-4) 

There is no code anywhere that asserts `repository.full_name`'s owner equals `repository_owner`/`organization.login` used to select the signing secret. The binding that should hold is:
`organization authenticated by verify_signature == organization that owns the repository the handler writes to`

This equality is never enforced. An attacker who is an admin of (or otherwise knows the webhook secret for) organization A's GitHub App integration can:
1. Build a JSON payload with `repository.owner.login = "org-a"` (or `organization.login = "org-a"`) so `verify_signature` selects and validates against org-a's own legitimate secret.
2. Set `repository.full_name = "org-b/victim-repo"` — a repository belonging to a completely different organization already onboarded onto the same Shipit instance.
3. Sign the raw body with org-a's secret and POST it to `/github/webhooks`.

`verify_signature` succeeds (org-a's HMAC is valid over the body org-a's own admin controls), and the dispatched handler (e.g. `status`, `push`, `check_suite`, `membership`, `pull_request` handlers, all inheriting `Handler#stacks`/`#repository_name`) then acts on `org-b/victim-repo`'s stacks/commits — completely outside the organization whose credentials were actually verified.

### Impact Explanation
This breaks the deployment-trust binding "an organization that authenticated versus the repository that is written," matching the Critical-impact class of cross-repository writes / unauthorized deploy or merge. Concretely, an attacker controlling only organization A's webhook secret can:
- Forge `status`/`check_suite` events claiming CI success for a commit in organization B's repository, which can unblock Shipit's merge queue / continuous delivery and cause an unauthorized merge or deploy to organization B's stack, using Shipit's real GitHub credentials for organization B.
- Forge `push` events to trigger `GithubSyncJob` against organization B's stacks.
- Forge `membership` events to add/remove `Team`/`User` memberships tied to organization B, affecting `Shipit.github_teams` authorization decisions for org-B's stacks.

None of this requires any credential, session, or repository-write access to organization B — only knowledge of a webhook secret belonging to an unrelated, separately configured organization on the same Shipit instance.

### Likelihood Explanation
Exploitability requires a multi-organization Shipit deployment (the documented `github: <org>: {...}` config schema, supported and tested in `test/dummy/config/secrets_double_github_app.yml`) where the attacker is a legitimate administrator/owner of one onboarded organization's GitHub App and thus knows that organization's `webhook_secret`, while a second, unrelated organization is also onboarded to the same instance. This is a realistic and documented deployment topology (shared Shipit instance serving multiple GitHub orgs), so likelihood is moderate-to-high in any such multi-tenant setup.

### Recommendation
After signature verification succeeds, verify that the organization implied by the field(s) actually used to resolve the target repository (`repository.full_name`'s owner segment) matches the organization whose secret validated the signature (`repository_owner`/`organization.login`). Reject the webhook (422) on mismatch. This binding check should live in `WebhooksController#verify_signature` (or a shared validation invoked before dispatch), not solely rely on `repository_owner` for secret selection while letting `Handler#repository_name` pick an unrelated value.

### Proof of Concept
1. Configure Shipit with two organizations, `org-a` and `org-b`, each with distinct `webhook_secret`s (multi-org config schema).
2. As an administrator with access to `org-a`'s webhook secret, craft a JSON body:
```json
{
  "repository": { "owner": { "login": "org-a" }, "full_name": "org-b/victim-repo" },
  "sha": "<commit-sha-in-org-b-repo>",
  "state": "success",
  "branches": [{ "name": "master" }]
}
```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(org-a-secret, body)>` and POST to `/github/webhooks` with `X-Github-Event: status`.
4. `WebhooksController#verify_signature` picks `Shipit.github(organization: "org-a")` (per `repository_owner`, `app/controllers/shipit/webhooks_controller.rb:59-62`) and successfully verifies the signature using org-a's secret.
5. The `status` handler (extending `Handler`) resolves `stacks` via `payload.dig('repository', 'full_name')` = `"org-b/victim-repo"` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`), and creates a `Status` on org-b's commit — a write to organization B's data authorized only by organization A's credentials.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```
