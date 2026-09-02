### Title
`StatusHandler` Writes Commit Statuses Without Verifying The Signed Organization Owns The Target Commit - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` only proves that the payload was signed by the GitHub App installed for the organization named in `repository.owner.login`/`organization.login`. Nothing downstream re-checks that this authenticated organization actually owns the resource the handler mutates. `StatusHandler` looks up commits by a bare, database-wide `sha` with no repository/organization scoping at all, so a valid signature from *any* configured organization is sufficient to write a fabricated CI status onto a commit that belongs to a *different* organization's stack.

### Finding Description
The webhook signature check selects the verifying GitHub App purely from the payload's own `repository.owner.login` (or `organization.login`) field: [1](#0-0) 

This binds "signature is valid" to "signed by organization X", where X is attacker-controlled input inside the very payload being verified. In Shipit's documented multi-tenant configuration, each organization has its own `github.<org>.webhook_secret`: [2](#0-1) [3](#0-2) 

An organization administrator legitimately knows the `webhook_secret` configured for their own org's GitHub App installation. `verify_webhook_signature` only proves the raw body was HMAC-signed with that org's secret — it says nothing about which repository/commit inside the payload is trustworthy relative to other organizations: [4](#0-3) 

Once the signature check passes, `StatusHandler#process` looks up commits **globally by sha only**, with no scoping to the repository/organization that was authenticated: [5](#0-4) 

The base `Handler` class does define a `repository_name`/`stacks` scoping helper, but `StatusHandler` never uses it: [6](#0-5) 

This breaks the required binding:
`organization_authenticated(webhook signature) == organization_that_owns(commit.sha written)`

The equality holds implicitly for `push`/`pull_request` handlers because they filter by `params.repository.full_name` (the same repository field that determined the signing organization). It does **not** hold for `status`, because the handler ignores `repository` entirely and only trusts `sha`, a value that is public GitHub information and not scoped by the authenticated organization.

### Impact Explanation
An attacker who administers (or is a webhook-privileged member of) any organization `OrgAttacker` that has its own legitimate GitHub App/webhook installed on this shared Shipit instance can:
1. Compute a valid `X-Hub-Signature` using `OrgAttacker`'s own `webhook_secret`.
2. Set `repository.owner.login` = `"OrgAttacker"` so `verify_signature` passes.
3. Set `sha` to the SHA of a commit belonging to a victim's stack in a completely unrelated organization (`OrgVictim`), a value that is public on GitHub.
4. `StatusHandler` will create/update a `Status` (e.g., `state: "success"`, arbitrary `context`) on the victim's commit via `commit.create_status_from_github!`.

Because Shipit's `ci.require`/merge-queue gating relies on recorded commit statuses to determine deployability/mergeability (`ci.require`, `ci.allow_failures` in `shipit.yml`), this lets an attacker who is unprivileged with respect to the victim repository forge a passing CI status and help satisfy the conditions for an unauthorized merge or deploy of the victim's stack — one of the explicitly accepted High-severity impacts.

### Likelihood Explanation
This requires only: (a) the target Shipit instance to host multiple organizations (a documented, supported configuration), (b) the attacker to control any one of those organizations' own webhook delivery, and (c) knowledge of a target commit SHA in the victim repository (public GitHub data). No `GITHUB_TOKEN`, `ApiClient` token, `api_clients_secret`, GitHub App private key, or victim credentials are needed — exactly the class of unprivileged, credential-boundary-crossing bug this scan targets.

### Recommendation
In `StatusHandler` (and any other handler that does not already scope by `repository.full_name`), require and validate a `repository` field and resolve the commit only within stacks belonging to that repository (mirroring `Handler#stacks`/`Handler#repository_name`), rather than searching `Commit` globally by `sha`. Additionally, `WebhooksController#verify_signature` should ensure the organization used to select the webhook secret is cross-checked against the organization that owns every resource the handler subsequently mutates, not merely trusted from the same unauthenticated JSON body.

### Proof of Concept
1. Configure Shipit in multi-org mode with `OrgAttacker` and `OrgVictim`, each with their own GitHub App and `webhook_secret` (`docs/setup.md` "Using Multiple Github Applications").
2. As an administrator of `OrgAttacker`, obtain `OrgAttacker`'s `webhook_secret` (legitimately known, since they configured it).
3. Find a public commit SHA belonging to a stack under `OrgVictim/some-repo` that is deployable/mergeable pending CI.
4. Send:
```
POST /webhooks
X-Github-Event: status
X-Hub-Signature: sha1=<HMAC-SHA1(OrgAttacker_webhook_secret, body)>
Body:
{
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "required-ci-check",
  "repository": { "owner": { "login": "OrgAttacker" }, "full_name": "OrgAttacker/irrelevant-repo" }
}
```
5. `verify_signature` succeeds (signed by `OrgAttacker`'s real secret). `StatusHandler#process` runs `Commit.where(sha: params.sha)` and finds the victim's commit (no repository check), creating a forged passing status on it via `commit.create_status_from_github!`, potentially unblocking a deploy/merge gated on that CI context.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
