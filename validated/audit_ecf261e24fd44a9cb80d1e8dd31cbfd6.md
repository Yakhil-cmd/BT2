### Title
Webhook signature is verified against the organization in `repository.owner.login`, but handlers resolve the target stack from `repository.full_name` — allowing cross-organization webhook forgery ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App / `webhook_secret` to validate the HMAC signature with, based on `repository.owner.login` (or `organization.login`) extracted from the JSON payload. Every webhook `Handler` subclass, however, resolves the actual `Repository`/`Stack` to act on using a different field of the same payload: `repository.full_name`. Because these two fields are never cross-checked, when Shipit is configured with multiple GitHub Apps (one webhook secret per organization, as documented for multi-tenant setups), an attacker who legitimately controls one configured organization (and therefore knows/owns a valid `webhook_secret`) can forge a webhook whose `repository.owner.login` matches their own org (so it authenticates), while `repository.full_name` points at a stack belonging to a completely different organization.

### Finding Description
`verify_signature` computes the verifying GitHub App from the attacker-controlled field `repository_owner`: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` looks up a distinct `webhook_secret` per organization when the multi-app config schema is used: [3](#0-2) 

The signature itself is a correct HMAC over the *entire* raw body using that organization's secret: [4](#0-3) 

So far this is sound — but the base `Handler` class, used by every event handler (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, `MembershipHandler`, pull-request handlers, etc.), determines which repository/stacks to mutate using a *different* payload field, `repository.full_name`, with no relation back to the organization that was actually authenticated: [5](#0-4) 

`PushHandler`, for example, uses that stack lookup to trigger a real sync against GitHub with an attacker-influenced `expected_head_sha`: [6](#0-5) 

Because the signature only proves "this body was signed by the secret belonging to the organization named in `repository.owner.login`", but the code that follows trusts a *different, unverified* field (`repository.full_name`) to decide which organization's stacks get acted upon, the equality:

`organization that authenticated (repository.owner.login → webhook_secret)` == `repository that is written (repository.full_name → Repository/Stack)`

is never enforced. Any installation using Shipit's documented "Using Multiple GitHub Applications" feature is exposed: an attacker who administers their own onboarded organization (Org A) can send a webhook with `repository.owner.login = "org-a"` (self-signed, valid signature) and `repository.full_name = "org-b/victim-repo"`, causing handlers to operate on Org B's stacks/commits. [7](#0-6) 

### Impact Explanation
This breaks the isolation boundary between GitHub organizations sharing one Shipit instance. An attacker with legitimate write access to their own onboarded org can forge events that are processed as if they came from an unrelated organization's repository, causing `GithubSyncJob`/`sync_github` calls and other handler side effects (membership/team churn, commit-status writes, pull-request state changes) to run against stacks the attacker does not control. This is a cross-organization write / spoofing capability reachable purely by an actor with no privileges on the victim organization, matching the "cross-repository writes" class of impact.

### Likelihood Explanation
Exploitability requires the deployment to use the multi-organization GitHub App configuration (explicitly documented as a supported feature) and for the attacker to control (or have compromised) one of the configured organizations/installations. Given that is the documented intended use case for shared Shipit instances, the precondition is realistic for any multi-tenant deployment, and the forgery itself only requires crafting a JSON body — no additional secrets are needed.

### Recommendation
Bind the two payload derivations together: after selecting the GitHub App/secret via `repository_owner`, verify that `repository.full_name`'s owner segment matches that same `repository_owner` (or, better, have `Handler#repository_name`/`stacks` receive and enforce the authenticated organization rather than re-reading it from the unauthenticated-relative field), rejecting the webhook if they diverge.

### Proof of Concept
1. Configure Shipit with two organizations, `org-a` and `org-b`, each with its own `webhook_secret` (per `docs/setup.md`, "Using Multiple Github Applications").
2. As the operator of `org-a` (attacker), build a `push` payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "org-a" },
    "full_name": "org-b/victim-repo"
  }
}
```
3. Sign the raw body with `org-a`'s known `webhook_secret` and send it to `/webhooks` with header `X-Github-Event: push`.
4. `verify_signature` resolves `repository_owner` = `"org-a"`, fetches `org-a`'s app, and successfully verifies the signature (`app/controllers/shipit/webhooks_controller.rb:24-30`).
5. `PushHandler#stacks` resolves the target repository via `repository.full_name` = `"org-b/victim-repo"` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`), and calls `stack.sync_github(expected_head_sha: "<attacker-chosen sha>")` on a stack belonging to `org-b`, despite the request never being authenticated by `org-b`'s secret.

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
