### Title
Webhook signature verification is keyed to `repository.owner.login` while all event handlers act on `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate a webhook against based on `repository_owner` (parsed from `repository.owner.login`, falling back to `organization.login`), but every `Shipit::Webhooks::Handlers::Handler` subclass resolves the target `Stack`/`Repository` using a completely different field of the same payload: `repository.full_name`. In a multi-org GitHub App deployment (`Shipit.github_organizations`), this breaks the binding "organization that authenticated" vs. "repository that is written."

### Finding Description
`verify_signature` picks the webhook secret with: [1](#0-0) 
using [2](#0-1) 

Verification itself is a straight HMAC check of `request.raw_post` against the secret configured for whichever organization `repository_owner` names: [3](#0-2) 

The multi-org config path is a first-class, documented feature: [4](#0-3) [5](#0-4) 

Once verification passes, `create` dispatches the raw parsed JSON to handlers: [6](#0-5) 

Every handler resolves which `Stack` to mutate using `repository.full_name`, not `repository.owner.login`: [7](#0-6) 

Because the HMAC only proves "this body was signed with OrgX's webhook secret" and OrgX's secret is chosen using `repository.owner.login`/`organization.login`, an attacker who legitimately owns and administers OrgX's own GitHub App on this shared Shipit instance (and therefore genuinely knows OrgX's `webhook_secret`) can construct a payload where:
- `repository.owner.login` = `"OrgX"` (and/or `organization.login` = `"OrgX"`) → causes `verify_signature` to fetch and use OrgX's secret, which the attacker legitimately possesses and can sign with,
- `repository.full_name` = `"OrgY/some-tracked-repo"` (a repo belonging to a *different* organization/customer tracked on the same shared Shipit instance).

The signature will verify successfully (it was correctly computed with OrgX's real secret over the exact bytes sent), yet every downstream handler (`push`, `status`, `check_suite`, `pull_request/*`, etc.) looks up and mutates the `Stack` belonging to `OrgY/some-tracked-repo` because it only reads `repository.full_name`. There is no code path anywhere between `verify_signature` and the handlers that checks `repository.full_name`'s owner segment matches the organization whose secret validated the request.

### Impact Explanation
This allows an attacker who administers one tenant/organization's own legitimate GitHub App installation on a shared Shipit instance to forge arbitrary webhook events (push, status, check_suite, pull_request open/close/label/merge, membership, etc.) against a different organization's tracked repositories/stacks, without ever having installed anything on that other organization. Depending on handler, this can:
- Fabricate `push` events causing `GithubSyncJob` to fetch and append fake commits / trigger continuous deployment for a repo the attacker doesn't own.
- Fabricate `status`/`check_suite` events to unblock CI gating and enable an unauthorized deploy on another org's stack.
- Fabricate `pull_request` events to open/close/merge review-stack provisioning flows on another org's repository.

This is a cross-organization/cross-repository write achieved purely by an entity that only controls its own (unrelated) organization's webhook credentials — matching the "unauthorized deploy" / "cross-repository writes" Critical impact bucket, since it lets an attacker with no privileges on the victim organization's repository trigger writes and CI/deploy state changes scoped to that repository.

### Likelihood Explanation
Requires: (1) the Shipit instance to be configured with the documented multi-organization GitHub App scheme (`github_organizations` returning more than one entry), and (2) the attacker to be a legitimate administrator/owner of at least one of those organizations' own GitHub App (so they know that org's real `webhook_secret`). Both conditions are explicitly supported/documented deployment configurations, not misconfigurations. No GitHub App private key, no Shipit session, and no privilege on the victim org's repository is required — only knowledge of a *different*, attacker-controlled org's webhook secret, which the attacker legitimately owns. This is a realistic scenario for any Shipit instance shared across multiple tenants/orgs.

### Recommendation
After signature verification succeeds, additionally verify that the organization used to select the webhook secret matches the owner of `repository.full_name` (or `organization.login`) actually referenced in the payload before dispatching to handlers — i.e., bind the verified organization to the repository being mutated. Concretely, in `WebhooksController#verify_signature`/`create`, assert `params.dig('repository','owner','login')&.casecmp?(repository_owner)` and that `repository.full_name.split('/').first` also matches the verified organization, rejecting the request (422) otherwise.

### Proof of Concept
1. Deploy Shipit configured with multi-org GitHub Apps: `OrgAttacker` and `OrgVictim`, both with stacks tracked (`OrgVictim/target-repo` has a Shipit stack).
2. Attacker legitimately owns the GitHub App for `OrgAttacker` and knows its real `webhook_secret`.
3. Attacker crafts a JSON push payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "full_name": "OrgVictim/target-repo",
    "owner": { "login": "OrgAttacker" }
  }
}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(OrgAttacker_webhook_secret, raw_body)` and POSTs to `/webhooks` with `X-Github-Event: push`.
5. `verify_signature` calls `Shipit.github(organization: "OrgAttacker")` (from `repository.owner.login`), verifies successfully since the attacker signed with the real `OrgAttacker` secret.
6. `Shipit::Webhooks::Handlers::PushHandler` (via `Handler#stacks`/`#repository_name`) resolves `repository.full_name` = `"OrgVictim/target-repo"` and processes the fabricated push against `OrgVictim`'s stack, enqueuing `GithubSyncJob` for a repository the attacker has no access to.

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
