### Title
Cross-organization repository binding bypass via unauthenticated `repository.owner.login` / `repository.full_name` mismatch in webhook processing - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App / webhook secret to authenticate a webhook against using `repository_owner`, a value parsed from the untrusted JSON body itself. `Webhooks::Handlers::Handler#stacks` (used by `PushHandler` and others) independently parses `payload.dig('repository', 'full_name')` from the same body to decide *which stack the event acts on*. Because these two fields are read independently and never cross-validated, an attacker can satisfy signature verification under one (weakly configured) organization while making the handler act on a repository/stack belonging to a completely different organization.

### Finding Description
`WebhooksController#verify_signature` derives the authenticating organization purely from attacker-controlled JSON: [1](#0-0) [2](#0-1) 

It then fetches `Shipit.github(organization: repository_owner)` and calls `verify_webhook_signature`, which for any organization configured without a `webhook_secret` (documented as *optional* in `docs/setup.md`) unconditionally returns `true`: [3](#0-2) 

Once the request passes this check, `WebhooksController#create` dispatches the *same raw JSON body* to event handlers: [4](#0-3) 

`Handlers::Handler#stacks`/`#repository_name`, used by `PushHandler`, resolves the target repository from a *different* field of the same body — `repository.full_name` — with no requirement that its owner match the `repository.owner.login` value that was used to select the signing organization during `verify_signature`: [5](#0-4) [6](#0-5) 

Multi-organization configuration is an explicitly supported, documented deployment mode: each organization gets its own GitHub App, `webhook_secret`, and installation: [7](#0-6) [8](#0-7) 

The binding that should hold is: `organization authenticated by verify_signature == organization owning the repository the handler mutates`. Because `repository_owner` (used for signature org selection) and `repository.full_name` (used for stack resolution) are two independently-trusted fields inside the same unauthenticated payload, this equality is never enforced, so the binding can be broken by simply setting them to different values.

`Webhooks::Handlers::StatusHandler` demonstrates an even more direct version of the same root cause — the commit status update path performs no repository scoping at all, matching purely on `sha` across the whole install: [9](#0-8) 

### Impact Explanation
In a multi-org Shipit install, if any one configured organization has `webhook_secret` left blank (an explicitly documented, supported configuration), an unauthenticated attacker can forge a `push` webhook whose `repository.owner.login` names that weakly-configured org (making `verify_signature` pass unconditionally) while `repository.full_name` names an arbitrary stack belonging to a *different*, properly-secured organization. `PushHandler#process` will then act on that victim stack — enqueueing `GithubSyncJob`/`sync_github` for a repository whose owning organization's GitHub App credentials were never used to authenticate the request. This is a cross-organization write triggered without any credential belonging to the targeted organization, matching the Critical "cross-repository writes" / "unauthorized deploy" category, since synced commits can drive continuous deployment and downstream automated ship actions for the victim org's stack.

### Likelihood Explanation
Requires no authentication, no `ApiClient` token, and no repository access — only that the Shipit instance is configured with more than one GitHub organization and at least one of them has no `webhook_secret` set (a state the project's own setup docs present as normal/optional). Given that many self-hosted installs run personal/test orgs alongside production orgs, this misconfiguration is plausible, and the request itself is a trivial crafted HTTP POST to `/webhooks`.

### Recommendation
Enforce that the organization used to select/verify the webhook signature is the *same* organization implied by every repository-bearing field the handlers subsequently trust (e.g., derive `repository_owner` once, verify the signature, and then require `payload.dig('repository','full_name')` to start with `"#{repository_owner}/"` before dispatching to handlers). Additionally, require `webhook_secret` to be present for every configured organization, and scope `StatusHandler`'s `Commit.where(sha:)` lookup by the same verified repository/owner.

### Proof of Concept
Given `config/secrets.yml`:
```yaml
production:
  github:
    OrgWeak:
      app_id: 1
      installation_id: 1
      webhook_secret:        # left blank, per docs "optional"
      private_key: ...
    OrgVictim:
      app_id: 2
      installation_id: 2
      webhook_secret: "s3cr3t"
      private_key: ...
```

Attacker (no credentials) sends:
```
POST /webhooks
X-Github-Event: push
Content-Type: application/json
(no valid X-Hub-Signature needed)

{
  "repository": {
    "owner": { "login": "OrgWeak" },
    "full_name": "OrgVictim/victim-repo"
  },
  "ref": "refs/heads/master",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
}
```
- `WebhooksController#verify_signature` resolves `repository_owner` = `"OrgWeak"`, loads `Shipit.github(organization: "OrgWeak")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally.
- `PushHandler#stacks` resolves `repository_name` from `payload.dig('repository','full_name')` = `"OrgVictim/victim-repo"`, finds the victim's `Stack`, and calls `stack.sync_github(expected_head_sha: "deadbeef...")`, acting on `OrgVictim`'s repository despite that organization's GitHub App/webhook secret never having authenticated the request.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
