### Title
Webhook signature verification keyed by `repository.owner.login` is not bound to the `repository.full_name` actually acted on, allowing cross-organization webhook forgery when any configured org has no `webhook_secret` - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization config (and its `webhook_secret`) to validate an inbound webhook against using `repository_owner`, which is read directly from the attacker-controlled JSON body (`params.dig('repository', 'owner', 'login')`). All downstream handlers, however, resolve the actual `Repository`/`Stack` to mutate using a *different* field from the same body, `repository.full_name` (via `Handler#repository_name`). Because Shipit supports multiple GitHub organizations each with their own optional `webhook_secret`, and signature verification trivially passes when a target org has no secret configured, nothing binds "the org whose secret validated this request" to "the repository whose state gets changed."

### Finding Description
In `app/controllers/shipit/webhooks_controller.rb`, `verify_signature` does: [1](#0-0) 
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
``` [2](#0-1) 

`repository_owner` is fully attacker-controlled JSON from the request body itself, so the org whose secret is used for HMAC verification is chosen by the attacker.

`GitHubApp#verify_webhook_signature` treats a missing secret as automatically verified: [3](#0-2) 
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
```

Shipit is explicitly multi-org: `Shipit.github(organization:)` maps org name to independently configured `webhook_secret` values, per `lib/shipit.rb`'s `github_app_config`/`TOP_LEVEL_GH_KEYS` handling, and the setup docs state the webhook secret is optional per app: [4](#0-3) [5](#0-4) 

Meanwhile, every webhook handler (`Handler#repository_name`, used by `PushHandler`, `StatusHandler`'s underlying `stacks`, `CheckSuiteHandler`, pull-request handlers, etc.) resolves the target `Repository`/`Stack` from `payload.dig('repository', 'full_name')`: [6](#0-5) 

`repository.owner.login` (used to pick the verifying secret) and `repository.full_name` (used to pick the acted-upon repository) are two independent fields inside the same unsigned-until-the-fact JSON body; nothing enforces they are consistent, and the raw-body HMAC only proves the *bytes* came from a holder of *some* org's secret — it says nothing about which org's repositories that payload is entitled to reference.

The binding that should hold is: `org whose webhook_secret validated the request == owner of the repository whose Stack/Commit/Team state is mutated`. This binding is not enforced anywhere in the controller or handler pipeline.

### Impact Explanation
If a Shipit deployment is configured with multiple GitHub organizations (a supported, documented configuration) and at least one of those organizations has no `webhook_secret` set (explicitly documented as optional), an attacker can craft a webhook payload with `repository.owner.login` set to the org lacking a secret (or `organization.login` for membership events) so that `verify_webhook_signature` short-circuits to `true`, while setting `repository.full_name` to a repository belonging to a *different*, secured organization/stack. The request passes signature verification entirely, and the handler then acts on the victim repository's `Stack`/`Commit` data — e.g. triggering `GithubSyncJob` (push), writing fabricated commit `Status` records that gate deploy eligibility (status), or scheduling check-run refreshes (check_suite) for a stack the attacker does not control. This is a cross-repository/cross-tenant write triggered by an unauthenticated actor exploiting a trust binding that the app itself sets up (per-org secrets) but never actually enforces between the field used for authentication and the field used for action.

### Likelihood Explanation
Requires a deployment with more than one configured GitHub org where at least one has no `webhook_secret` (a documented, optional setting) — a realistic operator misconfiguration rather than a code defect that always fires, but the underlying design gap (verification field ≠ action field) exists regardless of configuration and only needs one weak org to become exploitable.

### Recommendation
After successful signature verification, re-derive/validate the acted-upon repository's owner against the same `repository_owner` (or the App/org whose secret validated the request) before dispatching to handlers, and reject the webhook (422) if `repository.full_name`'s owner segment does not match the verified organization. Additionally, treat a missing per-org `webhook_secret` as a hard misconfiguration (fail closed, e.g. reject or loudly warn) rather than silently returning `true` from `verify_webhook_signature`.

### Proof of Concept
1. Deploy Shipit with two orgs configured in `secrets.github`: `attacker-org` (no `webhook_secret` set) and `victim-org` (has a stack, e.g. `victim-org/prod-app`, with `webhook_secret` set).
2. POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha already present as a commit on the victim stack>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/prod-app"
  }
}
```
No `X-Hub-Signature` header is required to match anything real, since `Shipit.github(organization: "attacker-org")` has no `webhook_secret`, causing `verify_webhook_signature` to return `true` unconditionally per `lib/shipit/github_app.rb:76-83`.
3. `WebhooksController#create` proceeds and dispatches to `Shipit::Webhooks.for_event('push')`, invoking `PushHandler`, whose `stacks` method resolves `Repository.from_github_repo_name("victim-org/prod-app")` (via `Handler#repository_name`) and enqueues `GithubSyncJob`/deploy-relevant state changes for the victim stack, despite the request never being validated with `victim-org`'s secret.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

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

**File:** docs/setup.md (L20-30)
```markdown
## Creating the GitHub App

Shipit needs a GitHub App to authenticate users, receive Webhooks and access the API.

You can create a new one for your organization at `https://github.com/organizations/<your-org>/settings/apps/new`, or [https://github.com/settings/apps/new](https://github.com/settings/apps/new) for a regular user.

  - Homepage URL: The URL where Shipit will be deployed, e.g. `https://example.com`.
  - User authorization callback URL: It must be set to `<homepage>/github/auth/github/callback`, e.g. `https://example.com/github/auth/github/callback`.
  - Setup URL: Leave it empty.
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
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
