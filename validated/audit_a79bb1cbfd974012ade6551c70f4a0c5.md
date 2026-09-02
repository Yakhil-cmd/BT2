### Title
Webhook signature verification keyed on `repository.owner.login` while every event handler acts on `repository.full_name` - unauthorized cross-repository writes in multi-org deployments - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
This maps to the "verify one field, act on another" bug class from the report: `PositionAction4626::_onIncreaseLever` approved/deposited to `address(this)` but the caller later acted on the position's proxy address, breaking the equality between the address that was authorized and the address that was actually used. In this engine, `WebhooksController#verify_signature` authenticates the inbound webhook against the `GitHubApp` config selected by `repository_owner` (derived from `payload.dig('repository','owner','login')`), while every `Webhooks::Handlers::Handler` subclass resolves which `Repository`/`Stack` to mutate using `repository_name` (`payload.dig('repository','full_name')`). These are two different, independently attacker-controlled fields inside the same unauthenticated JSON body. In a multi-organization Shipit deployment (`Shipit.github_organizations`/`github_app_config`), an attacker who legitimately owns one configured GitHub organization (and therefore knows that organization's `webhook_secret`) can sign a payload with their own secret while setting `repository.full_name` to a *different*, victim organization's repository.

### Finding Description
`WebhooksController` runs `verify_signature` as a `before_action`:

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

`Shipit.github(organization:)` looks up per-organization config (`app_id`, `installation_id`, `webhook_secret`, `oauth`, ...) via `github_app_config(organization)`, which is populated from `secrets.github` keyed by organization name, supporting multiple GitHub orgs on one Shipit instance:

```ruby
def github(organization: github_default_organization)
  if github_default_organization.nil?
    config = secrets.github
  else
    config = github_app_config(organization)
    raise GithubOrganizationUnknown, organization if config.nil?
  end
  @github ||= {}
  @github[organization] ||= GitHubApp.new(organization, config)
end
``` [3](#0-2) 

`GitHubApp#verify_webhook_signature` only checks the HMAC against *that org's* `webhook_secret`:

```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  algorithm, signature = signature.split("=", 2)
  return false unless algorithm == 'sha1'
  SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
end
``` [4](#0-3) 

Once signature verification passes, `Webhooks.for_event(event).each { |handler| handler.call(params) }` is invoked with the entire raw JSON body, and every handler's base class resolves the target repository/stack purely from `repository.full_name`, never re-checking `repository.owner.login` against the org whose secret validated the request:

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [5](#0-4) 

Push handling (`GithubSyncJob`), status/check-run handling, PR-merge handling, etc. all inherit this pattern - the field that is cryptographically bound to the request (`repository.owner.login`, used to select the verifying secret) is disjoint from the field that determines which `Stack`/`Repository` record is mutated (`repository.full_name`). This is the same class of defect as the ERC4626 report: the verified/authorized identity (organization whose secret matched) is not equal to the identity actually acted upon (repository resolved from `full_name`).

Binding broken (equality that should hold but doesn't):
`organization_whose_secret_verified_signature == owner_of(repository_full_name_used_by_handler)`
Before the fix, these can diverge whenever an attacker controls a first organization's secret but sets `full_name` to point at a second organization's tracked repository.

### Impact Explanation
If exploitable, this allows an attacker who controls (or is a legitimate customer of) one GitHub organization configured on a shared/multi-tenant Shipit instance to forge webhook events (`push`, `status`, `check_suite`, `pull_request`, `merge_group`, etc.) that are attributed to a *different* organization's repository/stack that they do not own. Depending on which handler fires, this can trigger unauthorized state changes on a victim's `Stack` — e.g. `GithubSyncJob` enqueued for the victim stack ID, forged commit `Status`/`CheckRun` records that influence `deployable?`/CI-gating decisions used by `Deploy` creation, or PR merge-queue state transitions (`MergeRequest`) for a repository the attacker doesn't own — all without needing that victim organization's `webhook_secret`, `ApiClient` token, or Shipit session. This is a cross-organization write via a confused-deputy signature check, matching the "Critical — cross-repository writes" impact tier.

### Likelihood Explanation
Exploitability strictly requires a **multi-organization Shipit deployment** (`github_default_organization` non-nil, i.e. `secrets.github` keyed by multiple org names) where the attacker is a legitimate tenant/customer of at least one configured organization and therefore knows that organization's `webhook_secret` — no theft of GitHub App credentials, no TLS interception, and no privileged Shipit account is required, only knowledge of a secret the attacker is entitled to hold for their own org. In the common single-organization deployment (the default/example config in `config/secrets.development.example.yml`), `github_default_organization` is `nil` and there is only one shared secret, so this specific cross-org confusion is not reachable — likelihood is therefore contingent on the multi-org feature being used, which the codebase explicitly supports and documents (`TOP_LEVEL_GH_KEYS`, `github_app_config`, `github_organizations`).

### Recommendation
After verifying the signature with the organization-specific secret, re-validate that `payload.dig('repository','owner','login')` (or `organization.login`) matches the owner encoded in `payload.dig('repository','full_name')` before dispatching to handlers, and reject (422) on mismatch. Alternatively, have `Webhooks::Handlers::Handler#repository_name`/`#stacks` scope lookups to `Repository` rows that belong to the same organization that was cryptographically verified in `WebhooksController`, rather than trusting an independent `full_name` field from the unauthenticated payload body.

### Proof of Concept
Conceptual PoC (requires a multi-org Shipit config with orgs `attacker-org` and `victim-org`, both onboarded as tenants):
1. Attacker knows `webhook_secret` configured for `attacker-org` (they legitimately administer that org's GitHub App).
2. Attacker crafts a `push` payload:
```json
{
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  },
  "after": "<attacker-chosen-sha>"
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC_SHA1(attacker-org-secret, raw_body)`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "attacker-org")` and successfully verifies the signature against the attacker's own known secret.
5. `Shipit::Webhooks.for_event('push').each { |handler| handler.call(params) }` runs the push handler, which resolves the target via `Repository.from_github_repo_name("victim-org/victim-repo")` and enqueues `GithubSyncJob` (or updates commit status/check runs) for the victim's `Stack`, despite the request never being signed by `victim-org`'s secret.

Note: I could not execute this against a running multi-org instance from the index; the analysis above is based on static code review of `WebhooksController`, `GitHubApp#verify_webhook_signature`, `Shipit.github_app_config`, and `Webhooks::Handlers::Handler`. Confirming the exact downstream effects per handler (push, status, check_suite, pull_request) would require running the flow in a real multi-org test environment, which is best done in a full Devin session with repository access.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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
