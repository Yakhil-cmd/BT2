### Title
Webhook signature verification is bound to `repository.owner.login` while event handlers act on `repository.full_name`, allowing an unsigned/mis-keyed payload to be routed to a different organization's stacks - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and therefore which `webhook_secret`) to validate the incoming payload against based on an **unverified** field of the payload itself (`repository.owner.login`, falling back to `organization.login`), not based on the organization that the event handlers subsequently act on (`repository.full_name`). This mirrors the analog bug class in the report: a value used to decide "is this safe" is derived from data that is not itself covered/consistent with what is actually consumed afterwards, and the caller does not validate that the two agree.

### Finding Description
`repository_owner` is computed purely from the JSON body, before any signature check has occurred: [1](#0-0) 

That value is used to pick the `GitHubApp` instance (and thus the `webhook_secret` used for HMAC comparison) that will validate the request: [2](#0-1) 

`Shipit.github` resolves per-organization config via `github_app_config(organization)`, confirming Shipit explicitly supports multiple GitHub organizations each with their own (optionally empty) `webhook_secret`: [3](#0-2) 

Crucially, `GitHubApp#verify_webhook_signature` treats a missing `webhook_secret` as automatically valid: [4](#0-3) 

and the docs explicitly describe `webhook_secret` as **optional**: [5](#0-4) 

Meanwhile, once past `verify_signature`, the `create` action dispatches the same raw body to handlers keyed off `event`, and those handlers resolve the target `Stack` from `repository.full_name` in the payload rather than from `repository_owner`: [6](#0-5) 

Because `repository_owner` (used only to pick which secret validates the signature) and `repository.full_name` (used to select which `Stack` is mutated) are two independently attacker-controlled fields in the same unsigned JSON body, an attacker can set `repository.owner.login` to an organization configured in the same Shipit instance with **no `webhook_secret`** set (or one whose secret has leaked/is weak), while setting `repository.full_name` to `victim-org/victim-repo`. `verify_webhook_signature` then returns `true` unconditionally for the no-secret organization, and the request is forwarded to `create`, where handlers act on the victim's stack using the attacker's fabricated `push`/`status`/`check_suite` payload.

This breaks the binding the rules call out explicitly: *"an organization that authenticated versus the repository that is written."* The organization whose credentials "authenticated" the webhook (the no-secret org) is not the same as the repository/stack that ends up being written to.

### Impact Explanation
If any organization configured on a multi-org Shipit deployment lacks a `webhook_secret` (an explicitly supported, documented "optional" configuration), an unauthenticated external attacker can forge webhook events (`push`, `status`, `check_suite`) that are accepted and dispatched against **any other organization's stacks** hosted on the same instance, without needing that organization's secret at all. Depending on which handler is exercised, this can trigger unintended `GithubSyncJob` runs, forged commit `status`, or check-run driven stack transitions — i.e., an unauthorized action on a stack that the attacker does not control, crossing a repository/organization trust boundary.

### Likelihood Explanation
This requires: (1) a multi-organization Shipit deployment, and (2) at least one configured organization without a `webhook_secret`. Both conditions are explicitly supported and documented as normal/optional configuration, not hardening failures, making this reachable by design in any installation that doesn't uniformly enforce secrets across all configured orgs, without requiring any credential, session, or prior access.

### Recommendation
Do not derive the organization used for signature validation from unverified payload content that differs from the field(s) actually consumed by the event handlers. At minimum: require `webhook_secret` to be present for every configured organization (fail closed instead of `return true unless webhook_secret`), and cross-check that the organization implied by `repository.full_name` (the value handlers act on) matches the organization whose secret validated the signature before dispatching to handlers.

### Proof of Concept
1. Configure Shipit with two GitHub orgs: `victim-org` (has `webhook_secret` set, hosts a real stack) and `attacker-org` (no `webhook_secret` configured, e.g., left blank per docs).
2. POST to `/webhooks` with header `X-Github-Event: push`, no valid `X-Hub-Signature` for `victim-org`, and a JSON body:
```json
{
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" },
  "after": "<attacker-chosen sha>",
  "ref": "refs/heads/master"
}
```
3. `repository_owner` resolves to `attacker-org` → `Shipit.github(organization: "attacker-org")` → `verify_webhook_signature` returns `true` (no secret configured) regardless of the actual signature header.
4. `create` proceeds and dispatches the push handler, which looks up the stack via `repository.full_name = "victim-org/victim-repo"`, causing `GithubSyncJob` to run against `victim-org`'s real stack using attacker-supplied data — without ever presenting `victim-org`'s webhook secret.

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

**File:** docs/setup.md (L30-30)
```markdown
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
```
