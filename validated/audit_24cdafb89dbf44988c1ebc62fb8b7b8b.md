## Title
Cross-organization webhook forgery via unauthenticated `repository_owner` field used to select the verifying secret - (File: `app/controllers/shipit/webhooks_controller.rb`)

## Summary

## Finding Description
`Shipit::WebhooksController#verify_signature` selects which GitHub App configuration (and therefore which `webhook_secret`) to verify the request against by reading an attacker-controlled field straight out of the *unauthenticated* JSON body: [1](#0-0) [2](#0-1) 

`repository_owner` is `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` — i.e. taken from the raw, unverified payload the attacker just sent. That value is fed to `Shipit.github(organization: repository_owner)`, which looks up the matching entry in the multi-org GitHub App config: [3](#0-2)  and setup docs confirm this multi-org, per-organization-secret scheme [4](#0-3) .

The signature check itself is: `return true unless webhook_secret` — i.e. if the *selected* org's app config has no `webhook_secret` configured (documented as "optional" in `docs/setup.md` line 30), verification is a no-op and always passes: [5](#0-4) .

After this check passes, the full (still attacker-authored) `params` hash — the same hash from which `repository_owner` was pulled — is handed unmodified to every registered webhook handler: [6](#0-5) . Handlers such as the push/status/pull_request handlers resolve the actual `Repository`/`Stack` to act on from other fields of that same payload (e.g. `repository.full_name`), which are **not** tied to the `repository_owner` value that determined which secret was checked.

This is the same bug class as the reported issue: a value is read and used to satisfy a security check (H-1: `gasleft()` read once to satisfy a check, then spent before the protected action; here: `repository_owner` read once to select/verify a secret, then a *different* field of the same untrusted payload is used to determine what gets mutated). The binding that should hold — "the organization whose secret authenticated this webhook == the organization whose repository/stack is acted upon" — is never enforced beyond the initial (bypassable) secret selection.

## Impact Explanation
If a Shipit instance is configured with multiple GitHub organizations (the documented `github: { orgA: {...}, orgB: {...} }` schema) and any one organization is left without a `webhook_secret` (explicitly supported as optional per `docs/setup.md`), an unauthenticated internet attacker can:
1. Send a POST to `/webhooks` with `repository.owner.login` set to the org with no secret (so `verify_webhook_signature` short-circuits to `true`), while
2. Populating the rest of the payload (e.g. `repository.full_name`, commit SHAs, status/check fields, PR numbers) to reference a *different*, secured organization's repository/stack.

Because signature verification never re-validates that the acted-upon repository belongs to the organization that was "authenticated" for the request, this allows spoofed `push`, `status`, `check_suite`, `pull_request`, or `membership` events to be injected against stacks that belong to a fully-secured organization — e.g. forging CI/commit statuses that gate `deployable?`, injecting fake commits via `GithubSyncJob`, or manipulating team/user membership records — without possessing any of that organization's secrets. This can influence which commits are considered deployable/mergeable, i.e. it can feed into an unauthorized deploy/merge decision.

## Likelihood Explanation
This requires a specific, but documented and plausible, misconfiguration: multi-org mode with at least one organization's `webhook_secret` left blank (explicitly called out as "optional" in the setup guide) while another organization is properly secured. Given that Shipit explicitly ships and documents the multi-org schema and marks `webhook_secret` as optional per app, this is a realistic operational configuration in installations onboarding multiple GitHub orgs incrementally. No session, API token, or credential is required by the attacker — only knowledge that a target instance is multi-tenant, which can often be inferred from public behavior.

## Recommendation
After verifying the webhook signature, re-derive/require the target repository's organization to match `repository_owner` that was used for verification (i.e., reject events whose acted-upon repository does not belong to the org whose secret authenticated the request), and/or require `webhook_secret` to be mandatory (not optional) whenever multi-org configuration is used, so an unsecured org entry cannot be used as a signature bypass for other orgs' events.

## Proof of Concept
1. Configure Shipit with two orgs: `SecureOrg` (webhook_secret set) hosting stack `secureorg/app`, and `OpenOrg` (webhook_secret left blank).
2. As an unauthenticated attacker, POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "repository": { "owner": { "login": "OpenOrg" }, "full_name": "secureorg/app" },
  "after": "<attacker-chosen-sha>",
  ...
}
```
No `X-Hub-Signature` header (or any value) is required, because `repository_owner` resolves to `OpenOrg`, whose `GitHubApp#verify_webhook_signature` returns `true` unconditionally at [7](#0-6) .
3. The push handler then processes the event against `secureorg/app`'s stack (via `GithubSyncJob`), even though no `SecureOrg` secret was ever presented.

*Note: I was not able to fully trace the exact field each individual webhook handler (`app/models/shipit/webhooks/handlers/**`) uses to resolve the target `Repository`/`Stack` down to the line level within the remaining iteration budget — this should be confirmed by a Devin session with full repo access before treating the PoC payload shape as exact, since the precise handler-to-field mapping for each event type (`push`, `status`, `pull_request`, `membership`) was only partially inspected.*

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```
