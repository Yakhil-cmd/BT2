### Title
Webhook signature-verification uses attacker-controlled `repository.owner.login`/`organization.login` to select the HMAC secret, while the acted-upon repository is a different field never covered by that check - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and therefore which `webhook_secret`) to use for HMAC verification based on `repository_owner`, a value read directly out of the untrusted, not-yet-verified JSON body [1](#0-0) . This mirrors the MT-token root cause: a value that drives a security-critical computation (which secret/whose "share" applies) is taken from attacker-supplied data instead of being bound to the thing the check is supposed to protect (the actual target repository/stack that downstream handlers will act on).

### Finding Description
`verify_signature` does:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [2](#0-1) 

`Shipit.github(organization:)` looks up a per-organization config (`app_id`, `installation_id`, `webhook_secret`) in the multi-org secrets schema [3](#0-2) . Critically, `GitHubApp#verify_webhook_signature` unconditionally returns `true` when that org's `webhook_secret` is blank/nil: `return true unless webhook_secret` [4](#0-3) .

In a multi-organization deployment (the documented `secrets.yml` schema supports several orgs each with their own `webhook_secret`, see `config/secrets.development.shopify.yml` and `docs/setup.md`), it is entirely possible—and shown as valid in the fixtures/tests themselves (`webhook_secret: # nil` appears in every sample secrets file)—for some configured organizations to have no `webhook_secret` set while others do. Because `repository_owner` is read from the payload body before the signature is validated, an attacker can submit a forged webhook whose `repository.owner.login` (or top-level `organization.login`) names an org with no configured `webhook_secret`, causing `verify_webhook_signature` to short-circuit to `true` regardless of the actual `X-Hub-Signature` header. The `create` action then dispatches the full, attacker-controlled `params` blob to every registered handler for the event (`Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [5](#0-4) ), and those handlers act on stack/repository lookups keyed by whatever fields (e.g. `repository.full_name`, `repository.id`) are present in the same forged payload — fields that were never independently bound to the org whose secret was used (or skipped) for verification.

This breaks the intended equality: **the organization whose secret authenticated the request** must equal **the organization/repository the payload's handlers actually act upon**. Here the field used to pick the verification secret (`repository.owner.login`) and the field used by handlers to resolve the concrete `Stack`/`Repository` (`repository.full_name`, commit SHAs, PR numbers, team/member data for `membership` events, etc.) are the same untrusted JSON body, decided before any cryptographic check succeeds, and the check can be trivially satisfied by naming a no-secret org.

### Impact Explanation
If any configured GitHub organization in a multi-org Shipit install has no `webhook_secret` (a state the documentation and default secrets templates explicitly allow with `webhook_secret: # nil`), an unauthenticated attacker can forge arbitrary GitHub webhook events (`push`, `status`, `check_suite`, `membership`, `pull_request`, etc.) for **any repository/organization tracked by the instance**, not just the unsecured one — because the payload's other repository-identifying fields are not tied to `repository_owner`. This can trigger `GithubSyncJob` push processing, membership/team mutations, or PR-driven merge-queue state changes for repositories belonging to organizations that *do* have a webhook secret configured, i.e. an authentication-bypass on inbound trust boundary that Shipit relies on to accept GitHub-originated state changes. Depending on which handlers are registered, this can influence merge-queue behavior and deploy readiness — a High severity issue (unauthenticated forgery of stack/task state through the webhook trust boundary).

### Likelihood Explanation
This requires: (1) a multi-organization Shipit deployment, and (2) at least one configured organization without a `webhook_secret`. Both conditions are explicitly supported and even shown as the default/example configuration in this repo (`webhook_secret: # nil` in every sample secrets file: `config/secrets.development.shopify.yml`, `test/dummy/config/secrets_double_github_app.yml`, `docs/setup.md`), making this a realistic misconfiguration rather than a purely theoretical edge case. No credentials, sessions, or GitHub access are required — only knowledge that the target instance uses multi-org config.

### Recommendation
- Do not select the verification secret from unverified payload fields. Verify the signature against every organization's configured secret (or a global one) that could plausibly own the referenced repository, and reject if none match, rather than trusting `repository.owner.login`.
- Do not treat "no secret configured" as an automatic pass; require an explicit administrative opt-in (e.g., only allow unsigned webhooks for organizations that have no linked repositories/stacks, or refuse to route payloads whose `repository.full_name`'s owner differs from `repository_owner`).
- After signature verification, revalidate that all repository-identifying fields used later by handlers belong to the same organization that was authenticated.

### Proof of Concept
1. Deploy Shipit with the documented multi-org secrets schema, configuring `OrgA` with a `webhook_secret` and `OrgB` with `webhook_secret: # nil` (a supported, documented configuration).
2. Send `POST /webhooks` with `X-Github-Event: push` and a JSON body:
```json
{
  "repository": {
    "owner": { "login": "OrgB" },
    "full_name": "OrgA/target-repo"
  },
  "after": "<attacker-chosen-sha>"
}
```
with no valid `X-Hub-Signature` header (or an arbitrary one).
3. `repository_owner` resolves to `"OrgB"` [1](#0-0) , `Shipit.github(organization: "OrgB")` returns the app config with a blank `webhook_secret`, and `verify_webhook_signature` returns `true` unconditionally [6](#0-5) .
4. `create` proceeds to dispatch the push payload — which references `OrgA/target-repo` — to `Shipit::Webhooks.for_event('push')` handlers [5](#0-4) , enqueuing a `GithubSyncJob` for the `OrgA` stack despite never presenting a valid signature for `OrgA`.

Note: I was unable to fully load `app/models/shipit/webhooks/handlers/push_handler.rb` and `handlers/handler.rb` in this session (tool calls did not return content) to cite the exact line that resolves the `Stack`/`Repository` from `repository.full_name` independent of `repository_owner`; this should be confirmed by inspecting those files directly, but the controller-level and `GitHubApp`-level logic establishing the bypass is confirmed above.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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
