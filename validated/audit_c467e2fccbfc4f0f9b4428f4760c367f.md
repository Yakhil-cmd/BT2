### Title
Webhook signature verification selects the HMAC secret from an unverified payload field, decoupling the authenticated organization from the repository the event handlers write to - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In `WebhooksController#verify_signature`, the organization whose `webhook_secret` is used to validate the HMAC signature is derived from a field inside the very payload being verified (`repository.owner.login` / `organization.login`), not from any independently authenticated source. The event handlers that are subsequently invoked act on a different, independently-controlled field of the same payload (the repository/stack identified elsewhere in `params`). Because both fields live in the same attacker-supplied JSON body, and the signature only proves "this exact byte string was signed with *some* configured org's secret," an actor who legitimately possesses one org's `webhook_secret` (their own integration's secret) can craft a payload whose `repository.owner.login` matches their own org (so verification passes) while other payload fields reference a different organization's repository, causing the handlers to act on a resource outside the boundary the signature was supposed to authenticate.

### Finding Description
`WebhooksController#verify_signature` selects the GitHub App/organization used for verification straight from the untrusted payload:

<cite repo="Ellentat/shipit-engine--022" path="app/controllers/shipit/webhooks_controller.rb" start="24="/> [1](#0-0) [2](#0-1) 

`repository_owner` is read via `params.dig('repository', 'owner', 'login')` before the signature has been checked, and is used only to pick *which* app's secret to HMAC-verify with — not to constrain which repository the handlers may subsequently mutate: [3](#0-2) 

The secret lookup itself is multi-tenant aware: `Shipit.github(organization:)` resolves a distinct `GitHubApp` (and thus a distinct `webhook_secret`) per organization key configured under `secrets.github`: [4](#0-3) 

`verify_webhook_signature` only proves that the exact raw request body was HMAC-signed with *that resolved organization's* secret: [5](#0-4) 

This reproduces the analog of the `addInterest()` bug: instead of binding the trust decision to state that is authoritative and independent of the caller's input, the code derives "which authority verified this" from a value the caller fully controls and that is not cross-checked against the value the rest of the request pipeline actually acts on. The equality that should hold is:

`organization whose secret validated the signature == organization/repository the dispatched handler mutates`

but nothing enforces this — `repository_owner` (used only for secret selection) and the repository object consumed by `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` are two independent reads of the same attacker-supplied JSON, with no consistency check between them.

### Impact Explanation
In a multi-organization Shipit deployment (the `github_app_config`/`github_organizations` schema this engine explicitly supports), an actor who legitimately owns a `webhook_secret` for one configured organization can compute a valid signature over a payload whose `repository.owner.login` matches their own org (passing `verify_signature`) while other payload fields reference a different organization's tracked repository. Since the HTTP endpoint is unauthenticated aside from this signature check, this breaks the organization-isolation trust boundary and lets a customer/tenant of one org drive `GithubSyncJob`, commit statuses, or membership/team writes against another organization's Stack — a cross-repository/cross-tenant write, matching the Critical impact category for cross-repository writes.

### Likelihood Explanation
Requires the attacker to already control (i.e., know) the `webhook_secret` for at least one organization configured in the same Shipit instance — this is knowledge of their own legitimately-provisioned integration secret, not a privileged Shipit credential, GitHub App key, or session. In any multi-tenant Shipit deployment this is a realistic, low-barrier precondition, making likelihood High for that deployment shape, though it does not apply to single-organization deployments where only one secret exists (there attacker and victim collapse into the same signer).

### Recommendation
Do not derive the organization used to select the verification secret purely from an unverified payload field consumed again later for repository resolution. After signature verification succeeds, re-derive the repository/organization used by the dispatched handlers from the same trusted `repository_owner` value that passed verification (or verify that all organization-identifying fields in the payload are mutually consistent) before invoking `Shipit::Webhooks.for_event(event)` handlers, so the authenticated organization and the organization/repository actually written to are provably the same entity.

### Proof of Concept
1. Deploy Shipit with two organizations configured, `orgA` and `orgB`, each with its own `webhook_secret` under `secrets.github` (per `lib/shipit.rb#github_app_config`).
2. As an operator/holder of `orgA`'s webhook secret, craft a JSON body for a `push` event where `repository.owner.login = "orgA"` (so `repository_owner` resolves to orgA and `verify_signature` succeeds) but other repository-identifying data referenced by the dispatched handler corresponds to a Stack tracked under `orgB`.
3. Compute `X-Hub-Signature: sha1=<hmac(orgA_secret, raw_body)>` and POST to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` passes because it only checked that the byte string was signed by orgA's known secret; `Shipit::Webhooks.for_event('push').each { |handler| handler.call(params) }` then processes the payload against the `orgB`-owned Stack, since nothing enforces that the entity the signature authenticated is the entity being mutated.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-16)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end

```

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
