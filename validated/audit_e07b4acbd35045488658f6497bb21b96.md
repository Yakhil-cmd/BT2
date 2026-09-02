## Confirmed vulnerability

### Title
Webhook signature verification selects the GitHub-App secret from unauthenticated payload data, letting an attacker choose which organization "authenticates" a webhook whose repository target comes from a different, uncorrelated field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks the HMAC secret to validate an incoming webhook against by reading `repository_owner` straight out of the *unverified* JSON body, then uses that same unverified body's `repository.full_name` to decide which `Repository`/`Stack` the event actually acts on. Nothing binds these two fields together, and nothing binds the chosen organization's secret to the repository ultimately mutated. This mirrors the M-2 pattern: one piece of logic authenticates against field A while the state-changing logic operates on unrelated field B from the same untrusted payload.

### Finding Description
`verify_signature` derives the org used for signature verification purely from payload content: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` looks up per-org config (including `webhook_secret`) and `GitHubApp#verify_webhook_signature` explicitly treats a **blank** `webhook_secret` as "always verified": [3](#0-2) [4](#0-3) 

Meanwhile, the event handlers that actually locate the `Repository`/`Stack` to act on read a completely different field, `repository.full_name`, with no cross-check against `repository.owner.login`/`organization.login` used above: [5](#0-4) 

In a multi-organization Shipit deployment (`Shipit.github(organization: ...)` per-org config, as documented), if **any** configured organization has `webhook_secret` unset/blank (a supported, documented configuration - `webhook_secret:` with no value in `config/secrets.development.example.yml`), an attacker can submit a forged POST to `/webhooks` with `repository.owner.login` (or `organization.login`) set to that unsecured org, while setting `repository.full_name` to `"<target-org>/<target-repo>"` for a completely different, secured organization's repository. `verify_signature` will succeed (because the *unsecured* org's blank secret short-circuits verification to `true`), yet the handler (`push_handler`, `status_handler`, etc.) processes the event against the **target** repository/stack, whose secret was never checked at all.

### Impact Explanation
This breaks the deployment-trust binding "an organization that authenticated versus the repository that is written." Depending on which webhook handler is exploited this can:
- Inject forged `push` events (`GithubSyncJob`) or forged commit `status` events against a fully-secured stack the attacker has no legitimate relationship with, poisoning CI/deployability state used to gate deploys (`Commit#deployable?`), potentially enabling an unauthorized deploy.
- Forge `pull_request`/`check_suite` events processed by handlers that act on the target repo's stacks/merge queue.

This satisfies the "unauthorized deploy/merge" tier of High/Critical impact, since it lets an attacker manipulate a target stack's CI/deploy-gating state without ever possessing that target organization's webhook secret.

### Likelihood Explanation
Requires: (1) a Shipit instance configured with multiple GitHub organizations (a documented, supported feature) where at least one configured org has no `webhook_secret` set - a configuration explicitly shown as valid/example in `config/secrets.development.example.yml` (`webhook_secret: # nil`), and (2) the target org's identifying data (owner login, full repo name) is guessable/known (it typically is, being public in GitHub). No GitHub App private key, no session, no ApiClient token, and no knowledge of the target org's real webhook secret is required — only network access to the public `/webhooks` endpoint.

### Recommendation
Do not derive the verification secret from unauthenticated request body content that is also used to select the target repository/stack. Bind the two: verify the signature using the secret associated with the *same* repository being acted on (e.g. resolve the target `Repository` first, then verify with that repository's org secret, rejecting when they differ), and treat a blank/misconfigured `webhook_secret` as "reject" rather than "always verify" for any organization that owns registered stacks, or require exact equality between `repository.owner.login`/`organization.login` and the owner encoded in `repository.full_name` before dispatching to handlers.

### Proof of Concept
1. Configure Shipit (per README/docs) with two orgs: `unsecured-org` (no `webhook_secret`) and `victim-org` (has stacks, `webhook_secret` set, real).
2. POST to `/webhooks` with headers `X-Github-Event: push`, `X-Hub-Signature: sha1=anything` (or omitted) and body:
```json
{
  "repository": { "owner": { "login": "unsecured-org" }, "full_name": "victim-org/victim-repo" },
  "after": "<attacker-chosen sha>",
  "ref": "refs/heads/main"
}
```
3. `verify_signature` resolves `Shipit.github(organization: "unsecured-org")`; because its `webhook_secret` is blank, `verify_webhook_signature` returns `true` unconditionally (`lib/shipit/github_app.rb:76-77`), regardless of the bogus `X-Hub-Signature`.
4. `create` then dispatches to `PushHandler`, whose `repository_name` (`handler.rb:36-38`) reads `victim-org/victim-repo` from the same payload and enqueues `GithubSyncJob`/updates commit state for `victim-org`'s real stacks — despite `victim-org`'s webhook secret never having been checked.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```
