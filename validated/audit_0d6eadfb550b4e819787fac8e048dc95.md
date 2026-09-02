### Title
Webhook Signature Verification Bound to `repository.owner.login` While Handlers Act on the Independent `repository.full_name` Field, Enabling Cross-Organization Webhook Spoofing - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and therefore which `webhook_secret`) to verify the inbound `X-Hub-Signature` against by reading `repository.owner.login` (or `organization.login`) out of the unauthenticated JSON body. Every webhook handler, however, resolves the repository/stack the event actually mutates using the independent `repository.full_name` field. Nothing cross-validates that these two attacker-supplied fields describe the same repository. Because `GitHubApp#verify_webhook_signature` treats a blank/unset `webhook_secret` as automatically verified (`return true unless webhook_secret`), an attacker who picks any configured organization that happens to have no `webhook_secret` set can forge a signature-free payload whose `repository.full_name` points at a completely different, properly-secured organization's repository, and have it processed as a legitimate event for that repository's stacks.

### Finding Description
`verify_signature` derives the authentication scope purely from the payload: [1](#0-0) [2](#0-1) [3](#0-2) 

`GitHubApp#verify_webhook_signature` short-circuits to `true` whenever the resolved organization has no configured secret: [4](#0-3) 

Every downstream handler, however, resolves the actual `Repository`/`Stack` acted upon using a *different* field of the same payload, `repository.full_name`, with no cross-check against `repository.owner.login`: [5](#0-4) 

The engine explicitly supports multiple GitHub App configurations keyed by organization, and its own documentation/fixtures show `webhook_secret` legitimately left unset (`# nil`) as a supported configuration state: [6](#0-5) [7](#0-6) 

This breaks the binding: **organization authenticated (`repository.owner.login` → `Shipit.github(organization:)` → secret used for HMAC check) ≠ repository written (`repository.full_name` → `Repository.from_github_repo_name` → `Stack`/`PullRequest`/`Commit` mutated)**. An unauthenticated caller can:
1. Send a POST to `/github/webhooks` with `X-Github-Event` set to any handled event (e.g. `push`, `status`, `pull_request`, `check_suite`, `membership`).
2. Set `repository.owner.login` (or top-level `organization.login`) to the name of *any* organization configured in `secrets.yml` whose `webhook_secret` is blank/unset — this passes `verify_signature` with no valid signature required.
3. Set `repository.full_name` to the `owner/name` of a real, victim stack tracked under a different, properly-secured organization.
4. The handler dispatched via `Shipit::Webhooks.for_event(event)` resolves the target `Repository`/`Stack` strictly from `repository.full_name`, ignoring which organization's secret actually authenticated the request.

### Impact Explanation
This is an authentication bypass on the webhook ingestion path: an unauthenticated network attacker can inject fabricated GitHub events (fake commit statuses/check-runs affecting merge-queue and deploy CI gating via `push`/`status`/`check_suite` handlers, spurious `pull_request` closed/reopened/edited transitions affecting review stacks, or `membership` events creating arbitrary teams/users) against any repository/stack in the system, as long as at least one configured organization in the deployment lacks a `webhook_secret`. Because merge-queue merging (`ProcessMergeRequestsJob`/`MergeRequest#merge!`) and deploy safety gating rely on statuses/check-runs recorded from webhooks, forging these can influence whether pull requests are merged or whether "required" CI signals appear satisfied, which aligns with the High-severity bucket ("escalation... unauthenticated read/write of stack state" analog) defined for this scan.

### Likelihood Explanation
Likelihood is moderate-to-high in any real multi-organization deployment: the project's own setup documentation and test fixtures present `webhook_secret: # nil` as an ordinary, supported configuration value, so operators onboarding a new/staging GitHub organization (or simply not yet having created the App's webhook secret) will commonly have at least one organization without a secret. No credentials, tokens, or prior access are required — only knowledge of one configured organization name lacking a secret and the target repository's `owner/name`, both of which are typically public information (GitHub org/repo names). The endpoint is unauthenticated by design (webhooks), so this is directly reachable by any external actor.

### Recommendation
After selecting the GitHub App/organization used to verify the signature, re-validate that the same payload's `repository.full_name` (and `organization.login` if present) actually belongs to that resolved organization before dispatching to handlers — i.e., derive the acting organization strictly from `repository.full_name`'s owner segment (or enforce equality between it and `repository.owner.login`) rather than trusting `repository.owner.login` independently. Additionally, treat a missing `webhook_secret` as a hard misconfiguration that rejects all inbound webhooks for that organization rather than silently authenticating every request.

### Proof of Concept
Given a `secrets.yml` with two organizations, `staging-org` (no `webhook_secret` configured) and `shopify` (properly configured, tracks a real stack for `shopify/shipit-engine`):
```
POST /github/webhooks
X-Github-Event: status
Content-Type: application/json
(no valid X-Hub-Signature required)

{
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/required-check",
  "target_url": "http://attacker.example",
  "repository": {
    "owner": { "login": "staging-org" },
    "full_name": "shopify/shipit-engine"
  }
}
```
`verify_signature` resolves `repository_owner` = `"staging-org"`, loads its `GitHubApp`, and since `staging-org.webhook_secret` is blank, `verify_webhook_signature` returns `true` unconditionally — no signature needed. The `status` handler then resolves the target repository from `repository.full_name` = `"shopify/shipit-engine"` and records a forged successful status against the real `shopify` stack's commit, as shown by the flow in `Handler#stacks`/`#repository_name`. [5](#0-4) [4](#0-3)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-61)
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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
