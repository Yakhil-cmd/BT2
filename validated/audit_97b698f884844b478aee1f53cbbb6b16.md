### Title
Webhook signature verification org derived from unverified payload allows spoofed events for any repository - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects *which* GitHub App/organization config (and therefore which `webhook_secret`) to validate the signature against by reading an attacker-controlled field of the still-unverified JSON body (`repository.owner.login` / `organization.login`). The event handlers that actually mutate state, however, key off a *different* field of that same unverified body (`repository.full_name`). Because Shipit supports multiple GitHub orgs configured simultaneously, each with its own optional `webhook_secret`, these two fields are never checked for consistency, breaking the binding "organization that authenticated" == "repository that is written."

### Finding Description
`verify_signature` computes `repository_owner` from the raw, unverified payload and uses it purely to pick the `GitHubApp` instance used to verify the HMAC signature: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` looks up the org's config, and `GitHubApp#verify_webhook_signature` short-circuits to `true` when that org has no configured `webhook_secret`: [3](#0-2) 

`Shipit.github` raises only if the organization name is *unknown*, not if it has a blank secret: [4](#0-3) 

Once the (trivially bypassed) signature check passes, `create` dispatches the entire raw payload to handlers: [5](#0-4) 

But the handlers resolve the target repository/stack from `repository.full_name`, a field that was never used or covered by the org selection made in `verify_signature`: [6](#0-5) [7](#0-6) 

Multi-org configuration (each org with its own `webhook_secret`) is an explicitly supported, documented deployment shape: [8](#0-7) 

Given this, if a Shipit instance has **any** configured organization whose `webhook_secret` is blank/unset (a valid configuration state per `verify_webhook_signature`), an unprivileged attacker can:
1. Set `repository.owner.login` (or `organization.login`) to that org's name — signature verification is skipped entirely.
2. Set `repository.full_name` to a completely different, real, tracked repository (e.g. one belonging to another org that does have deploys/CI configured).
3. Send the forged webhook with an arbitrary/absent `X-Hub-Signature` for events like `push`, `status`, `pull_request`, `check_suite`, `membership`.

The handler layer will act on the spoofed `repository.full_name`, since it never re-validates against the org that was actually authenticated (or not authenticated at all) in `verify_signature`.

### Impact Explanation
This breaks the deploy-trust binding "organization authenticated" vs "repository written," matching the High-severity criteria: unauthenticated actions can be injected into any tracked stack. Concretely, an attacker can forge a `status` event to post fabricated CI status (`success`/`pending`) for a target repository's commit, which Shipit's deploy-readiness checks rely on, potentially enabling an **unauthorized deploy**. They can also forge `push` events to trigger `GithubSyncJob` against arbitrary stacks, or `membership`/`pull_request` events to manipulate team membership or archive/unarchive review stacks for repositories they have no access to — all without possessing the real target's `webhook_secret`.

### Likelihood Explanation
Requires only that the Shipit deployment configures more than one GitHub organization and that at least one of them (which need not be a "real"/sensitive org, e.g., a low-value test org onboarded to the same instance) has no `webhook_secret` set — a state the codebase explicitly tolerates (`return true unless webhook_secret`). No credentials, GitHub App keys, or prior access are needed; the attacker only needs to know the name of that lax organization and the target repository's `full_name`, both of which are typically public knowledge.

### Recommendation
Cross-validate that the organization used to select/verify the signature matches the owner embedded in `repository.full_name` (or `organization.login`) before dispatching to handlers, and reject events where they diverge. Additionally, treat an org with a blank `webhook_secret` as unverifiable/untrusted rather than auto-passing signature verification, or require all configured orgs to have a non-blank secret.

### Proof of Concept
1. Configure Shipit with two orgs: `victim-org` (has deploys, real `webhook_secret`) and `laxorg` (`webhook_secret` unset), per `config/secrets.development.shopify.yml` structure.
2. POST to `/webhooks` with header `X-Github-Event: status`, no valid `X-Hub-Signature`, and body:
```json
{
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "full_name": "victim-org/victim-repo", "owner": { "login": "laxorg" } }
}
```
3. `verify_signature` resolves `repository_owner` to `"laxorg"`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally.
4. `StatusHandler` (keyed off `repository.full_name`) creates/updates a green CI status on `victim-org/victim-repo`'s real commit, influencing deploy eligibility for a repository the attacker never authenticated against.

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

**File:** lib/shipit.rb (L170-181)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
```
