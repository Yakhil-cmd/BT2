### Title
Webhook signature is verified against the organization derived from `repository.owner.login`, but the repository actually mutated is resolved from the unrelated `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App / `webhook_secret` to validate a webhook against using `repository.owner.login` (falling back to `organization.login`), while every `Shipit::Webhooks::Handlers::Handler` subclass resolves the `Repository`/`Stack` to actually write to using the completely independent `repository.full_name` field. These two fields are never checked for consistency, so the "organization whose secret authenticated the request" and "the repository/org that is written to" are not the same equality that the code implicitly assumes.

### Finding Description
In `app/controllers/shipit/webhooks_controller.rb`: [1](#0-0) 
`verify_signature` computes `repository_owner` from `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` and uses it to look up `Shipit.github(organization: repository_owner)`, then verifies the `X-Hub-Signature` against that org's `webhook_secret`: [2](#0-1) 

Meanwhile, every webhook handler (`PushHandler`, `StatusHandler`, `MembershipHandler`, PR handlers, etc.) inherits `Handler#stacks`/`#repository_name`, which resolves the target `Repository` from `payload.dig('repository', 'full_name')`: [3](#0-2) 

`Repository.from_github_repo_name` splits this `owner/name` string and looks the repository up purely by that string, independent of `repository.owner.login`: [4](#0-3) 

`GitHubApp#verify_webhook_signature` also has a bypass: if no `webhook_secret` is configured for the resolved organization, verification is skipped entirely (`return true unless webhook_secret`): [5](#0-4) 

Multi-organization deployments are an explicitly supported configuration shape, and it's normal/documented for individual orgs to have no `webhook_secret` set (`webhook_secret: # nil`), as shown in the shipped example secrets files: [6](#0-5) [7](#0-6) 

The equality that the code should enforce but doesn't:
`organization used to select/verify webhook_secret (repository.owner.login)` == `organization/repository actually written by the handler (repository.full_name)`.

Because the controller and the handler each independently trust a different attacker-controlled JSON field from the same unauthenticated POST body, an attacker who can produce (or does not even need, if a secret-less org exists) a validly-"verified" webhook for organization A can set `repository.full_name` to `B/some-repo` in the same payload. The signature check passes (verified against A's app, possibly with no secret at all), yet `PushHandler`, `StatusHandler`, `MembershipHandler`, etc. will act on organization/repository B's `Stack`/`Repository`/`Team` records.

### Impact Explanation
This breaks the isolation the per-organization `webhook_secret` binding is meant to provide across a multi-org Shipit deployment: an attacker able to satisfy the (possibly secret-less) verification for one configured organization can trigger writes against a stack belonging to a different, better-protected organization — e.g. forcing `PushHandler` to invoke `stack.sync_github` on another org's stack, injecting `StatusHandler`-created commit statuses on another org's commits, or having `MembershipHandler` add/remove team members for another org's `Team`. This is a cross-organization/cross-repository write achieved without possessing the target organization's real webhook credentials, satisfying the "cross-repository writes" impact bucket.

### Likelihood Explanation
Requires: (1) a Shipit instance configured with more than one GitHub organization (a documented, supported configuration — see `lib/shipit.rb#github_app_config`/`#github_organizations` and the shipped multi-org secrets examples), and (2) at least one of the configured organizations having no `webhook_secret` set (also a documented/valid configuration, shown directly in the example secrets files) or the attacker otherwise being able to produce a valid signature for some org. Given that shipped configuration examples themselves show `webhook_secret: # nil` as an accepted value, this is a realistic operational condition rather than a purely theoretical one.

### Recommendation
Derive the organization used for signature verification from the same field used to resolve the target repository (`repository.full_name`'s owner segment), or, conversely, have handlers validate that `repository.owner.login`/`organization.login` matches the owner segment of `repository.full_name` before acting. Additionally, reconsider silently treating a missing `webhook_secret` as "verified" (`return true unless webhook_secret`) in multi-org configurations, since it effectively disables authentication for that organization's webhook traffic while still allowing cross-org payload confusion.

### Proof of Concept
1. Configure Shipit with two organizations, `orgA` (no `webhook_secret` configured, or one known to the attacker) and `orgB` (protected, unknown secret), each with a `Stack` tracking a repository (per `test/dummy/config/secrets_double_github_app.yml`-style setup).
2. POST to the shared webhook endpoint with headers `X-Github-Event: push` and a body where:
   - `repository.owner.login = "orgA"` (or `organization.login = "orgA"`), used by `WebhooksController#verify_signature` to pick `orgA`'s (secret-less or known) `webhook_secret` — verification succeeds.
   - `repository.full_name = "orgB/some-repo"`, used by `PushHandler#stacks` (via `Handler#repository_name` / `Repository.from_github_repo_name`) to resolve the actual `Stack` to sync.
3. `Shipit::Webhooks.for_event('push')` runs `PushHandler`, which calls `stack.sync_github(expected_head_sha: params.after)` on `orgB`'s stack, even though the signature was only verified against `orgA`'s (weak/absent) secret.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** config/secrets.development.shopify.yml (L5-18)
```yaml
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
```

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```
