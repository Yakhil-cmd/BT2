### Title
Webhook signature verified against the organization named in an attacker-controlled JSON field, not the repository the event actually acts on - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and therefore which `webhook_secret`) to check the `X-Hub-Signature` against by reading `repository.owner.login` (or `organization.login`) straight out of the *unverified* JSON body. Push processing, however, resolves the target `Stack`/`Repository` from a completely different field of the same body — `repository.full_name` — inside `Shipit::Webhooks::Handlers::Handler#repository_name`. Because these two fields are never cross-checked, an attacker who legitimately controls a GitHub App installation (and thus knows a valid `webhook_secret`) for one organization configured in this Shipit instance can forge a payload whose `repository.owner.login` names *their own* org (so the signature check passes) while `repository.full_name` names a victim repository/stack tracked by Shipit, causing the attacker-signed payload to drive sync/status/build actions for a repository they do not own.

### Finding Description
`verify_signature` picks the GitHub App config to validate against using data taken from the same untrusted payload it is trying to authenticate: [1](#0-0) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
```

`repository_owner` is derived purely from JSON that has not yet been authenticated: [2](#0-1) 

The signature itself is a valid HMAC-SHA1 of the raw body under the secret belonging to `repository_owner`'s configured GitHub App: [3](#0-2) 

This binding — "organization that authenticated" vs. "repository that is written" — is never re-checked. Once the request passes `verify_signature`, `create` dispatches the raw parsed `params` to every registered handler for the event: [4](#0-3) 

Handlers determine the target repository from a *different* field, `repository.full_name`, completely independent of `repository.owner.login`: [5](#0-4) 

For `push` events, `PushHandler#process` loads all not-archived stacks for that repository/branch and calls `sync_github`, which enqueues `GithubSyncJob` to fetch and append new commits for the stack, feeding whatever `expected_head_sha` was in the (fully attacker-controlled once signed) body: [6](#0-5) 

`Shipit` explicitly documents and supports installing multiple GitHub App organizations against a single instance, each with an independent `webhook_secret` known only to whoever administers that org's app: [7](#0-6) 

In this configuration, "authenticated organization" (whose secret validated the HMAC) and "repository written" (looked up via `full_name`) are two unrelated JSON fields, so trust granted to one org's webhook secret is silently extended to any repository string in the same instance's `Repository` table, regardless of actual ownership.

### Impact Explanation
An attacker who is an admin of any one GitHub organization configured under this Shipit instance's `github:` secrets (a routine, low-privilege situation for a multi-tenant Shipit deployment) can forge signed webhook deliveries that are accepted for repositories belonging to *other* organizations tracked by the same instance. Depending on which event/handler is targeted, this can trigger `GithubSyncJob` (importing forged commit history that ends up gated for deploy), spurious/forced commit statuses, or pull-request/review-stack provisioning actions for a victim repository — an unauthorized cross-repository write of Shipit's internal state driven by another org's forged, but validly "signed", payload. This matches the report's core bug class: a value used to authorize/act (the repository acted upon) is not the value actually covered/pinned by the verification (the organization/secret used to verify).

### Likelihood Explanation
Exploitability requires only that the attacker control one legitimate GitHub App installation/webhook secret already trusted by the target Shipit instance (a normal condition in the documented multi-org setup) — no repository write access to the victim, no `ApiClient` token, and no compromise of the victim org's own webhook secret is needed. This is a plausible, realistic misconfiguration-independent path once multiple organizations are configured, which the project's own docs recommend as a supported feature.

### Recommendation
Cross-check that `repository.owner.login` (the org whose secret validated the signature) matches the owner encoded in `repository.full_name` before dispatching to handlers, or better, derive the verifying organization strictly from the persisted `Repository`/`Stack` record resolved by `full_name`, never from a second untrusted field in the same unauthenticated payload. Reject the webhook if the two disagree.

### Proof of Concept
1. Configure Shipit with two GitHub App orgs, `attacker-org` and `victim-org`, per `docs/setup.md` multi-org instructions; attacker administers `attacker-org` and knows its `webhook_secret`.
2. Attacker crafts a `push` event JSON body where `repository.owner.login` = `"attacker-org"` but `repository.full_name` = `"victim-org/victim-repo"` and `ref`/`after` point to attacker-chosen commits.
3. Attacker computes `X-Hub-Signature: sha1=HMAC(attacker-org's webhook_secret, raw_body)` and POSTs to `/webhooks`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "attacker-org")` and validates successfully against the attacker's own known secret.
5. `PushHandler#process` resolves stacks via `Repository.from_github_repo_name("victim-org/victim-repo")`, unrelated to `attacker-org`, and enqueues `GithubSyncJob` for the victim stack with the attacker-supplied `expected_head_sha`.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-24)
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

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
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
