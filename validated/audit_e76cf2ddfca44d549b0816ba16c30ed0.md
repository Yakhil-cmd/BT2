Confirmed: `Handler#stacks` in `app/models/shipit/webhooks/handlers/handler.rb:32-38` resolves the target repository from `payload.dig('repository', 'full_name')`, while `WebhooksController#verify_signature` in `app/controllers/shipit/webhooks_controller.rb:59-62` selects the GitHub App / `webhook_secret` used to authenticate the request from a *different* field: `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`). These two fields are never cross-checked against each other.

### Title
Webhook signature is validated against `repository.owner.login`, but processing acts on the independently-controlled `repository.full_name` - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` picks which organization's `webhook_secret` to HMAC-verify a webhook against using `repository.owner.login` (or `organization.login`) from the JSON body. Once the signature check passes, the actual event handler (`Shipit::Webhooks::Handlers::Handler#stacks`) resolves the stack/repository to act on using `repository.full_name` — a sibling field in the same JSON body that carries no cryptographic tie to `repository.owner.login`.

### Finding Description [1](#0-0)  shows `verify_signature` computing `github_app = Shipit.github(organization: repository_owner)` and then calling `github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)`, where `repository_owner` is `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [2](#0-1) . This only proves the raw body was signed with *some* organization's configured secret (looked up by the `owner.login` value inside that same unauthenticated body).

Once verification passes, `Handler#stacks` looks up the repository/stack using an entirely separate field, `repository.full_name` [3](#0-2) , and e.g. `PushHandler#process` uses that resolved stack together with `params.ref`/`params.after` to trigger `stack.sync_github(expected_head_sha: params.after)` [4](#0-3) .

In a multi-organization Shipit deployment (explicitly supported, see `config/secrets.development.shopify.yml` and README's "Use this configuration schema if you are configuring multiple Github applications for different Github organizations"), each org has its own `webhook_secret`. Because `verify_webhook_signature` HMACs the *entire* `raw_post` [5](#0-4) , an attacker who legitimately controls one onboarded organization's webhook secret (e.g., they administer their own org's GitHub App settings, which is not a Shipit-privileged action) can freely craft the JSON body before it is signed. They can set `repository.owner.login` to their own org (so the correct secret is selected and the HMAC passes) while setting `repository.full_name` to any other tracked `owner/repo` string that Shipit has a `Repository`/`Stack` record for. Nothing after signature verification re-checks that `full_name`'s owner matches the org whose secret authenticated the request.

This is exactly the "authenticated organization vs. repository actually written" trust-binding break called out in scope: `Shipit.github(organization: repository_owner)` authenticates one field; `Repository.from_github_repo_name(repository_name)` (via `full_name`) is the field actually acted upon.

### Impact Explanation
This lets an attacker who only controls a webhook secret for one onboarded (possibly low-trust) GitHub organization inject forged webhook events — pushes, statuses, check runs, `pull_request`, `membership`, etc. — against **any other organization/repository's stack** already tracked by the same Shipit instance, as long as they know or can guess a valid `full_name`. For the `push` handler this can force `GithubSyncJob` to run against an arbitrary stack with an attacker-chosen `expected_head_sha`; for `status`/`check_suite` it can forge CI status data used to gate the merge queue and continuous deployment, which can enable an unauthorized merge/deploy decision on a repository the attacker does not own. This satisfies the High/Critical bar of "unauthorized deploy, rollback, or merge" via a cross-repository write of webhook-driven state.

### Likelihood Explanation
Requires a Shipit instance configured for more than one GitHub organization (a documented, supported configuration) and requires the attacker to control (or obtain) the `webhook_secret` for at least one of those organizations — something within reach of any org admin who legitimately manages their own onboarded organization's GitHub App settings, without needing any Shipit-side privilege, `ApiClient` token, or the target organization's secret. Single-organization deployments are not affected, since there is only one `webhook_secret` to select regardless of the claimed owner.

### Recommendation
Cross-validate that `repository.owner.login`/`organization.login` (the field used to select the verifying secret) matches the owner embedded in `repository.full_name` before dispatching to any handler, or better, resolve the target `Repository`/`Stack` using the same organization identity that was cryptographically verified rather than trusting an independent field from the same unauthenticated JSON body.

### Proof of Concept
1. Shipit configured for two orgs, `attacker-org` and `victim-org`, each with distinct `github.<org>.webhook_secret` (per `config/secrets.development.shopify.yml` multi-org schema).
2. Attacker controls `attacker-org`'s GitHub App webhook secret (legitimately, as an admin of their own org's app).
3. Attacker crafts a `push` payload: `{"repository": {"owner": {"login": "attacker-org"}, "full_name": "victim-org/victim-repo"}, "ref": "refs/heads/main", "after": "<attacker-chosen-sha>"}`.
4. Attacker signs the raw body with `attacker-org`'s `webhook_secret` and sets `X-Hub-Signature`.
5. `WebhooksController#verify_signature` resolves `repository_owner` → `"attacker-org"`, fetches `attacker-org`'s secret, and the HMAC check passes.
6. `PushHandler#stacks` resolves the target repository via `payload.dig('repository','full_name')` → `victim-org/victim-repo`, and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on the victim's stack — a cross-repository write triggered by a request never authenticated for that repository/organization.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```
