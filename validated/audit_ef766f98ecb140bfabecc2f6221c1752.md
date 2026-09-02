### Title
Cross-organization webhook forgery via signature/target mismatch in `WebhooksController` - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects the GitHub App secret used to authenticate an inbound webhook based on `repository.owner.login` (falling back to `organization.login`), a field read out of the *unverified* JSON body itself. Once verification succeeds, the same body is handed to event handlers (`PushHandler`, PR handlers, etc.) which instead resolve the target `Repository`/`Stack` using a *different* field from that body: `repository.full_name`. Because Shipit supports multiple GitHub Apps for multiple organizations, each with its own `webhook_secret`, an attacker who possesses valid webhook credentials for one onboarded organization ("OrgA") can forge a payload that authenticates as OrgA but whose `repository.full_name` (and other content) targets a stack belonging to a completely different organization ("OrgB").

### Finding Description
`verify_signature` computes the authenticating organization purely from attacker-supplied JSON, before any cryptographic check has occurred: [1](#0-0) [2](#0-1) 

It then verifies the raw body's HMAC against the `webhook_secret` configured for that organization: [3](#0-2) 

This succeeds as designed whenever the payload was actually signed with OrgA's secret — the problem is that nothing ties `repository.owner.login` (used to pick the secret) to `repository.full_name` (used to pick the target). Handlers universally resolve the acted-upon repository via `full_name`, not `owner.login`: [4](#0-3) [5](#0-4) 

The multi-organization configuration model, where each org has an independently held `webhook_secret`, is a first-class, documented feature: [6](#0-5) 

The binding that should hold is:
`organization authenticated by verify_signature (repository.owner.login / organization.login)` == `organization whose stack is mutated by the handler (repository.full_name)`

The code never enforces this equality. An attacker who legitimately controls OrgA's GitHub App webhook secret (e.g., an org admin of a tenant onboarded to a shared Shipit instance) can construct:
```json
{
  "ref": "refs/heads/main",
  "after": "<victim commit sha>",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/victim-repo"
  }
}
```
sign it with OrgA's `webhook_secret`, and send it to the shared `/webhooks` endpoint. `verify_signature` resolves `Shipit.github(organization: "OrgA")` and validates the HMAC successfully. `PushHandler` then resolves `Repository.from_github_repo_name("OrgB/victim-repo")` and calls `stack.sync_github(expected_head_sha: ...)` on a stack belonging to OrgB — an organization the attacker never authenticated for.

### Impact Explanation
This breaks the tenant/organization isolation the multi-GitHub-App design is meant to provide. An attacker who is only authorized (holds valid webhook credentials) for one organization can force `GithubSyncJob`/`CacheDeploySpecJob` execution against another organization's stack, causing it to fetch and cache commits it selected, mark the stack accessible/inaccessible, and, depending on other handlers reachable the same way (`pull_request` handlers use the identical `repository.full_name` pattern), archive/unarchive review stacks or mutate pull-request-driven state for a repository outside the attacker's org. This is a cross-organization write achieved purely by crafting payload fields never covered by the authentication check on those specific fields, matching the "unauthorized deploy/rollback" / cross-repository-write impact class.

### Likelihood Explanation
Requires the attacker to already hold a valid `webhook_secret` for at least one organization configured in Shipit's `secrets.yml` (i.e., they administer that org's installed GitHub App) — a real but bounded precondition in genuinely multi-tenant deployments, which is exactly the scenario the `github: {org: {...}}` config schema (see `config/secrets.development.shopify.yml`) is built to support. No other privilege (no Shipit session, no API token, no target-org access) is required to affect the victim organization's stack.

### Recommendation
In `WebhooksController#verify_signature`/`create`, bind the authenticated organization to the object actually acted upon: derive `repository_owner` from `repository.full_name`'s owner segment (or explicitly compare `repository.owner.login` against the owner parsed out of `repository.full_name`) and reject the request if they diverge. Additionally, `Handler#repository_name`/`stacks` should validate that the resolved repository's `owner` matches the organization that successfully verified the signature before dispatching to `sync_github` or any mutating action.

### Proof of Concept
1. Configure two orgs in `secrets.yml`, `OrgA` and `OrgB`, each with distinct GitHub Apps/`webhook_secret`s (per `config/secrets.development.shopify.yml` schema).
2. As an attacker who administers OrgA's GitHub App (knows OrgA's `webhook_secret`), craft:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha existing in OrgB/victim-repo>",
  "repository": { "owner": {"login": "OrgA"}, "full_name": "OrgB/victim-repo" }
}
```
3. Compute `X-Hub-Signature` as `sha1=HMAC-SHA1(OrgA_webhook_secret, body)`.
4. `POST /webhooks` with header `X-Github-Event: push`.
5. `verify_signature` resolves `repository_owner` = `"OrgA"`, verifies successfully against OrgA's secret.
6. `Shipit::Webhooks.for_event('push')` invokes `PushHandler`, which resolves `Repository.from_github_repo_name("OrgB/victim-repo")` and triggers `sync_github` for OrgB's stack — despite the attacker never authenticating for OrgB.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-27)
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
    end
  end
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
