### Title
Webhook signature bypass for orgs without `webhook_secret` allows cross-repository/cross-tenant writes - ([File: lib/shipit/github_app.rb])

### Summary
`GithubApp#verify_webhook_signature` unconditionally trusts a webhook when the matched organization has no `webhook_secret` configured, and the webhook event handlers resolve the target `Repository`/`Stack` from a payload field (`repository.full_name`) that is never checked against the organization used to select/skip the signature check. This breaks the trust binding "organization that authenticated" == "repository that is written to."

### Finding Description
`WebhooksController#verify_signature` selects a `github_app` for signature verification using `repository_owner`, a value pulled directly from the untrusted payload (`params.dig('repository','owner','login')` or `params.dig('organization','login')`): [1](#0-0) 

That `github_app` is then asked to verify the signature: [2](#0-1) 

If the matched organization's config has a blank `webhook_secret`, `verify_webhook_signature` returns `true` unconditionally — no HMAC check is performed at all for that request.

Once `create` runs, the JSON payload is dispatched to handlers, which resolve the repository/stack to act on purely from the `repository.full_name` payload field, independent of whatever organization was used (or bypassed) during signature verification: [3](#0-2) [4](#0-3) 

There is no cross-check anywhere in this pipeline that the `repository.full_name` (or the repositories/stacks it maps to) actually belongs to the organization named in `repository.owner.login`/`organization.login` that was used to select the `github_app` for verification. Because that field selection happens purely from attacker-controlled JSON and the signature check can be a no-op for orgs without a secret configured, the "authenticating organization" and the "repository that gets written" are two independently attacker-influenced values with no enforced equality.

### Impact Explanation
An unauthenticated caller who only needs to know the name of any GitHub organization configured on the Shipit instance without a `webhook_secret` (a supported, documented configuration — `webhook_secret` is optional per `GithubApp#initialize`) can submit a forged webhook (`push`, `status`, `check_suite`, etc.) that:
- Sets `repository.owner.login`/`organization.login` to the secret-less org, so `verify_webhook_signature` trivially returns `true` without ever checking a signature.
- Sets `repository.full_name` to any other repository tracked by Shipit, including ones belonging to a fully secured, unrelated organization.

The handlers then act on that unrelated repository: e.g. `PushHandler` enqueues `GithubSyncJob` for the targeted stack's branch, `StatusHandler`-style flows write commit statuses, `check_suite` triggers `RefreshCheckRunsJob`. This is an unauthorized, cross-repository/cross-tenant write performed without ever presenting a valid signature for the targeted repository's organization — satisfying the "cross-repository writes" Critical-impact criterion.

### Likelihood Explanation
Exploitability only requires knowledge of one organization name hosted on the Shipit instance that has no `webhook_secret` set (discoverable by trial, since unknown orgs are rejected with a distinguishable `422`/log message via `GithubOrganizationUnknown`, letting an attacker enumerate valid organization names). No GitHub credentials, Shipit session, or API token are required — the request goes straight to the public `WebhooksController#create` endpoint.

### Recommendation
- Do not silently accept requests when `webhook_secret` is blank; either require `webhook_secret` for all configured organizations or explicitly restrict which organizations may skip verification.
- After verifying the signature, enforce that the `repository.full_name` (and any repository/stack acted upon by a handler) actually belongs to the organization (`repository_owner`) that was verified for that request, rejecting payloads where they diverge.

### Proof of Concept
1. Identify (by trial against `WebhooksController`, using the distinguishable `GithubOrganizationUnknown` response) an organization `unsecured-org` configured on the target Shipit instance with no `webhook_secret`.
2. POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "unsecured-org" },
    "full_name": "victim-org/protected-repo"
  }
}
```
3. `verify_signature` resolves `github_app` for `unsecured-org`, whose blank `webhook_secret` makes `verify_webhook_signature` return `true` without inspecting `X-Hub-Signature`.
4. `PushHandler#process` looks up stacks for `victim-org/protected-repo` and enqueues `GithubSyncJob`/writes state for that stack, even though `victim-org` never authenticated this request.

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
