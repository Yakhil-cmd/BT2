### Title
Webhook signature is bound to `repository.owner.login`, but every handler acts on the unauthenticated `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization config (and therefore which `webhook_secret`) to validate the incoming payload against using `repository.owner.login` (falling back to `organization.login`). Every webhook handler, however, resolves the `Repository`/`Stack` to act on using a *different* payload field, `repository.full_name`, via `Shipit::Webhooks::Handlers::Handler#repository_name`. Nothing ties these two fields together, and if the organization named by `repository.owner.login` has no `webhook_secret` configured, `verify_webhook_signature` unconditionally returns `true`, allowing a fully unauthenticated caller to submit a payload whose `repository.full_name` points at an entirely different organization's stack.

### Finding Description
`verify_signature` computes the organization to authenticate against purely from attacker-supplied JSON: [1](#0-0) [2](#0-1) 

`Shipit::GithubApp#verify_webhook_signature` short-circuits to `true` when no `webhook_secret` is configured for that organization: [3](#0-2) 

A `webhook_secret` is explicitly documented/shipped as an optional, nilable per-organization setting (see the example config shipping `webhook_secret: # nil` for each org): [4](#0-3) 

Meanwhile, every default handler (`PushHandler`, the `PullRequest::*` handlers, `MembershipHandler`, etc.) resolves the target `Repository`/`Stack` using a completely separate field of the same payload, `repository.full_name`, via the shared base class: [5](#0-4) [6](#0-5) 

Because a legitimate GitHub-generated payload always keeps `repository.owner.login` consistent with `repository.full_name`, this split is invisible in normal operation. But an attacker crafting a raw HTTP POST to the webhooks endpoint controls both fields independently. If any organization configured on the Shipit instance has a blank `webhook_secret` (a supported, documented configuration), the attacker can set `repository.owner.login` to that org (so `verify_signature` accepts the request with `verified = true` regardless of `X-Hub-Signature`) while setting `repository.full_name` to the full name of a stack belonging to a *different*, unrelated organization/repository. The handler then acts on that unrelated stack with no authentication check ever having been performed against it. This breaks exactly the binding the review targets: "an organization that authenticated versus the repository that is written."

### Impact Explanation
Depending on which handler is invoked, this allows an unauthenticated network attacker to:
- Trigger `PushHandler#process`, which calls `stack.sync_github(expected_head_sha: params.after)` on any stack matching the forged `repository.full_name` + `branch`, potentially causing an unauthorized deploy sync/trigger for continuous-deployment-enabled stacks (`app/models/shipit/webhooks/handlers/push_handler.rb`).
- Trigger `MembershipHandler`, which mutates `Team`/`Membership` records for arbitrary GitHub logins "on the fly" (confirmed by `test/controllers/webhooks_controller_test.rb` cases `:membership creates the mentioned user on the fly` / `can append an user membership`), which can affect `Shipit.github_teams`-based authorization used to gate access to the app.
- Trigger `PullRequest::*` handlers to archive/unarchive review stacks or manipulate pull request labels used in deploy gating logic, for stacks outside the "authenticated" organization.

This matches the High-impact category: escalation into `Shipit.github_teams` authorization and/or an unauthorized deploy trigger, achievable with zero credentials against any instance that has at least one organization configured without a `webhook_secret`.

### Likelihood Explanation
Likelihood is conditioned on operational configuration: it requires at least one organization on the Shipit instance to have `webhook_secret` unset/blank. This is not a hypothetical edge case — the engine's own shipped example configuration (`config/secrets.development.shopify.yml`) sets `webhook_secret` to nil for every org, and the setup docs describe the secret as something you set "if" you configured one on the GitHub App side, implying it is optional. Any multi-organization Shipit deployment where even one org skips this optional field is fully exposed, with no rate limiting or other check to slow the attacker down. No credential, session, or prior repository access is required — the attacker only needs the name of an organization configured with a blank secret and the `full_name` of the victim repository, both of which are typically public information (organization/App names are often discoverable).

### Recommendation
Reject webhook payloads where the effective "authenticated" identity does not match the entity being mutated:
- Derive the organization/stack lookup used by handlers from the same verified scope used during signature verification instead of an independent field of the same untrusted payload, e.g. pass the verified `repository_owner`/organization down to handlers and require `repository.full_name`'s owner segment to match it.
- Do not allow `verify_webhook_signature` to silently return `true` when `webhook_secret` is blank; either require a secret for every configured organization or explicitly restrict what unsigned webhooks are permitted to do (e.g., disallow cross-repository lookups entirely when unsigned).
- Consider validating that `repository.owner.login` equals the owner segment of `repository.full_name` before dispatching to handlers, rejecting the request otherwise.

### Proof of Concept
Preconditions: Shipit instance has organization `no-secret-org` configured with `webhook_secret: nil` (or blank), and organization `victim-org` has a stack tracking `victim-org/victim-repo` on branch `main`.

```
POST /webhooks HTTP/1.1
X-Github-Event: push
Content-Type: application/json

{
  "repository": {
    "owner": { "login": "no-secret-org" },
    "full_name": "victim-org/victim-repo"
  },
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>"
}
```

- `verify_signature` computes `repository_owner = "no-secret-org"`, loads that org's `GithubApp`, and since it has no `webhook_secret`, `verify_webhook_signature` returns `true` unconditionally regardless of the (missing or arbitrary) `X-Hub-Signature` header.
- `PushHandler#process` then resolves stacks via `repository_name = "victim-org/victim-repo"` (unrelated to the authenticated org) and calls `stack.sync_github(expected_head_sha: "<attacker-chosen sha>")` on the victim's stack — an action never covered by any verified signature for `victim-org`.

The same technique applies by swapping the `X-Github-Event` header/payload shape to hit `MembershipHandler` (mutating Team/Membership records) or the `pull_request` handlers (archiving/unarchiving review stacks) for any repository, using only the identity of an organization configured without a webhook secret.

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
