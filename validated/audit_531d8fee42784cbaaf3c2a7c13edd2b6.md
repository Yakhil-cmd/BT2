### Title
Webhook signature verification is keyed on `repository.owner.login`/`organization.login` while event handlers act on `repository.full_name`, allowing forged events against protected stacks - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and therefore which `webhook_secret`) validates an inbound webhook using the org name embedded in the payload itself, while every webhook `Handler` resolves the actual `Repository`/`Stack` to mutate using a *different* field of that same attacker-suppliable payload. Because these two fields are never checked for consistency, an attacker can pick an organization that authenticates trivially (e.g. one with no `webhook_secret` configured) while pointing the event body at a completely different, protected repository's stack. This mirrors the Maia finding where `execute()` conflated the "recipient" field with the "refundee" field: two logically distinct trust roles are collapsed into fields that are never cross-validated.

### Finding Description
`WebhooksController#verify_signature` picks the GitHub App/secret to check the signature against solely from data inside the JSON body: [1](#0-0) [2](#0-1) 

`repository_owner` is `params.dig('repository','owner','login') || params.dig('organization','login')`. Shipit natively supports multiple configured GitHub organizations, each with its own independent `webhook_secret`, and that secret is explicitly documented/shown as optional (`webhook_secret: nil` is a valid, working per-org value): [3](#0-2) [4](#0-3) 

`verify_webhook_signature` returns `true` unconditionally when no `webhook_secret` is configured for the organization that was picked.

Meanwhile, every default webhook handler (`PushHandler`, all `PullRequest::*Handler`s) resolves the target `Repository`/`Stack` using an entirely different payload field, `repository.full_name`, via the shared base class: [5](#0-4) [6](#0-5) 

There is no code anywhere that checks that `repository.owner.login` (the field used to select the signing org) actually matches the owner encoded in `repository.full_name` (the field used to find the real `Stack`). Both fields are attacker-controlled JSON in the same unauthenticated POST body, so a crafted payload can declare `repository.owner.login = "org-with-no-secret"` while setting `repository.full_name = "victim-org/victim-repo"`. Signature verification then succeeds under `org-with-no-secret`'s (empty) secret, but `PushHandler`/`PullRequest*Handler` will locate and mutate the `Stack` belonging to `victim-org/victim-repo`, a repository actually protected by a different, secret-bearing GitHub App.

This is the direct analog of the reported bug: `recipient` (used for delivery) and `refundee` (used for trust/ownership) are two conceptually different fields silently equated in `MulticallRootRouter`; here, "the organization that authenticated" (`repository.owner.login`/`organization.login`) and "the repository that is written" (`repository.full_name`) are two conceptually different fields silently treated as if they always agree.

### Impact Explanation
An unauthenticated, unprivileged attacker (no Shipit session, no `ApiClient` token, no `webhook_secret`, no GitHub App key) can forge `push`, `pull_request`, `status`, or `check_suite` events for any `Stack` already tracked by the Shipit instance, as long as any *other* configured GitHub organization in that instance lacks (or the attacker can otherwise satisfy) a `webhook_secret`. This lets the attacker:
- Force `Stack#sync_github` re-syncs (`PushHandler` → `stack.sync_github`) on arbitrary, protected stacks at will, and
- Force provisioning/archival of review stacks (`PullRequest::OpenedHandler`, `LabeledHandler`, etc.) for arbitrary repositories.

Because `Stack#sync_github` feeds directly into `CacheDeploySpecJob` and (for stacks with `continuous_deployment` enabled) into the deploy pipeline, this crosses the "unauthorized deploy" boundary called out in the impact list, without the attacker ever needing valid credentials for the targeted organization.

### Likelihood Explanation
Requires only that the Shipit deployment (a) has more than one GitHub organization configured (a documented, supported feature) and (b) at least one configured organization omits `webhook_secret` (an explicitly documented optional field, and shown as a valid config value in `config/secrets.development.shopify.yml`). This is a realistic multi-tenant configuration (e.g., one org used only for auxiliary/testing repos with no secret set, alongside a production org with a real secret), and the attack requires no secrets, tokens, or prior access — only knowledge of the low-security org's name and the victim stack's `owner/repo` name, both of which are typically public.

### Recommendation
After selecting the GitHub App config via `repository_owner`/`organization.login` and validating the signature, additionally verify that the `repository.full_name` (or any other repository identifier used later by handlers) belongs to the same organization that was used to authenticate the request, rejecting the webhook otherwise. Do not allow signature selection and payload-target resolution to be derived from independent, individually-attacker-controlled fields.

### Proof of Concept
1. Configure two GitHub Apps in `secrets.yml` under `github:`, e.g. `victim-org` (with a real `webhook_secret`) and `sandbox-org` (with `webhook_secret: nil`), both installed as documented in `docs/setup.md`.
2. Register `victim-org/victim-repo` as a Shipit `Stack`.
3. As an unauthenticated attacker, POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "sandbox-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
No `X-Hub-Signature` header (or any arbitrary value) is required, because `verify_signature` selects `sandbox-org`'s GitHub App config (`repository_owner` resolves to `sandbox-org`), which has no `webhook_secret`, so `verify_webhook_signature` returns `true` unconditionally.
4. `WebhooksController#create` dispatches to `Shipit::Webhooks::Handlers::PushHandler`, which resolves the target via `payload.dig('repository','full_name')` = `"victim-org/victim-repo"`, and calls `stack.sync_github(expected_head_sha: ...)` on the real, protected `victim-org/victim-repo` stack — despite the request never being signed by `victim-org`'s app.

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
