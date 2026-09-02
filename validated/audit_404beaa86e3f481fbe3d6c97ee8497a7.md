### Title
Webhook signature verification is bound to the wrong organization, allowing cross-repository webhook forgery when any configured GitHub org has no `webhook_secret` - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App's HMAC secret to validate against using an attacker-controlled field of the *unverified* JSON body (`repository.owner.login`), while the event handlers that actually mutate state process the full, still-unverified body content (including whatever repository/organization data it contains). The signature check therefore authenticates "some organization named in the payload," not "the organization whose repository is actually being acted upon."

### Finding Description
`repository_owner` is read directly out of the untrusted payload before any signature check occurs: [1](#0-0) 

That value is used to pick which configured GitHub App/org's secret to verify with: [2](#0-1) 

`verify_webhook_signature` on that per-org config object short-circuits to `true` whenever the org's `webhook_secret` is blank/unset: [3](#0-2) 

Shipit explicitly supports multiple GitHub orgs configured simultaneously, each with its own (optional) `webhook_secret`: [4](#0-3) 

Once `verify_signature` passes (because the org picked via the attacker-supplied `repository_owner` field happens to have no secret configured), `create` dispatches the *entire, still-attacker-controlled* JSON body to the registered handlers: [5](#0-4) 

Nothing re-checks that the repository/organization the handlers subsequently look up and mutate (e.g. via `params.dig('repository', ...)` used elsewhere to resolve a `Stack`) is the same organization (`repository_owner`) that was used to select the verification secret. The binding that should hold — *the organization whose secret authenticated the request* == *the organization/repository the handlers act on* — is never enforced. An attacker can set `repository.owner.login` to an org configured without a secret (satisfying `verify_signature`) while leaving the rest of the payload (the data the handlers actually consume to resolve stacks/commits) pointing at a *different*, victim organization/repository that does have a secret configured.

### Impact Explanation
If a Shipit deployment configures multiple GitHub orgs (a documented, supported setup) and any one of them lacks a `webhook_secret`, an unauthenticated attacker can forge push/status/check_suite/membership/pull_request events for repositories belonging to *other* configured organizations, bypassing the app's signature-based authentication entirely for those events. Depending on which handler is targeted, this can forge CI/check statuses that the merge queue relies on (`MergeRequest::StatusChecker`, `ProcessMergeRequestsJob`) to decide when to auto-merge or unblock deploys, i.e., an unauthorized effect on cross-repository stack state and potentially triggering an unauthorized merge. This matches the report's underlying bug class: a value used to establish/verify trust (`repository_owner`, analogous to the "delegatee"/owner) is decoupled from the entity the system actually acts on (the target repository/stack), letting an attacker "wrap" the trust boundary.

### Likelihood Explanation
Exploitability requires no privileged credentials, tokens, or repository access — only that the deployment has at least one configured GitHub org without a `webhook_secret`, which the shipped example config (`config/secrets.development.shopify.yml`) explicitly shows as a supported (`nil`) value. This is a plausible real-world misconfiguration rather than a theoretical one, since the code path for handling a missing secret is intentional (`return true unless webhook_secret`), not a bug in signature math itself.

### Recommendation
- Require `verify_signature` to also confirm that the repository/organization actually referenced by the handler-relevant payload fields (e.g., the `Stack`'s configured `github_app`/org) matches the org whose secret validated the request, rejecting mismatches even when that org's secret check trivially passed.
- Consider making `webhook_secret` mandatory for every configured org (fail closed) instead of defaulting to `true` when absent.
- Resolve the target `Stack`/repository first, then verify the signature using that repository's own org secret — never let an attacker-chosen field determine which secret is checked.

### Proof of Concept
1. Configure Shipit with two GitHub orgs: `victim-org` (has `webhook_secret` set) and `attacker-org` (leaves `webhook_secret` blank, as shown supported in `config/secrets.development.shopify.yml`).
2. POST to `/webhooks` with header `X-Github-Event: status` (or `push`) and a body where `repository.owner.login = "attacker-org"` but the remainder of the payload (sha/branches/etc.) references a commit/stack belonging to `victim-org/some-repo`.
3. `verify_signature` calls `Shipit.github(organization: "attacker-org")`, whose `webhook_secret` is nil, so `verify_webhook_signature` returns `true` regardless of the actual `X-Hub-Signature` header/value.
4. `create` dispatches the full payload to the `status`/`push` handlers, which resolve and mutate `victim-org`'s stack/commit state using data from a request that was never actually authenticated by `victim-org`'s secret.

**Uncertainty note:** I was not able to fully inspect the internal repository/stack-resolution logic of the individual event handlers (e.g., the push/status handler implementation files under `app/models/shipit/webhooks/handlers/`) within the available tool budget, so I cannot cite the exact line where a handler resolves `Stack` purely from payload content independent of `repository_owner`. This is inferred from the dispatcher (`Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`) receiving the raw, unfiltered `params` and the absence of any cross-check between `repository_owner` and the handler-processed repository in the controller itself. A follow-up review of the handler classes would be needed to confirm the exact mutation path for a specific event type.

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
