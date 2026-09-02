### Title
Cross-organization webhook forgery via mismatched signature-selection field and action-target field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In multi-organization Shipit deployments, `WebhooksController#verify_signature` selects which GitHub App/webhook secret to validate a webhook against using the `repository.owner.login` (or `organization.login`) field of the *unverified* JSON payload, while the downstream `Handler` subclasses that actually act on the payload (triggering syncs, archiving/unarchiving review stacks, updating pull requests, etc.) resolve the target `Repository`/`Stack` using the `repository.full_name` field of that same payload. Because these are two independently attacker-controlled fields, an attacker who can produce a validly-signed payload for *any one* configured organization (e.g., one with no `webhook_secret` set, which is explicitly allowed and bypasses verification entirely) can set `repository.full_name` to point at a repository/stack belonging to a *different* organization and have Shipit act on it.

### Finding Description
`verify_signature` in `WebhooksController` computes `repository_owner` from the raw payload before any signature has been checked: [1](#0-0) 

It then looks up the `GitHubApp` config for that organization and verifies the signature against that org's secret: [2](#0-1) 

`GitHubApp#verify_webhook_signature` explicitly treats a missing/blank `webhook_secret` as automatically verified: [3](#0-2) 

and the example/documented multi-org secrets configuration allows per-organization `webhook_secret` to be left blank: [4](#0-3) 

Once the request passes this check, `Handler#stacks`/`Handler#repository_name` (the base class used by `PushHandler` and all pull-request handlers) locate the target `Repository` using a *different* field of the same payload, `repository.full_name`, not `repository.owner.login`: [5](#0-4) [6](#0-5) 

Because the HMAC in `verify_signature` is computed over the entire raw request body, this is not simply "sign with org A's secret, GitHub sends consistent fields" — it is that `verify_signature`'s selection of *which* secret to check against is driven by `repository.owner.login`, but nothing enforces that `repository.owner.login` and `repository.full_name` refer to the same repository/org. An attacker who knows (or is not required to know, if blank) the webhook secret for organization A can craft a payload where `repository.owner.login` = `"A"` (so `Shipit.github(organization: "A")` is used for verification, which may accept any/no signature) while `repository.full_name` = `"B/target-repo"` (so the handler acts against organization B's stack). The signature check never inspects `full_name`, and the handler never inspects `owner.login`.

This breaks the binding: **organization that authenticated == repository that is written**. This is the exact class of flaw described in the analog report — the value/field actually used to gate/authorize an action (here, "was this payload legitimately signed for the org that owns the object being changed") diverges from the field used to compute the value that is authenticated (here, `owner.login` used for secret selection vs. `full_name` used for the actual write).

### Impact Explanation
If more than one GitHub organization/app is configured in `secrets.github` (the documented multi-org schema — see `config/secrets.development.shopify.yml`, `test/dummy/config/secrets_double_github_app.yml`), and at least one of them has no `webhook_secret` configured (a documented, supported configuration — `webhook_secret: # nil`), an unauthenticated external attacker can forge webhook deliveries that:
- Trigger `stack.sync_github` for arbitrary stacks belonging to a different, "protected" organization (`PushHandler`).
- Archive/unarchive review stacks, or manipulate pull-request-driven provisioning, for repositories under a different organization (`OpenedHandler`, `ClosedHandler`, `ReopenedHandler`, `UnlabeledHandler`, `LabelCapturingHandler`, all of which resolve their target purely from `repository.full_name`).

This can lead to unauthorized state changes (deploy/rollback-adjacent sync triggers, stack archival) on repositories outside the org the attacker is nominally authorized to send webhooks for — an unauthorized action across the organization/repository trust boundary, matching the report's "cross-repository writes / unauthorized deploy" impact class.

### Likelihood Explanation
Requires: (1) the host application configured with the documented multi-organization `secrets.github` schema, and (2) at least one configured organization with a blank `webhook_secret` (explicitly supported/documented) or a webhook secret known to the attacker for one org while another org is the actual target. Both preconditions are plausible in real deployments since the multi-org schema and optional webhook secret are first-class, documented features, not misconfiguration outside the app's intended use. No repository write access, session, or API token is needed — only the ability to send an HTTP POST to `/webhooks`.

### Recommendation
Do not select the verification key using a payload field that is independent from the field used to identify the object being acted upon. Concretely:
- Derive the organization used for signature verification and the organization/repository used for handler dispatch from the *same* field (e.g., always derive both from `repository.full_name`'s owner segment, or always from `repository.owner.login`), and reject the request if they don't match.
- Alternatively, verify the signature against every configured organization's secret (or require it to match the org owning `repository.full_name`) rather than trusting `repository.owner.login`/`organization.login` picked out of the unverified body to select a single verifier.
- Reconsider allowing `webhook_secret` to be blank in production/multi-org configurations, since a blank secret causes `verify_webhook_signature` to accept any payload unconditionally.

### Proof of Concept
Given a Shipit instance configured with two organizations, `weak-org` (no `webhook_secret`) and `victim-org` (has stacks/repositories configured), an attacker sends:

```
POST /webhooks
X-Github-Event: push
X-Hub-Signature: sha1=anything-or-omitted

{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "weak-org" },
    "full_name": "victim-org/protected-repo"
  }
}
```

- `verify_signature` computes `repository_owner` = `"weak-org"` [1](#0-0) , loads `Shipit.github(organization: "weak-org")`, and `verify_webhook_signature` returns `true` unconditionally because `weak-org` has no `webhook_secret` [7](#0-6) .
- The request passes into `Shipit::Webhooks.for_event('push')`, and `PushHandler#stacks` resolves stacks via `Repository.from_github_repo_name("victim-org/protected-repo")` [5](#0-4) , causing `stack.sync_github` to run against `victim-org`'s stack despite the request never being validated against `victim-org`'s webhook secret.

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
