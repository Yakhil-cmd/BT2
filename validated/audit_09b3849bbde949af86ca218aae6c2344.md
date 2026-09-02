### Title
Cross-organization webhook signature confusion allows unauthorized writes to stacks in other organizations - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to verify the inbound HMAC against using `repository_owner`, a value read straight out of the attacker-controlled JSON body (`params.dig('repository', 'owner', 'login')` or `params.dig('organization', 'login')`). The event handlers that actually act on the payload, however, resolve the target `Stack`/`Repository` using a *different* field of the same unauthenticated body: `payload.dig('repository', 'full_name')`. Because these two fields are never cross-checked against each other, and because multi-org Shipit deployments (as documented in `config/secrets.development.shopify.yml`) can configure some organizations with no `webhook_secret` at all, an attacker can craft a payload whose "authenticating" organization is one with no/known secret while the "acted upon" repository belongs to a completely different, protected organization/stack. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) 

### Finding Description
The bindings that should be equal but are not:

- **`organization` used for signature verification** = `params.dig('repository', 'owner', 'login')` / `params.dig('organization', 'login')` (`WebhooksController#repository_owner`, `app/controllers/shipit/webhooks_controller.rb:59-62`), used to pick `Shipit.github(organization: repository_owner)` and thus which `webhook_secret` HMAC to verify against (`app/controllers/shipit/webhooks_controller.rb:24-30`, `lib/shipit/github_app.rb:76-83`).
- **`repository` that is actually written to** = `payload.dig('repository', 'full_name')` (`Handler#repository_name`, `app/models/shipit/webhooks/handlers/handler.rb:36-38`), used by every concrete handler (e.g. `PushHandler`) to resolve `Repository.from_github_repo_name(repository_name)` and mutate the matching stacks.

`verify_signature` never checks that the organization used to select the signing secret is consistent with the `owner` embedded in `repository.full_name` that the handler later trusts, nor does it check that the resolved organization actually owns the target repository beyond string-matching an attacker-supplied field. Any part of the JSON body — including `repository.owner.login`, `organization.login`, and `repository.full_name` — is fully attacker-controlled prior to signature verification succeeding, since the raw body is only used *after* HMAC validation but the value used to pick the HMAC key is read from that same untrusted body before validation completes.

This mirrors the `BaseMilestone::onlyDeposited` bug class: a check (`balance >= allocation * recipients.length`) is performed against a value (`allocation * recipients.length`) that is not kept coherent with the value actually consumed (per-recipient state that changes independently). Here, the "authorization" check (HMAC verified using a key selected by `repository.owner.login`) is decoupled from the value actually consumed by the write operation (`repository.full_name`), breaking the equality: `organization authenticated == repository written`.

In the common single-organization Shipit installation (the default template configuration shown in `config/secrets.development.example.yml`), `webhook_secret` is frequently left blank (`# nil`), which makes `verify_webhook_signature` return `true` unconditionally (`lib/shipit/github_app.rb:76-77`: `return true unless webhook_secret`). Because `github_default_organization` collapses to `nil` for single-org configs (`lib/shipit.rb:170-188`), `repository_owner` has no bearing on which secret is used in that mode — but for a **multi-organization** deployment (the schema demonstrated in `config/secrets.development.shopify.yml`), each org can have an independently configured (or absent) `webhook_secret`, and `repository_owner` genuinely selects a different `GitHubApp`/secret per request.

### Impact Explanation
If any organization onboarded into a multi-org Shipit deployment has no `webhook_secret` configured (a supported, documented configuration), an attacker with no credentials can send an unauthenticated POST to `/webhooks` with:
- `X-Github-Event: push`
- Body: `{"repository": {"owner": {"login": "<org-with-no-secret>"}, "full_name": "<victim-org>/<victim-repo>"}, "ref": "refs/heads/<branch>", "after": "<attacker-chosen-sha>"}`

`verify_signature` resolves `Shipit.github(organization: "org-with-no-secret")`, whose `verify_webhook_signature` short-circuits to `true` because that org's `webhook_secret` is blank. The webhook is accepted, and `PushHandler` then resolves the target stack via `repository.full_name` = `<victim-org>/<victim-repo>`, invoking `stack.sync_github(expected_head_sha: params.after)` — an unauthorized write of arbitrary commit-sha state onto a stack belonging to an organization whose GitHub App/webhook secret is otherwise fully secured. This crosses the "organization authenticated versus the repository that is written" trust boundary and can trigger unauthorized deploy/sync behavior on a repository the attacker has no access to, meeting the High-impact bar (escalation across organizational boundaries via unauthenticated write to stack state).

### Likelihood Explanation
Requires only that the operator has configured at least two GitHub organizations in `secrets.github` (the multi-org schema is first-class and documented/shipped as `config/secrets.development.shopify.yml`) and that at least one of them has no `webhook_secret` set (also a documented/default state — `webhook_secret: # nil` appears in every example secrets file in the repo, including the single-org template). No credentials, session, or repository access are required — only knowledge that Shipit is multi-org and that one org lacks a signing secret, which can often be inferred externally (e.g., a smaller/less critical org onboarded without configuring a webhook secret).

### Recommendation
- Do not use attacker-supplied payload fields (`repository.owner.login`, `organization.login`) to select the verification secret without independently confirming, after verification, that the resolved organization actually owns the repository being acted upon (e.g., re-derive `repository_owner` from `Repository.from_github_repo_name(payload.dig('repository','full_name'))&.owner` and require it to match the org whose secret validated the signature).
- Require a non-blank `webhook_secret` for every configured organization in multi-org mode, or fail closed (reject silently-unsecured events) rather than defaulting to `true` when `webhook_secret` is blank.
- Bind the verified organization to the specific `Repository`/`Stack` resolved by the handler before performing any mutation, rejecting the event if they disagree.

### Proof of Concept
1. Configure Shipit with multi-org secrets similar to `config/secrets.development.shopify.yml`, where `orgA` has `webhook_secret: nil` and `orgB` (victim) has a real, secret `webhook_secret` and an installed stack tracking `orgB/victim-repo`.
2. Attacker sends, without any credentials:
```
POST /webhooks
X-Github-Event: push

{
  "repository": {
    "owner": { "login": "orgA" },
    "full_name": "orgB/victim-repo"
  },
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>"
}
```
3. `WebhooksController#verify_signature` calls `Shipit.github(organization: "orgA")`; since `orgA.webhook_secret` is blank, `verify_webhook_signature` returns `true` (`lib/shipit/github_app.rb:76-77`), so the request is accepted.
4. `Shipit::Webhooks.for_event('push')` dispatches to `PushHandler`, which resolves `stacks` via `Repository.from_github_repo_name("orgB/victim-repo")` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`) and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on the victim org's stack — a write triggered with zero valid authentication for `orgB`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

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
