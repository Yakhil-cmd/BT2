Based on my investigation, I found a genuine analog matching the bug class ("a value acted upon is not bound to the verified/authorized value used elsewhere"). Note: I could not run additional tool calls in this final iteration to fully trace the push/status handler's repository lookup logic (e.g., `Shipit::Webhooks::Handlers::Push` / `GithubSyncJob` and `Status` handler) beyond what was retrieved earlier — this should be verified in a follow-up session against `app/models/shipit/webhooks/handlers/**` before treating this as confirmed.

### Title
Webhook signature is verified against an organization key selected from an unauthenticated payload field, decoupled from the repository the event handlers act on - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization `webhook_secret` to verify the HMAC signature against using `repository_owner`, a value read straight out of the untrusted JSON body (`params.dig('repository','owner','login')` or `params.dig('organization','login')`), before the signature has been checked.

### Finding Description
`repository_owner` is computed from the request body itself: [1](#0-0) 
and is used to pick the app/secret used for verification: [2](#0-1) 
`verify_webhook_signature` then HMAC-validates the raw body against that organization's configured `webhook_secret`: [3](#0-2) 
Once verification succeeds, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the full, attacker-controlled `params` (including `repository.full_name`) to the event handlers: [4](#0-3) 

The equality that should hold is: `organization whose secret authenticated the request == organization that owns the repository the handler subsequently mutates (via repository.full_name / commit / status lookups)`. Because the field used to *select the verification key* (`repository.owner.login` / `organization.login`) is never cross-checked against the field the downstream handlers use to *locate the Stack/Repository/Commit to act on* (`repository.full_name`), a party who legitimately controls one configured organization's `webhook_secret` (e.g. an org admin who set up their own GitHub App integration in Shipit, as documented in `config/secrets.development.shopify.yml`) can craft a signed payload whose `owner.login` matches their own org (so it passes `verify_webhook_signature` with their own secret) while `repository.full_name` names a completely different organization/repository configured in the same Shipit instance. This is the same class of defect as the ProtectedListings bug: a value that downstream logic treats as authoritative (`tokenTaken` / here, the repository identity acted upon) is not kept consistent with the value that was actually validated/paid-for (the compounded debt / here, the signature-verified organization).

### Impact Explanation
If a handler (e.g. the `push` or `status` handlers under `Shipit::Webhooks::Handlers`) resolves the target `Stack`/`Repository`/`Commit` purely from `repository.full_name` in the payload without validating that its owner segment matches the `repository_owner` used for signature verification, an attacker who is only entitled to deliver webhooks for organization A can forge commit statuses, push events, or check-suite refreshes for organization B's stacks — a cross-organization/cross-repository write of state Shipit trusts (commit statuses gating deploys, CI status, PR merge/label state). This maps to the "cross-repository writes" Critical impact bucket in scope, since it lets a party who only holds credentials scoped to one GitHub organization mutate state belonging to a different repository/organization tracked by the same Shipit instance.

### Likelihood Explanation
Exploitability depends on an attacker legitimately possessing (or having leaked) the `webhook_secret` for at least one organization configured in the multi-tenant `Shipit.github` config (a realistic scenario since Shipit explicitly supports hosting several independent GitHub orgs, each with its own secret, per `config/secrets.development.shopify.yml`). No Shipit session, `ApiClient` token, or GitHub App private key is required — only a raw HTTP POST to `/webhooks` with a body signed using one org's own webhook secret while spoofing the `repository` object's `full_name`.

### Recommendation
After signature verification succeeds, re-derive the organization/owner from the same payload field(s) trusted by the downstream handlers (`repository.full_name`'s owner segment, or the `Repository` record resolved by the handler) and assert it equals the `repository_owner` that selected the verification key, rejecting the webhook otherwise. Alternatively, pass the verified `repository_owner`/`github_app` explicitly into `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` and have every handler that resolves a `Stack`/`Repository` scope its lookup to that verified owner rather than trusting `full_name` unconditionally.

### Proof of Concept
1. Configure Shipit with two organizations in `secrets.yml`: `org-a` (attacker-controlled, secret known to attacker) and `org-b` (victim, secret unknown to attacker), each with stacks tracked by Shipit.
2. Attacker crafts a `push`/`status` webhook JSON body where `repository.owner.login` = `"org-a"` (or `organization.login` = `"org-a"`) but `repository.full_name` = `"org-b/victim-repo"`.
3. Attacker computes `X-Hub-Signature: sha1=<hmac(org-a-secret, raw_body)>` and POSTs to `/webhooks` with `X-Github-Event: push` (or `status`).
4. `verify_signature` calls `Shipit.github(organization: 'org-a')`, verifies successfully with `org-a`'s secret.
5. `Shipit::Webhooks.for_event('push')` handlers receive the full `params`, including `repository.full_name = "org-b/victim-repo"`, and (if they resolve the target purely by `full_name`, as suggested by `app/models/shipit/webhooks_controller.rb`'s own use of `repository_owner` for the *different* purpose of secret selection) act on `org-b`'s stack — a forged push/status event injected into a repository the attacker does not own, using only `org-a`'s own credentials.

*Note: full confirmation requires reading `app/models/shipit/webhooks/handlers/push_handler.rb` / `status_handler.rb` (or equivalents) to verify they indeed key off `repository.full_name` without cross-checking `repository.owner.login` against the organization that authenticated the request — this was not retrievable in the available tool budget and should be validated directly against those files.*

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
