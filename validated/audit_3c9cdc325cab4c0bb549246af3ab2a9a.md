### Title
Webhook signature verification uses an attacker-controlled organization field to select the secret, decoupling "authenticated organization" from "repository acted upon" - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to verify a payload against using a field taken from the *unverified* JSON body itself, rather than from any channel bound to the actual GitHub installation that delivered the request. This breaks the intended binding: `organization that authenticated == repository that is written`.

### Finding Description
`verify_signature` derives the organization used to pick the verification secret directly from the request body, before that body's authenticity has been established: [1](#0-0) [2](#0-1) 

`repository_owner` reads `params.dig('repository', 'owner', 'login')` (falling back to `organization.login`) straight out of the attacker-supplied JSON, and `Shipit.github(organization: repository_owner)` uses that value to look up which configured webhook secret to HMAC-verify the raw body against. `verify_webhook_signature` then does a keyed comparison against that specific organization's secret: [3](#0-2) 

Because a single Shipit instance can be configured with multiple organizations (see `config/secrets.development.shopify.yml` showing multiple orgs each with independent `webhook_secret`), and because the field selecting *which* secret to check is itself part of the unverified payload, an attacker who legitimately controls a GitHub App installation on **their own** configured organization (i.e., they know that org's `webhook_secret` because they administer that org's app installation) can compute a valid HMAC over an arbitrary payload — including a `repository.full_name` (or other repository identifiers used later by handlers such as `push_handler.rb` to resolve the target `Stack`) that names a *different, victim* repository. `verify_signature` will accept the signature because it only checks that the body was signed with *the secret belonging to whatever organization the body claims in `repository.owner.login`* — not that the organization whose secret was used actually owns the repository the payload claims to describe.

This is the direct analog of the reported bug class: a value is *acted upon* (here, the repository identity used to route the event to a `Stack` and process pushes/statuses/check-suites) that is not actually covered by the trust check that is supposed to bind it (here, the HMAC verification is keyed off the same untrusted field it is meant to protect, rather than an independent, trustworthy signal of the delivering organization).

### Impact Explanation
This lets an attacker who administers a GitHub App installation on any one of the organizations configured in `Shipit.github` forge webhook events (push, status, check_suite, etc.) that are processed by Shipit as if they came from a different organization/repository — enabling out-of-scope writes such as spoofed commit statuses, spoofed check-suite refreshes, or triggering `GithubSyncJob` against a `Stack` belonging to a repository the attacker does not control. Depending on which handlers key off `repository.full_name` vs the organization that actually signed the request, this crosses a repository trust boundary without repository write access, matching the "cross-repository writes" / unauthorized-action class of impact.

### Likelihood Explanation
Requires the attacker to control (be the admin/owner of) at least one GitHub App installation/org that is configured in the target Shipit instance's `Shipit.github` config — a realistic scenario for multi-tenant or multi-org Shipit deployments where different teams/orgs are onboarded to the same Shipit host. No Shipit session, `ApiClient` token, or repository write access is needed; only knowledge of one's own organization's `webhook_secret`, which the attacker legitimately possesses.

### Recommendation
Do not let the payload itself dictate which secret is used to verify the payload. Bind webhook verification to the actual GitHub App installation delivering the request (e.g. via a per-installation delivery ID looked up server-side, or by verifying against all configured secrets and independently cross-checking that the resulting authenticated organization matches the `repository.owner.login`/`full_name` the handlers will act on before dispatching). At minimum, after selecting the app/secret from `repository_owner`, re-validate that every repository-identifying field consumed by downstream handlers (`full_name`, `owner.login`) is consistent with the organization whose secret validated the signature, and reject mismatches.

### Proof of Concept
I could not fully trace the downstream `push_handler.rb`/`status_handler.rb` logic (file reads failed in the final iteration) to confirm whether `full_name` vs `owner.login` are cross-checked anywhere before a `Stack` lookup, so the exact reachable handler chain from a mismatched payload to a concrete `Stack` write is not fully verified — this should be confirmed by inspecting `app/models/shipit/webhooks/handlers/push_handler.rb`, `status_handler.rb`, and `check_suite_handler.rb` (and how they resolve `Stack`/`Repository` from the payload) via a follow-up session before treating this as fully proven end-to-end.

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
