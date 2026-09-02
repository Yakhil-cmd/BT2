### Title
GitHub webhook signature verification is keyed off an attacker-controlled `repository.owner.login` field and fails open when that organization has no `webhook_secret`, letting an unauthenticated caller forge events (push/status/membership) for **any** repository tracked by the engine - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
This is the same class of bug as the AI Arena `reRoll` finding: a check is performed using one identifier while the state-mutating operation is keyed on a *different*, unverified identifier from the same request. In AI Arena, `maxRerollsAllowed`/generation were checked with an attacker-supplied `fighterType` that never had to match the NFT's real type. In Shipit, `WebhooksController#verify_signature` decides *which organization's secret to validate against* using `repository_owner`, a value read straight out of the untrusted JSON body, while the event handlers that actually create/modify records (`Repository`, `Stack`, `Commit`, `Status`, `Task`, `Team`, `User`, …) key off a *different* field, `repository.full_name`, that is never cross-checked against the field used for signature selection.

### Finding Description
`WebhooksController` runs signature verification like this: [1](#0-0) 

`repository_owner` is derived purely from the JSON payload the caller supplies: [2](#0-1) 

That value is used only to pick *which* GitHub App / organization config (and therefore which `webhook_secret`) to verify the HMAC against: [3](#0-2) 

Critically, `verify_webhook_signature` fails open when the selected organization has no configured `webhook_secret`:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
``` [4](#0-3) 

Once "verified", the actual event handlers resolve the target repository/stack from a **completely different** payload field, `repository.full_name`, with no relationship to `repository_owner`/`organization.login` used above: [5](#0-4) 

Equality that should hold but doesn't:
`organization(secret used to authenticate the request) == repository.owner(of the repository the handlers actually write to)`

Before/after the attacker's request:
- Before: no secret is verified for the *victim* repository at all; the engine trusts whichever org name the attacker puts in `repository.owner.login`/`organization.login`.
- After: if that named organization is configured in this Shipit instance but has a blank/unset `webhook_secret`, `verify_webhook_signature` returns `true` unconditionally, and the handler is invoked with attacker-chosen `payload`, including an arbitrary `repository.full_name` pointing at any repository/stack actually onboarded to this Shipit instance (e.g. a production stack).

This lets an unauthenticated caller (no `ApiClient` token, no Shipit session, no GitHub credentials for the victim repo) that merely knows the name of *one* configured-but-secret-less organization forge:
- `push` events → enqueue `GithubSyncJob` for the victim stack, syncing/overwriting commit state,
- `status`/`check_suite` events → create fabricated `Status`/check-run records for arbitrary SHAs, which feed `Commit#deployable?` and CI-gating logic used by manual and continuous deploys,
- `membership`/`team` events → create arbitrary `Team`/`User` records on the fly (as shown by `test/controllers/webhooks_controller_test.rb`).

### Impact Explanation
This crosses the "organization that authenticated versus the repository that is written" trust boundary explicitly called out as in-scope, and lands squarely in the Critical bucket: an unauthorized entity can perform cross-repository writes and manipulate commit/CI state that gates unauthorized deploys, without ever holding an `ApiClient` token, Shipit session, or write access to the targeted repository.

### Likelihood Explanation
Requires only that the deployment configure at least one GitHub organization/App without a `webhook_secret` (a supported, non-error configuration state - `@webhook_secret = @config[:webhook_secret].presence`, silently `nil` if omitted) and that the attacker know or guess that organization's login name; no other credential or repository access is needed.

### Recommendation
- Derive the signing organization strictly from the delivering GitHub App/installation context, never from attacker-supplied JSON fields.
- Make `verify_webhook_signature` fail closed when `webhook_secret` is blank instead of returning `true`.
- Cross-check that `repository.full_name`'s owner matches the organization used to authenticate the delivery before dispatching to handlers.

### Proof of Concept
1. Identify (or configure, for local reproduction) an organization `org-no-secret` in `Shipit.github_apps` config that omits `webhook_secret`.
2. Send, without any Shipit credentials:
```
POST /github/webhooks
X-Github-Event: push
Content-Type: application/json

{
  "organization": { "login": "org-no-secret" },
  "repository": { "full_name": "victim-org/production-repo", "owner": { "login": "org-no-secret" } },
  "ref": "refs/heads/main",
  "after": "<any sha already known to Shipit>"
}
```
3. `verify_signature` resolves `repository_owner` to `org-no-secret`, calls `Shipit.github(organization: 'org-no-secret')`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` regardless of (or absent) `X-Hub-Signature`.
4. `Shipit::Webhooks.for_event('push')` handlers run using `payload.dig('repository', 'full_name') == 'victim-org/production-repo'`, enqueuing a `GithubSyncJob` for that real, unrelated stack - fully attacker-controlled, with zero legitimate credentials for `victim-org`.

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
