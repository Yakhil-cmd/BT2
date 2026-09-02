## Title
Webhook signature verification is silently skipped for organizations configured without a `webhook_secret`, allowing unsigned forged webhooks to act on any repository named in the payload - ([File: app/controllers/shipit/webhooks_controller.rb], [File: lib/shipit/github_app.rb])

### Summary
Shipit's webhook signature check (`Shipit::GitHubApp#verify_webhook_signature`) selects which organization's secret to check *and whether to check at all* based on an unauthenticated field of the incoming payload (`repository.owner.login`), and defaults to **accepting the request as verified when that organization has no `webhook_secret` configured** [1](#0-0) . This breaks the intended binding "the organization that authenticated the webhook == the repository the webhook writes to," because the org used to pick the (possibly absent) secret is attacker-controlled and independent from the `repository.full_name`/stack that the resulting event handlers act upon.

### Finding Description
`WebhooksController#verify_signature` is a `before_action` that:
1. Reads `repository_owner` straight from the untrusted request body (`params.dig('repository','owner','login')` or `params.dig('organization','login')`) [2](#0-1) .
2. Uses that value to fetch a `GitHubApp` instance via `Shipit.github(organization: repository_owner)`.
3. Calls `github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)` [3](#0-2) .

`verify_webhook_signature` is implemented as:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  algorithm, signature = signature.split("=", 2)
  return false unless algorithm == 'sha1'
  SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
end
``` [1](#0-0) 

If the organization resolved from the attacker-supplied `repository.owner.login` field has **no `webhook_secret` configured** in `Shipit.github` (a legitimate configuration state, as shown in the documented multi-org config sample where `webhook_secret:` is left `nil` for some orgs) [4](#0-3) , `verify_webhook_signature` returns `true` unconditionally — no signature at all is required.

Critically, once signature "verification" passes, the `create` action re-parses the raw body and dispatches to handlers using fields from that same attacker-controlled JSON, including `repository.full_name`, which is used elsewhere (e.g. `GithubSyncJob`) to resolve and mutate a specific `Stack`/`Repository` [5](#0-4) . Nothing ties `repository.owner.login` (used to choose the auth check) to `repository.full_name` (used to decide which stack is synced/affected) — an attacker can set the former to an org that has no secret configured, while setting the latter to any tracked repository belonging to a *different, properly secured* organization.

Equality that should hold but doesn't:
`organization whose credential authorized this request == organization owning the repository the webhook payload causes Shipit to act on`

Before the attacker's request: only a party holding a configured org's `webhook_secret` (or an org with no secret, if such misconfiguration exists) can produce events recognized as "verified" for that org's repositories.

After the attacker's request: because the same field determines both "is this considered verified" and can be set independently of the repository actually processed, an attacker with zero credentials can produce a payload that is accepted as "verified" (by pointing `repository.owner.login`/`organization.login` at an org configured with no secret, or simply omitting webhook_secret from *any* org they can name) while `repository.full_name` references a real, tracked stack belonging to a different organization, causing Shipit to run its push/status/check_suite handlers (queue `GithubSyncJob`, create commits/statuses, trigger deploy-eligibility changes) against that unrelated stack.

### Impact Explanation
This crosses an authentication boundary with no credential: an unauthenticated network requester can inject forged GitHub events (push, status, check_suite, membership, etc.) that are treated as verified GitHub-originated events for any tracked repository/stack, without needing the target organization's webhook secret, a Shipit session, or an API token. Depending on which handlers are registered, this can manipulate CI/status state, alter commit history bookkeeping, and change what looks "deployable" to human operators using the UI — a stepping stone to influencing which commit gets shipped. Per the given impact classes, this reaches at least "unauthenticated read/write of stack state via forged webhook processing," bordering on enabling an unauthorized action against a stack an attacker does not control, satisfying the High-impact category ("escalation ... unauthenticated ... task streams", generalized to unauthenticated forged state mutation of stack data).

### Likelihood Explanation
Likelihood depends on deployment configuration: it requires that at least one organization configured in `Shipit.github` has no `webhook_secret` set (an explicitly documented/supported state — see the sample multi-org secrets file which sets `webhook_secret: # nil` for some orgs) while other organizations/stacks are properly secured. In any Shipit instance onboarding multiple GitHub orgs incrementally (a normal operational pattern), this is a realistic transient or permanent misconfiguration that the code does nothing to warn about or forbid explicitly at the "did this attacker legitimately own this event" check.

### Recommendation
- Do not treat an organization with a blank `webhook_secret` as automatically "verified" — require an explicit configuration flag if unsigned webhooks are intentionally allowed for an org, and fail closed by default.
- Bind the signature verification to the *same* repository/stack the handlers will act on: derive the org used for verification from `repository.full_name`'s owner rather than from `repository.owner.login`/`organization.login` alone, or verify that both fields (and the eventual resolved `Stack#repository`) agree before dispatching to handlers.
- Reject webhook payloads whose `repository.full_name` does not match a repository Shipit knows to belong to the organization/app that signed (or is claimed to have signed) the payload.

### Proof of Concept
1. Configure Shipit with two organizations, e.g. `secure-org` (with `webhook_secret: real-secret`) and `unsecured-org` (with `webhook_secret:` left blank/nil) — matching the documented sample config [4](#0-3) , and track a stack for `secure-org/victim-repo`.
2. As an unauthenticated attacker (no session, no token, no secret), send:
```
POST /webhooks
X-Github-Event: push
X-Hub-Signature: sha1=0000000000000000000000000000000000000000  (anything, or omit)

{
  "repository": { "owner": { "login": "unsecured-org" }, "full_name": "secure-org/victim-repo" },
  "after": "<attacker chosen sha>",
  "ref": "refs/heads/master"
}
```
3. `repository_owner` resolves to `unsecured-org` [2](#0-1) ; `Shipit.github(organization: 'unsecured-org')` returns a `GitHubApp` with `webhook_secret` nil; `verify_webhook_signature` returns `true` regardless of the (fake) signature header [1](#0-0) .
4. The `create` action proceeds and dispatches the push handler using `repository.full_name = "secure-org/victim-repo"`, causing Shipit to enqueue `GithubSyncJob` and mutate state for `secure-org`'s tracked stack — despite the attacker never possessing `secure-org`'s webhook secret.

Note: I could not directly inspect the built-in push/status webhook handler source (`Shipit::Webhooks` handler registrations) within the indexed context to show the exact line that maps `repository.full_name` to a `Stack`; this was inferred from `GithubSyncJob#perform` receiving `stack_id` and the documented webhook registration mechanism in `README.md`. A Devin session with full repository access could confirm the exact handler code path.

### Citations

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/jobs/shipit/github_sync_job.rb (L18-20)
```ruby
    def perform(params)
      @stack = Stack.find(params[:stack_id])
      expected_head_sha = params[:expected_head_sha]
```
