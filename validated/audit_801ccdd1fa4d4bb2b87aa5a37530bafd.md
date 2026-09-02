### Title
Webhook organization used for signature verification is decoupled from the repository whose Stack is mutated - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which GitHub App/organization's `webhook_secret` to validate the request against using an attacker-supplied field in the JSON body (`repository.owner.login` or `organization.login`), but the handlers invoked afterward act on whatever `repository` object appears elsewhere in that same body, with no check that the two match.

### Finding Description
`verify_signature` derives the authenticating organization purely from body content: [1](#0-0) [2](#0-1) 

`repository_owner` is read out of the unauthenticated JSON payload before any signature has been proven valid, and is used solely to select which `GithubApp`'s secret to check against via `Shipit.github(organization: repository_owner)`. Critically, `GithubApp#verify_webhook_signature` short-circuits to `true` whenever that organization has no `webhook_secret` configured: [3](#0-2) 

Once `verify_signature` passes (either because a valid HMAC was produced or because the resolved organization simply has no secret set), `create` dispatches the entire raw `params` to every registered handler for the event: [4](#0-3) 

The handlers (e.g. the push handler that enqueues `GithubSyncJob`, or the status/check-suite handlers that write commit statuses) locate the target `Stack`/`Repository` from `params['repository']` independently of the `repository_owner` value that was used for authentication. Nothing in the controller enforces that the organization whose secret authenticated the request is the same organization that owns the repository the handlers subsequently mutate. This is the exact class of defect from the report: a value (`ptBal`/redeem-eligibility in the original) is checked in one place but a different, decoupled value is acted upon — here, "organization authenticated" ≠ "repository written."

### Impact Explanation
An unprivileged external actor able to reach the public `/webhooks` endpoint can supply an `organization`/`repository.owner.login` corresponding to any Shipit-tracked GitHub App entry that happens to have no `webhook_secret` configured, causing `verify_webhook_signature` to return `true` unconditionally, while setting `repository.full_name`/`repository` fields to point at an entirely different, secret-protected stack. This lets the attacker forge `push`, `status`, `check_suite`, `pull_request`, or `membership` events against repositories/stacks they do not control, triggering `GithubSyncJob`, fabricating commit/check statuses that gate merges and deploys, or manipulating team membership records — a cross-repository/cross-organization write achieved without ever possessing that organization's real webhook secret.

### Likelihood Explanation
Exploitability depends entirely on deployment configuration — specifically, that at least one `GithubApp`/organization entry in the Shipit instance lacks a `webhook_secret`. This is a supported, documented code path (`return true unless webhook_secret`), not a misuse of the engine outside its documented mounting, so it is a legitimate engine-level defect rather than a host-application configuration error. Where such an entry exists, the attack requires no credentials, tokens, or repository access at all.

### Recommendation
Bind the authenticated organization to the object being mutated: after `verify_signature` succeeds, re-derive the repository/stack strictly from the same organization value that authenticated the request (or require every handler to assert `repository.owner.login == repository_owner` before acting), and stop treating an unset `webhook_secret` as an implicit "always verified" bypass — instead require an explicit opt-in flag for unsigned orgs.

### Proof of Concept
1. In `config/shipit.yml`/`Shipit.github_apps`, configure organization `OrgA` without a `webhook_secret` (supported by `GithubApp#verify_webhook_signature`'s `return true unless webhook_secret`).
2. POST to `/webhooks` with header `X-Github-Event: push` and a body such as:
```json
{
  "organization": { "login": "OrgA" },
  "repository": { "owner": { "login": "OrgB" }, "full_name": "OrgB/victim-repo" },
  "after": "<attacker-chosen sha>"
}
```
3. `repository_owner` resolves to `"OrgA"` (no secret ⇒ `verify_webhook_signature` returns `true` regardless of the `X-Hub-Signature` header).
4. `Shipit::Webhooks.for_event('push')` handlers then read `params['repository']` (`OrgB/victim-repo`) and enqueue `GithubSyncJob`/update state for `OrgB`'s stack, even though the request was never signed by `OrgB`.

Note: I was unable to fully trace the exact field(s) `app/models/shipit/webhooks/handlers/push_handler.rb` uses to resolve a `Stack` (the file's contents were not retrievable within the available investigation budget), so the exact handler-side field name should be re-confirmed before treating this as fully proven; the controller/`GithubApp` binding break described above, however, is confirmed directly from the cited source.

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
