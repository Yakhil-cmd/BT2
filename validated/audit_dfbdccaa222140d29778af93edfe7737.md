### Title
Webhook signature verification is bound to `repository.owner.login`, but the event is applied to whatever `repository.full_name` the payload claims — allowing cross-organization commit-status/push forgery when any configured GitHub App has no `webhook_secret` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which `GitHubApp` (and thus which HMAC secret) to validate a webhook against using `repository_owner`, a value read straight out of the untrusted JSON body. Once "verified", the payload is dispatched to handlers that resolve the target `Stack`/`Repository` using a **different field of the same untrusted body** (`repository.full_name`), with no check that the two agree. If a multi-org Shipit deployment has even one organization configured without a `webhook_secret` (an explicitly documented, optional setting), an attacker can craft a payload whose `repository.owner.login` is that unsecured org (bypassing signature verification for free) while `repository.full_name` points at a completely different, securely-configured organization's tracked repository — causing Shipit to act on that other repository's stacks with no valid signature at all.

### Finding Description
Signature verification: [1](#0-0) [2](#0-1) 

`repository_owner` is derived purely from the JSON body (`repository.owner.login` or `organization.login`) and is used to pick the `GitHubApp` instance whose secret should validate `X-Hub-Signature`: [3](#0-2) 

Critically, `verify_webhook_signature` **short-circuits to `true` whenever the selected organization has no configured `webhook_secret`** (`return true unless webhook_secret`). `webhook_secret` is an explicitly optional field in this engine's multi-org configuration schema (each org entry independently sets/omits it), so it is entirely realistic for one org among several configured orgs to have no secret while others do.

After the controller accepts the request (either genuinely verified, or trivially accepted because the claimed owner has no secret), it dispatches to handlers: [4](#0-3) 

Every handler resolves the actual `Repository`/`Stack` to mutate using a **separate** field pulled from the same attacker-controlled body — `repository.full_name` — with no cross-check against the `repository_owner`/org that was used for signature selection: [5](#0-4) 

This is exactly the DODO-style binding break described in the report: one field (`temp2`/the price-and-k used for the corner-case check) can degenerate to a trivial/zero value while a different field (`temp3`/the actual computation) is used downstream without re-validating the relationship between them. Here: the org used to *authenticate* the request (`repository.owner.login`) is never required to equal the org embedded in `repository.full_name` that is actually *written to* (Stack/Repository lookup, commit status writes, sync triggers, etc.) — matching the rule's named analog: "an organization that authenticated versus the repository that is written."

### Impact Explanation
An unprivileged attacker who knows (a) that a target Shipit instance is configured with multiple GitHub orgs and (b) that at least one of those orgs has no `webhook_secret` set, can:
- Forge a `push` event with `repository.owner.login` = the unsecured org and `repository.full_name` = `"<secured-org>/<tracked-repo>"`, causing `PushHandler` to call `stack.sync_github(expected_head_sha: ...)` against the secured org's real stacks without ever presenting a valid signature for that org.
- Forge a `status` (commit_status) event the same way to write a fabricated passing/failing `Status` onto a specific commit SHA of the secured org's repository (`StatusHandler` also inherits `Handler#stacks`/`#repository_name`), which can flip a commit's deployability/CI status as seen by Shipit and enable an unauthorized deploy of unreviewed/uncertified code.

This crosses the "unauthorized deploy" / "cross-repository writes" bar defined for Critical impact, achieved purely by controlling unauthenticated HTTP request bodies to `/webhooks` — no session, `ApiClient` token, `api_clients_secret`, or the target org's `webhook_secret` is ever needed.

### Likelihood Explanation
Requires only a documented, legitimate configuration state (one org among several with `webhook_secret` left blank/optional) plus a single unauthenticated HTTP POST to the public `/webhooks` endpoint. No credentials, GitHub App keys, or privileged accounts are needed — the attacker only needs to know that multi-org support is in use and that any one org lacks a secret (observable operationally, e.g., no HMAC ever demanded for that org's traffic, or simply by trial).

### Recommendation
Bind the two identities together instead of trusting them independently:
1. After selecting `repository_owner` for signature lookup, require that `payload.dig('repository', 'full_name')`'s owner segment (and/or `payload.dig('organization','login')`) is identical to `repository_owner` before dispatching to handlers; reject (422) on mismatch.
2. Do not allow `verify_webhook_signature` to silently return `true` when `webhook_secret` is blank for one org while other orgs are secured — either require all configured orgs to set a secret, or scope the "no secret configured" bypass so it can never authorize writes to a *different*, secured organization's repositories.
3. In `Handler#repository_name`/`#stacks`, cross-validate the resolved `Repository#owner` against the organization that passed signature verification, not merely against the free-form `full_name` string in the body.

### Proof of Concept
Given a `config/secrets.yml` with two orgs, `UnsecuredOrg` (no `webhook_secret`) and `SecuredOrg` (a real, tracked repo with `webhook_secret` set):

```
POST /webhooks
X-Github-Event: status
X-Hub-Signature: sha1=anything-or-omitted

{
  "sha": "<real commit sha of SecuredOrg/tracked-repo>",
  "state": "success",
  "context": "ci/attacker-forged",
  "repository": {
    "full_name": "SecuredOrg/tracked-repo",
    "owner": { "login": "UnsecuredOrg" }
  }
}
```

`WebhooksController#verify_signature` calls `Shipit.github(organization: "UnsecuredOrg")` → that app's `webhook_secret` is blank → `verify_webhook_signature` returns `true` unconditionally [6](#0-5) 
The request is accepted and forwarded to `StatusHandler`, which resolves the target repository via `payload.dig('repository', 'full_name')` = `"SecuredOrg/tracked-repo"` [5](#0-4) 
and writes a forged `Status` record against `SecuredOrg`'s real, secured repository/commit — despite the request never being validated by `SecuredOrg`'s `webhook_secret`.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```
