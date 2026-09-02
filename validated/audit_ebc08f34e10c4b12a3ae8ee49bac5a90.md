### Title
Webhook signature verification selects the GitHub App secret from an attacker-controlled field that is decoupled from the repository the payload actually targets - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` picks which GitHub App config (and thus which `webhook_secret`) to authenticate an inbound webhook against by reading `repository.owner.login` (or `organization.login`) straight out of the *unauthenticated* JSON body. Every downstream `Handler` (e.g. `PushHandler`, `StatusHandler`) instead resolves the target `Stack`/`Repository` using a different field of the same body, `repository.full_name`. Nothing binds these two attacker-supplied fields together, so the organization whose credentials are used to "authenticate" the request can differ from the repository that is actually acted upon.

### Finding Description
`verify_signature` derives the verification org purely from request body content, before any authentication has occurred: [1](#0-0) [2](#0-1) 

The selected `GitHubApp` instance's `webhook_secret` is used to HMAC-verify the raw body: [3](#0-2) 

Critically, `verify_webhook_signature` **unconditionally returns `true` if `webhook_secret` is blank/nil** for the selected organization — and per the engine's own setup docs, the webhook secret is explicitly optional per-organization:
`docs/setup.md` — "Webhook secret (optional): ... `webhook_secret: # nil`" and the multi-org example block where each org has its own independent `webhook_secret`.

Once `head(422) unless verified` passes (or is skipped because of the nil-secret shortcut), `create` dispatches the *entire, still-untrusted* JSON body to handlers: [4](#0-3) 

Every handler resolves its target `Repository`/`Stack` using `repository.full_name`, a field completely independent of the one used for signature-org selection: [5](#0-4) [6](#0-5) 

`PushHandler`, for example, uses this to look up stacks and trigger a GitHub sync for whatever repository `full_name` says, regardless of which org's secret gated the request: [7](#0-6) 

**The broken equality**: the engine implicitly assumes
`organization that authenticated the webhook (repository.owner.login / organization.login)` == `repository that the handler writes to (repository.full_name)`.
Because both sides are independent, attacker-controlled fields inside the same unauthenticated JSON body, and the code never cross-checks them, an attacker can set `repository.owner.login` to any organization configured on the instance that has no `webhook_secret` set (a documented, supported, non-privileged configuration state — see `docs/setup.md`'s multi-org example, where each org's `webhook_secret` is independently optional), while setting `repository.full_name` to point at a *different* organization's repository/stack. The signature check trivially passes (`return true unless webhook_secret`) for the org with no secret, yet the actual side effects (triggering `Repository.from_github_repo_name(...).stacks`, `stack.sync_github`, `Commit#create_status_from_github!`, etc.) are applied to the unrelated target repository named in `full_name`.

This is a direct structural analog of the reported Velodrome issue: a value used to gate/limit an action (`tnsl` reduction gated on the wrong epoch boundary; here, the *authentication org* gated on an unverified field) is computed from data that is not the same data the downstream logic actually consumes/acts on (`rewardReserve` rollover amount; here, the *actual target repository*), breaking an implicit equality the code relies on for correctness/safety.

### Impact Explanation
An unprivileged network attacker (no `ApiClient` token, no GitHub credentials, no repository access) can send a raw POST to the public `/webhooks` endpoint with a forged JSON body and pass signature verification for free as long as any single organization configured on the Shipit instance omits `webhook_secret` (an explicitly documented, legitimate, non-privileged configuration). Because handler dispatch resolves the acted-upon repository from an unrelated, unverified field (`repository.full_name`), the attacker can:
- Force `PushHandler` to trigger `GithubSyncJob`/`stack.sync_github` against any `Stack` in the instance whose repository they can name, feeding an arbitrary `expected_head_sha`.
- Force `StatusHandler` to inject fake commit statuses (`commit.create_status_from_github!`) for arbitrary commits/stacks, which can influence deploy-safety gating (`Commit#deployable?`) used elsewhere to decide whether an "unauthorized deploy" is permitted, including via `continuous_deployment`.

This crosses a real authentication boundary (bypassing per-organization webhook authentication) and can cascade into deploy-safety-relevant state corruption on repositories/stacks the attacker has no access to, matching the "unauthorized deploy" / "authentication bypass" impact class.

### Likelihood Explanation
Requires only:
1. Network access to the public `/webhooks` endpoint (always exposed, unauthenticated by design pending signature check).
2. The Shipit instance operator having configured at least one GitHub organization without a `webhook_secret` — an officially documented, supported, non-privileged configuration (single or multi-org setups per `docs/setup.md`).

No secrets, tokens, or GitHub write access are needed to exploit divergence between the org used for auth and the repository acted upon; the only "gate" the attacker must clear (a nil `webhook_secret`) is bypassed by design, not by breaking cryptography. This makes exploitation practical whenever this common, documented configuration exists.

### Recommendation
- Do not select the verification `webhook_secret` from unauthenticated payload fields at all. Instead, verify the signature against *every* configured organization's secret (or require the caller to identify the org via a trusted, out-of-band channel, e.g. URL path/subdomain per org) before trusting any field of the body.
- After signature verification succeeds for organization `O`, enforce that `repository.full_name`'s owner segment equals `O` (or `organization.login` equals `O`) before dispatching to handlers; reject (422) on mismatch.
- Treat a missing/blank `webhook_secret` for one organization as isolated: it must never be usable to authenticate payloads whose `repository`/`organization` claims to be a different, secret-protected organization.

### Proof of Concept
Assume the Shipit instance has two configured orgs: `OrgB` (no `webhook_secret` configured — supported per docs) and `OrgA` (has a stack `OrgA/victim-repo`, `webhook_secret` set and unknown to the attacker).

```
POST /webhooks HTTP/1.1
X-Github-Event: push
X-Hub-Signature: sha1=0000000000000000000000000000000000000000   (arbitrary/garbage)
Content-Type: application/json

{
  "ref": "refs/heads/master",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "owner": { "login": "OrgB" },
    "full_name": "OrgA/victim-repo"
  }
}
```

- `repository_owner` resolves to `OrgB` (`app/controllers/shipit/webhooks_controller.rb:59-62`).
- `Shipit.github(organization: 'OrgB')` has `webhook_secret` blank → `verify_webhook_signature` returns `true` unconditionally (`lib/shipit/github_app.rb:76-77`), regardless of the bogus `X-Hub-Signature`.
- `create` dispatches the full body to `PushHandler` (`app/controllers/shipit/webhooks_controller.rb:10-15`).
- `PushHandler#stacks` resolves via `payload.dig('repository','full_name')` = `"OrgA/victim-repo"` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`), matching the real, protected `OrgA` stack, and triggers `stack.sync_github(expected_head_sha: 'deadbeef...')` (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`) — despite `OrgA`'s webhook secret never having been checked.

Note: I could not execute this against a running instance (no filesystem/terminal access in this mode); the trace above is derived directly from reading the cited source and is limited to what static analysis of the referenced files can establish — a Devin session with the actual app running would be needed to confirm runtime behavior (e.g., exact interaction with `ContinuousDeliveryJob`/deploy-safety gating) end-to-end.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
