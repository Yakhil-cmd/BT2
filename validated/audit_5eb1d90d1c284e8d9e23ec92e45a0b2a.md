### Title
Webhook signing key is selected by `repository.owner.login`, but the handler acts on the unrelated `repository.full_name` field — allowing cross-organization/cross-repository writes - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks the GitHub App configuration (and thus the webhook secret) to validate a payload against using one field of the untrusted JSON body — `repository.owner.login` (or `organization.login`) — while the handler that subsequently *acts* on the same payload resolves the target `Stack`/`Repository` from a **different** field, `repository.full_name`. Nothing ties these two fields together, so the "organization whose secret authenticated the request" is not enforced to equal "the repository the handler writes to." This is the same class of bug as the FloatCapital finding: a value is checked against one state/field, but the action executed later relies on a different, unchecked field of the same request.

### Finding Description
`WebhooksController#verify_signature` resolves which app/secret to check against purely from the attacker-supplied JSON body: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` explicitly treats an unset `webhook_secret` as automatically valid: [3](#0-2) 

Shipit supports (and documents) multiple GitHub organizations, each with its own, individually optional `webhook_secret`: [4](#0-3) [5](#0-4) 

Once signature verification passes, the actual handler that mutates state resolves its target repository from a *different* JSON field than the one used to select the verifying organization: [6](#0-5) [7](#0-6) 

The equality that should hold but is never checked is:
`organization(secret used to verify signature) == owner(repository.full_name acted on by the handler)`

Because the `WebhooksController` has no authentication other than `verify_signature` (it is a bare `ActionController::Base`, unlike the rest of the engine which requires `Shipit::Authentication`), and because an org with no configured `webhook_secret` makes `verify_webhook_signature` return `true` unconditionally, any unprivileged remote attacker can:
1. Send a POST directly to `/webhooks` (this endpoint is not restricted to GitHub's IPs and requires no session/API token).
2. Set `repository.owner.login` (or `organization.login`) to the name of any org configured in Shipit that has **no** `webhook_secret` set (webhook secrets are explicitly optional per `docs/setup.md`), which makes `verify_signature` pass with any (or no) `X-Hub-Signature`.
3. Set `repository.full_name` to `<victim-org>/<victim-repo>` — a repository belonging to a completely different, secured organization managed by the same Shipit instance.
4. `Shipit::Webhooks.for_event(event)` dispatches to the handler, e.g. `PushHandler`, which resolves the target via `Repository.from_github_repo_name(payload.dig('repository', 'full_name'))` — i.e., the victim org's stacks — and acts on them (`stack.sync_github(expected_head_sha: params.after)`), even though the signature check never validated anything about that organization/repository.

This directly breaks the "organization that authenticated versus the repository that is written" binding called out as an allowed analog class.

### Impact Explanation
An attacker with no relationship to a victim organization/repository can force Shipit to execute repository-scoped webhook logic against that victim's stacks by exploiting a *different, unrelated* organization's lack of (or leaked) webhook secret. This is a cross-repository/cross-organization write: the handler layer (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, pull-request handlers, `MembershipHandler`) all inherit the same `Handler#stacks`/`repository_name` resolution and can be pointed at arbitrary stacks this way, letting an attacker trigger GitHub syncs, commit-status/check-run driven CI gating, and PR-driven review-stack lifecycle actions (open/close/label/assign) on a repository they do not control. Because Shipit's continuous-delivery gating relies on ingested commit status/check-run state (`ci.require`, `deployable?`), spoofing status/check-suite payloads against a victim stack under this same binding gap could influence deploy gating for that stack — an unauthorized-ship class impact.

### Likelihood Explanation
This requires only that the Shipit deployment be configured with more than one GitHub organization (an explicitly documented, supported configuration) where at least one configured organization has no `webhook_secret` (also explicitly documented as "optional"). No credentials, sessions, or API tokens are required — the `/webhooks` endpoint is intentionally unauthenticated aside from the HMAC check, and the HMAC check itself is bypassable for any org without a configured secret. Any operator following the documented "webhook secret (optional)" guidance for even one org exposes every other org's repositories to this cross-binding issue.

### Recommendation
- Reject webhook payloads whose `repository.owner.login` does not match the owner embedded in `repository.full_name` (or `organization.login` for org-level events).
- Do not allow a missing `webhook_secret` on any configured organization to short-circuit signature verification when the engine is configured for multiple organizations; make `webhook_secret` mandatory, or scope the "no secret configured" bypass to installations with exactly one organization/no ambiguity.
- Bind the handler's repository/stack resolution to the same identity value that produced a successful signature (i.e., verify against the specific organization derived consistently from a single, signed field before any handler executes).

### Proof of Concept
Assume `config/secrets.yml` configures two orgs: `no-secret-org` (no `webhook_secret`) and `victim-org` (real, secret-protected stacks managed in Shipit).

```
POST /webhooks HTTP/1.1
X-Github-Event: push
Content-Type: application/json
(no valid X-Hub-Signature required)

{
  "repository": {
    "owner": { "login": "no-secret-org" },
    "full_name": "victim-org/victim-repo"
  },
  "ref": "refs/heads/main",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
}
```

- `verify_signature` computes `repository_owner = "no-secret-org"` [2](#0-1)  → `Shipit.github(organization: "no-secret-org").verify_webhook_signature(...)` returns `true` unconditionally because that org has no secret [8](#0-7) .
- `PushHandler#process` resolves stacks via `Repository.from_github_repo_name("victim-org/victim-repo")` [9](#0-8)  and calls `stack.sync_github(expected_head_sha: "deadbeef...")` on the victim's stacks [10](#0-9)  — despite the attacker having no relationship to `victim-org` whatsoever.

Note: I was able to fully confirm this root-cause chain for `PushHandler`; I could not read `status_handler.rb`/`check_suite_handler.rb` contents in this session (index/tool limits), so the additional CI-status-spoofing/"unauthorized ship" amplification described above is a reasonable inference from the shared `Handler` base class and README's CI-gating documentation, not independently verified line-by-line — this should be confirmed against those files directly.

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

**File:** docs/setup.md (L26-30)
```markdown
  - Homepage URL: The URL where Shipit will be deployed, e.g. `https://example.com`.
  - User authorization callback URL: It must be set to `<homepage>/github/auth/github/callback`, e.g. `https://example.com/github/auth/github/callback`.
  - Setup URL: Leave it empty.
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-24)
```ruby
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

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
```
