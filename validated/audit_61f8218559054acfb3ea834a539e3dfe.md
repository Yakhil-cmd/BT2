### Title
Webhook signature verification is bound to `repository.owner.login`/`organization.login` while the write path acts on the untrusted `repository.full_name` field, enabling cross-repository status/webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App (and thus which HMAC secret) is used to authenticate an inbound webhook based on the attacker-controlled JSON fields `repository.owner.login` / `organization.login`. Every handler that actually mutates state, however, resolves the target `Stack`/`Commit` using a *different* attacker-controlled field, `repository.full_name` (or, in the case of `StatusHandler`, no repository scoping at all). Nothing ties the organization whose secret validated the signature to the repository the handler subsequently writes to, breaking the binding "organization that authenticated == repository that is written."

### Finding Description
`WebhooksController#verify_signature` derives the signing organization purely from the untrusted JSON body: [1](#0-0) [2](#0-1) 

It then calls `Shipit.github(organization: repository_owner)` and verifies the raw body against that organization's `webhook_secret`. Critically, `GitHubApp#verify_webhook_signature` trivially returns `true` when no `webhook_secret` is configured for that organization: [3](#0-2) 

`webhook_secret` is explicitly documented as optional per organization (`docs/setup.md`), so a Shipit multi-tenant instance can legitimately have an organization entry with no secret configured. Any request whose `repository.owner.login` (or `organization.login`) resolves to such an organization passes `verify_signature` unconditionally, regardless of the rest of the payload's contents.

Once past this check, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the full, attacker-controlled `params` to handlers. These handlers resolve the actual `Repository`/`Stack` to act on using the *separate* field `repository.full_name`: [4](#0-3) 

`PushHandler` uses this to enqueue a sync for any stack matching that full name and branch: [5](#0-4) 

Worse, `StatusHandler` doesn't scope by repository at all — it matches purely on commit SHA across the entire `commits` table: [6](#0-5) 

So an attacker who can get `verify_signature` to pass for *any* onboarded organization (e.g., one with no `webhook_secret` configured, or one they legitimately administer) can forge a `status` webhook whose `sha` matches a commit belonging to a completely unrelated stack/organization, and set arbitrary `state`, `description`, `target_url`, and `context` on it — none of these are re-validated against the organization that authenticated the request.

### Impact Explanation
Commit statuses drive Shipit's deploy safety gating (blocking statuses / CI checks referenced by `deployment_checks_passed?` and merge-queue validation). Forging a passing status on a victim stack's commit lets an unrelated, unprivileged webhook sender fake "green CI" for a repository they do not own, directly enabling an **unauthorized deploy** or bypass of merge-queue safety checks — one of the explicitly listed Critical/High impacts. This also generalizes to `PushHandler`, which will happily enqueue `GithubSyncJob` for any stack whose `full_name` is supplied, regardless of which organization's secret actually authenticated the request.

### Likelihood Explanation
Requires the target Shipit deployment to run in the multi-tenant `github` config mode (`github_app_config`) with at least one organization lacking a `webhook_secret` — a state explicitly permitted by the documented setup (`docs/setup.md` marks `webhook_secret` as optional). Given that configuration, exploitation needs only a single unauthenticated HTTP POST to `/webhooks`; no GitHub credentials, `ApiClient` token, or Shipit session are required.

### Recommendation
Bind the authenticated organization to the write path: after computing `repository_owner` for signature verification, re-derive/validate `repository.full_name`'s owner against that same organization before dispatching to handlers, and reject mismatches. Additionally, scope `StatusHandler` (and any other handler that doesn't already) to the repository/stack whose owning organization matches the one that authenticated the signature, rather than matching purely on commit SHA. Consider also disallowing organizations from being configured without a `webhook_secret` in multi-tenant mode, since its absence effectively disables authentication for that organization's traffic.

### Proof of Concept
1. Deploy Shipit in multi-org GitHub App mode with organizations `no-secret-org` (no `webhook_secret` configured) and `victim-org` (has a real stack/commit synced).
2. Send:
```
POST /webhooks
X-Github-Event: status
Content-Type: application/json

{
  "repository": { "owner": { "login": "no-secret-org" }, "full_name": "no-secret-org/whatever" },
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/required-check",
  "description": "forged",
  "target_url": "https://example.com"
}
```
3. `verify_signature` resolves `Shipit.github(organization: "no-secret-org")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally regardless of the (absent/garbage) `X-Hub-Signature` header.
4. `StatusHandler#process` matches `Commit.where(sha: params.sha)` — the victim's commit — and creates a fabricated "success" status on it, even though the request was never authenticated for `victim-org`.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
