## StatusHandler#process trusts payload-derived `repository.full_name` independent of the org whose (optional) webhook secret authenticated the request - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to check against using `repository_owner`, a value read straight out of the untrusted JSON body (`params.dig('repository', 'owner', 'login')`). But `Shipit::Webhooks::Handlers::Handler#stacks`, used by every handler (push, status, check_suite), resolves the target repository from a *different* field of the same body: `payload.dig('repository', 'full_name')`. Nothing binds these two fields together. Combined with `GitHubApp#verify_webhook_signature` short-circuiting to `true` when an organization has no `webhook_secret` configured (documented as "optional" in `docs/setup.md`), an unauthenticated caller can pick any org with no configured secret, then set `repository.full_name` to a completely unrelated (properly-configured) org's tracked repository to inject fabricated commit statuses/check-run refresh signals for that repository.

### Finding Description
- `WebhooksController#verify_signature` does: `github_app = Shipit.github(organization: repository_owner); verified = github_app.verify_webhook_signature(...)`. [1](#0-0) 
- `repository_owner` is taken from the same JSON body being verified, with a fallback to `organization.login`: [2](#0-1) 
- `GitHubApp#verify_webhook_signature` returns `true` unconditionally when `webhook_secret` is blank for that organization: [3](#0-2) 
- The webhook secret is explicitly documented/configured as optional per organization: [4](#0-3) , and example secrets files ship with `webhook_secret: nil`: [5](#0-4) [6](#0-5) 
- Every handler resolves the acted-upon repository/stacks from `repository.full_name`, not from the organization used for signature verification: [7](#0-6) 
- `StatusHandler#process` then creates a commit status directly from attacker-controlled `state`/`context`/`description` for any commit sha matching in the database, with no additional check tying it to the verified org: [8](#0-7) 
- `CheckSuiteHandler#process` similarly resolves `stacks` via `full_name` and schedules check-run refreshes for arbitrary matching commits: [9](#0-8) 

**Binding broken:** organization authenticated (`repository_owner` → org whose, possibly absent, `webhook_secret` gated the request) `≠` repository that is written (`repository.full_name` → arbitrary stack/commit resolved by `Handler#stacks`).

Concretely: if any organization configured on this Shipit instance has `webhook_secret` unset (an explicitly supported, documented configuration), POSTing to `/webhooks` with `X-Github-Event: status`, `repository.owner.login` = that no-secret org, but `repository.full_name` = a stack belonging to a different, properly-secured organization, passes `verify_signature` trivially (secret-less org branch) while `StatusHandler` acts on the unrelated org's commits.

### Impact Explanation
Forged `status` events let an attacker mark arbitrary commits on a targeted stack as CI-`success`, which is exactly the signal `Shipit`'s merge queue and deploy-safety checks rely on to determine mergeable/deployable commits — this can push forged-green commits through the merge queue or unblock deploys that should have been blocked by failing/absent CI, i.e. an unauthorized merge/deploy path. This satisfies the "unauthorized deploy, rollback, or merge" bar without requiring any Shipit session, `ApiClient` token, or the target organization's real `webhook_secret`.

### Likelihood Explanation
Requires only: (1) the Shipit instance to host at least one organization/app config without a `webhook_secret` (an explicitly supported/optional setting per `docs/setup.md` and shipped example configs), and (2) knowledge of that org's login and the target stack's `owner/repo` full name, both public information. No credentials, no signature secret, no session are needed to reach `WebhooksController#create`, which is publicly mounted at `/webhooks`.

### Recommendation
Bind the signature-verifying organization to the resolved repository: after determining the target repository via `full_name`, verify that its owner matches the `repository_owner`/organization whose secret validated the signature, and reject the webhook otherwise. Consider also disallowing organizations with a blank `webhook_secret` from having `verify_webhook_signature` unconditionally return `true` (or require a secret for organizations that are used to look up webhooks not scoped to a specific hook `stack_id`).

### Proof of Concept
1. Configure/observe an org `orgA` on the Shipit instance with `webhook_secret: nil` (supported per docs).
2. `POST /webhooks` with header `X-Github-Event: status`, no valid `X-Hub-Signature` needed, and body:
```json
{
  "sha": "<sha of a commit on victim stack in orgB/repo>",
  "state": "success",
  "context": "ci/build",
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/repo" }
}
```
3. `verify_signature` resolves `Shipit.github(organization: "orgA")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` regardless of body/signature.
4. `StatusHandler.process` runs against `Commit.where(sha: params.sha)` for the commit belonging to `orgB/repo`, creating a fabricated successful status usable to satisfy merge/deploy CI gating for `orgB`'s stack.

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

**File:** docs/setup.md (L29-30)
```markdown
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
```

**File:** config/secrets.development.shopify.yml (L9-9)
```yaml
    webhook_secret: # nil
```

**File:** config/secrets.development.shopify.yml (L18-18)
```yaml
    webhook_secret: # nil
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```
