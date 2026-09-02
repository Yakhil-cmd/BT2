### Title
Webhook signature verification is bypassed when an organization has no `webhook_secret`, allowing an attacker to forge events for arbitrary repositories/stacks - ([File: lib/shipit/github_app.rb], [File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/secret to validate against using an *organization login taken directly from the untrusted request body*, and `GitHubApp#verify_webhook_signature` treats a missing secret as automatic success. Because the org used for "authentication" and the repository whose data is actually mutated are both attacker-supplied fields inside the same unverified JSON payload, the two are never cryptographically bound together — exactly the class of bug the report describes (a degenerate/absent verification result being treated as valid).

### Finding Description
`verify_webhook_signature` returns `true` unconditionally whenever `webhook_secret` is blank/nil for the resolved organization: [1](#0-0) 

The organization used to look up that secret is derived from the incoming, unauthenticated payload itself: [2](#0-1) [3](#0-2) 

Sample configuration confirms `webhook_secret` is a legitimately supported nil value per configured org (multi-org deployments are a documented feature): [4](#0-3) 

Once `verify_signature` passes (either because the picked org has no secret, or trivially because the attacker names an org with a blank secret), the handler dispatch uses a *different* field of the same untrusted payload to decide what to actually write: [5](#0-4) [6](#0-5) 

For example, `PushHandler` resolves stacks solely from `repository.full_name` and enqueues a sync: [7](#0-6) 

`StatusHandler` looks up commits **globally by SHA**, with no repository scoping at all, and writes a forged CI status onto them: [8](#0-7) 

The binding that should hold is:
`organization whose secret authenticated the request == owner of the repository/commits the handler mutates`

but nothing enforces this — `repository_owner` (used only to pick a secret, or to bypass verification if that org's secret is unset) is never checked against `repository.full_name`/commit ownership used by the handlers. An attacker who knows (or guesses) the login of *any* organization configured in this Shipit instance without a `webhook_secret` can set `repository.owner.login` (or `organization.login`) to that org to pass `verify_signature`, while setting `repository.full_name` / commit `sha` to point at a completely different, secret-protected stack's repository/commits.

### Impact Explanation
This breaks the authentication boundary between "which GitHub App/org validated the webhook" and "which repository's state gets modified." Concretely:
- `PushHandler` can trigger `GithubSyncJob`/`stack.sync_github` for any stack the attacker names, regardless of which org's (missing) secret was used to pass verification.
- `StatusHandler` can inject forged commit statuses onto arbitrary commits (matched globally by SHA, not scoped to the org/repo used for verification), which can influence deploy-gating logic that checks required statuses before allowing a deploy.
- Other handlers (`membership_handler.rb`, `pull_request/*`) are reachable the same way, letting an attacker fabricate team membership changes or pull-request/merge-status events for repositories unrelated to the org whose (absent) secret was checked.

This crosses the required boundary: an unverified, attacker-controlled payload results in written stack/commit state for repositories the attacker was never authenticated against, which can feed into unauthorized deploy decisions.

### Likelihood Explanation
Likelihood depends on operational configuration: it requires at least one organization registered in `Shipit.github(organization: ...)` with no `webhook_secret` set — a state the shipped sample config (`config/secrets.development.shopify.yml`) explicitly shows as a valid/supported value (`webhook_secret: # nil`). In any multi-tenant instance where even one configured org omits the secret (e.g., during onboarding, or an org that never configured a GitHub App), the check for every payload naming that org's login is fully defeated, with no other authentication on the `/webhooks` endpoint. I could not verify from the available files whether any deployment-time validation forces `webhook_secret` to be non-blank for all configured orgs; this is a configuration precondition worth confirming.

### Recommendation
- Require `webhook_secret` to be present for every configured GitHub organization at boot/config-load time, rather than allowing `verify_webhook_signature` to silently return `true` when it is blank.
- Bind repository/commit resolution in each handler (`Handler#repository_name`, `StatusHandler#process`, etc.) to the same organization that was cryptographically verified in `WebhooksController#verify_signature`, rejecting payloads where `repository.full_name`'s owner does not match the verified `repository_owner`.
- Scope `StatusHandler`'s `Commit.where(sha:)` lookup by the verified repository, not globally.

### Proof of Concept
1. Operator configures Shipit with two GitHub orgs: `org-a` (has an App + `webhook_secret`) and `org-b` (App configured but `webhook_secret` left blank, e.g. during setup) — a state explicitly represented in the shipped sample secrets file.
2. Attacker POSTs to `/webhooks` with:
   - `X-Github-Event: push`
   - Body: `{"repository": {"owner": {"login": "org-b"}, "full_name": "org-a/protected-repo"}, "ref": "refs/heads/master", "after": "<target sha>"}`
   - No valid `X-Hub-Signature` needed.
3. `verify_signature` resolves `Shipit.github(organization: "org-b")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` ( [9](#0-8) ) without checking anything about `org-a`.
4. `PushHandler#process` resolves stacks via `Repository.from_github_repo_name("org-a/protected-repo")` ( [10](#0-9) ) and enqueues `sync_github` for `org-a`'s stack, even though only `org-b`'s (blank) secret was ever checked.
5. Repeating with `X-Github-Event: status` and a known SHA lets the attacker inject a fabricated `commit_status` on `org-a`'s commit via the unscoped `Commit.where(sha:)` lookup ( [8](#0-7) ), potentially satisfying deploy-gating conditions for an unauthorized deploy.

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

**File:** config/secrets.development.shopify.yml (L5-18)
```yaml
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
