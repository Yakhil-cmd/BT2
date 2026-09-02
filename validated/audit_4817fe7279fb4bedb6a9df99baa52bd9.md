This confirms the binding mismatch: `WebhooksController#verify_signature` authenticates the request based on the **organization derived from `repository.owner.login` (or `organization.login`)**, using that org's configured `webhook_secret` to select which GitHub App/secret validates the HMAC [1](#0-0) . But every event handler (`Handler#stacks`, used by `PushHandler`, `CheckSuiteHandler`, etc.) resolves the target repository/stack from an entirely different, independently-controlled JSON field: `payload.dig('repository', 'full_name')` [2](#0-1) . `Repository.from_github_repo_name` splits that string on `/` and looks it up directly, with no cross-check against `repository.owner.login` [3](#0-2) .

Critically, `verify_webhook_signature` in `GitHubApp` returns `true` unconditionally whenever the resolved organization has no `webhook_secret` configured: `return true unless webhook_secret` [4](#0-3) . In a multi-tenant deployment (`config/secrets.*.yml` supports multiple orgs, some may be left with `webhook_secret: nil` as shown in the shipped example config) [5](#0-4) , an attacker only needs an organization name known to Shipit's config that has no secret set. They then POST a webhook to `/github/webhooks` with `repository.owner.login` (or `organization.login`) set to that secret-less org — making `verify_signature` pass with **no signature required at all** — while setting `repository.full_name` to `"victim-org/tracked-repo"`, a completely different, secret-protected repository that Shipit tracks. Because `Handler#stacks`/`Repository.from_github_repo_name` only look at `full_name` and never re-validate it against the authenticated `owner.login`, the forged event is processed against the victim's real `Stack`.

This lets an unauthenticated attacker drive real state changes on `Stack`s belonging to organizations they don't control:
- `PushHandler#process` calls `stack.sync_github(expected_head_sha: params.after)` for the victim stack/branch [6](#0-5) , forcing a fake `after` SHA to be treated as the head of the target branch.
- `StatusHandler#process` creates a commit status keyed only on `sha` (no repo binding check at all beyond the loose `stacks` scoping used elsewhere) via `Commit.create_status_from_github!` [7](#0-6) , letting the attacker forge a passing CI status on an arbitrary commit SHA (since `Commit.where(sha:)` isn't even scoped by `stacks`), which can satisfy `ci.require` gating and enable an unauthorized deploy through the normal deploy flow.
- `CheckSuiteHandler#process` similarly triggers `schedule_refresh_check_runs!` against the victim's commits [8](#0-7) .

The binding broken is: **the organization the signature check authenticates (`repository.owner.login`/`organization.login`) ≠ the repository whose `Stack` the handler code actually writes to (`repository.full_name`)**. Both fields come from the same unauthenticated JSON body, and nothing enforces they refer to the same repository.

### Title
Webhook signature verification authenticates `repository.owner.login`/`organization.login` while handlers act on the independently-controlled `repository.full_name` field - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/handler.rb)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/secret to validate the HMAC based on `repository.owner.login` (falling back to `organization.login`), but the actual event-processing code in `Handler#stacks`/`Repository.from_github_repo_name` resolves the target `Stack`/`Repository` from the unrelated `repository.full_name` field. When an organization known to Shipit has no `webhook_secret` configured, `verify_webhook_signature` bypasses verification entirely for that organization, letting an attacker submit an unsigned payload that claims that secret-less organization for the check while pointing `repository.full_name` at a different, victim-owned repository that Shipit actually tracks.

### Finding Description
The signature-check binding (`repository_owner` → webhook secret) and the repository-write binding (`repository.full_name` → `Stack`) are computed from two independent, attacker-controlled JSON fields with no cross-validation between them [1](#0-0) [2](#0-1) . Combined with `GitHubApp#verify_webhook_signature`'s intentional bypass for organizations without a configured secret [4](#0-3) , this permits forging events for any tracked repository as long as any other configured (or attacker-claimed) organization lacks a secret.

### Impact Explanation
This is an unauthenticated write path into tracked `Stack`s: fake push events can move the recorded "deployed" head SHA, and fake `status`/`check_suite` events can inject fabricated CI results (`StatusHandler` doesn't even scope `Commit` lookups by stack) that can satisfy CI-gating checks and enable an unauthorized deploy — matching the "unauthorized deploy" high-severity criteria.

### Likelihood Explanation
Requires that the Shipit installation configures at least one organization without a `webhook_secret` (a supported, documented configuration, e.g. `config/secrets.development.shopify.yml`) and that the attacker knows/guesses that organization's login. No repository write access, GitHub App key, or session is required — only network access to the public webhooks endpoint.

### Recommendation
Cross-validate that `repository.owner.login` (the organization used to select/verify the signature) matches the owner segment of `repository.full_name` before dispatching to handlers, and reject mismatches; additionally consider requiring a configured `webhook_secret` for every organization rather than silently bypassing verification when absent.

### Proof of Concept
1. Configure/identify an organization `secretless-org` in Shipit's GitHub config with no `webhook_secret`, and a genuine tracked repository `victim-org/prod-app`.
2. POST to `/github/webhooks` with header `X-Github-Event: push` and no valid `X-Hub-Signature`, body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": { "owner": { "login": "secretless-org" }, "full_name": "victim-org/prod-app" }
}
```
3. `verify_signature` resolves `repository_owner` = `secretless-org`, fetches its `GitHubApp`, and since it has no `webhook_secret`, `verify_webhook_signature` returns `true` unconditionally — request passes.
4. `PushHandler#process` resolves `stacks` via `repository.full_name` = `victim-org/prod-app`, and calls `sync_github(expected_head_sha: <attacker sha>)` on the real, victim-owned `Stack`.

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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```
