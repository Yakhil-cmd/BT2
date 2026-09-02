### Title
Webhook signature verification key is chosen from `repository.owner.login`/`organization.login`, but the acted-upon repository is looked up from an unrelated `repository.full_name` field, letting an attacker impersonate any tracked stack via an org with no `webhook_secret` configured - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which `GitHubApp`/`webhook_secret` to validate the HMAC against using `repository_owner`, derived from `params.dig('repository','owner','login')` or `params.dig('organization','login')`. [1](#0-0) [2](#0-1)  Every downstream event handler, however, resolves the *actual* target `Repository`/`Stack` using a completely different field of the same payload, `payload.dig('repository', 'full_name')`. [3](#0-2)  These two fields are never checked for consistency, so the org whose credential authenticates the request is not bound to the repository the handler ultimately mutates.

### Finding Description
`GitHubApp#verify_webhook_signature` explicitly treats an unset `webhook_secret` as automatically valid:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [4](#0-3) 

The docs mark `webhook_secret` as optional per-organization configuration. [5](#0-4)  In any deployment that manages more than one GitHub organization (Shipit supports per-organization `GitHubApp` instances keyed by `organization`, exactly what `Shipit.github(organization: ...)` looks up), if even one configured organization has no `webhook_secret`, `verify_signature` will report `verified = true` for *any* payload claiming that organization as `repository.owner.login` (or `organization.login`), regardless of the `X-Hub-Signature` header content. [1](#0-0) 

Meanwhile, `PushHandler` (and every other handler) never re-checks `repository.owner.login`; it only trusts `repository.full_name` to find the `Repository`/`Stack` to act on:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [3](#0-2) 

So an unauthenticated attacker can craft a JSON body where `repository.owner.login` = the unsecured organization (satisfies `verify_signature`), while `repository.full_name` = `victim-org/victim-repo`, a completely different, secured stack already tracked by Shipit. `PushHandler#process` will then call `stack.sync_github(expected_head_sha: params.after)` for the victim stack with an attacker-chosen `after` SHA. [6](#0-5) 

This is the direct analog of the reported bug class: a single constant/shared property (`STALE_PRICE_THRESHOLD`, here the "org used to pick the signing secret") is treated as valid coverage for a completely separate, per-instance-sensitive value (the per-token price feed, here the "repository actually written to"), producing a binding break between "organization that authenticated" and "repository that is written."

### Impact Explanation
An unauthenticated request can forge push/status/check_suite events attributed to any Stack tracked by the Shipit instance as long as one configured GitHub organization in that deployment lacks a `webhook_secret` (an explicitly documented, supported "optional" configuration). This triggers `Stack#sync_github`/`GithubSyncJob` for a victim stack under attacker control of `expected_head_sha`, which can drive Shipit's commit sync and, depending on stack configuration (continuous deployment), lead to an unauthorized deploy pipeline action on a repository the attacker has no legitimate relationship with. This crosses the "organization authenticated vs. repository written" trust boundary called out in the rules, with a realistic no-privilege attacker precondition (no `webhook_secret`, no `ApiClient` token, no repository access required).

### Likelihood Explanation
Likelihood depends on deployment topology: it requires a Shipit instance configured with multiple GitHub organizations where at least one has no `webhook_secret` set — a state explicitly permitted by the documented setup ("Webhook secret (optional)"). In such multi-tenant deployments this is trivially reachable by any internet client capable of POSTing to `/webhooks`, with zero authentication.

### Recommendation
Bind the signature-verification identity to the same field the handlers use to locate the target repository: derive `repository_owner`/`repository_name` once from `repository.full_name` (or otherwise unify the two lookups), and reject webhooks whose `repository.owner.login`/`organization.login` do not match `repository.full_name`'s owner. Additionally, do not silently treat a missing `webhook_secret` as "signature valid"; require an explicit opt-in (e.g., only skip verification for orgs marked `insecure_webhooks: true`) so a per-org missing secret cannot become a global bypass for cross-organization repository targeting.

### Proof of Concept
1. Deploy Shipit configured with two organizations: `attacker-org` (no `webhook_secret` set) and `victim-org` (secured, has a tracked `Stack` for `victim-org/victim-repo`).
2. POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
No valid `X-Hub-Signature` is needed.
3. `WebhooksController#verify_signature` resolves `repository_owner = "attacker-org"`, calls `Shipit.github(organization: "attacker-org").verify_webhook_signature(...)`, which returns `true` immediately because that org has no `webhook_secret`. [4](#0-3) 
4. `Shipit::Webhooks.for_event('push')` dispatches to `PushHandler`, which resolves the target stack via `payload.dig('repository','full_name')` = `"victim-org/victim-repo"` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` for the victim stack. [6](#0-5) [3](#0-2)

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** docs/setup.md (L30-30)
```markdown
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
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
