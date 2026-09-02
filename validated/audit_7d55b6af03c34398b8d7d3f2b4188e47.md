### Title
Webhook signature verified against the wrong GitHub organization, allowing an unauthenticated push/check_suite event to be accepted for a stack it does not belong to - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects the GitHub App / `webhook_secret` used to authenticate an inbound webhook using `repository_owner`, a value read straight from the untrusted JSON body (`params.dig('repository', 'owner', 'login')` or `params.dig('organization', 'login')`). The event handlers that actually act on the payload (`PushHandler`, `CheckSuiteHandler`, via `Handler#stacks`) instead resolve the target `Repository`/`Stack` from a *different* field of the same untrusted body: `payload.dig('repository', 'full_name')`. Nothing enforces that these two attacker-controlled fields refer to the same repository/organization.

### Finding Description
The binding that should hold is:

`organization whose webhook_secret authenticated the request == organization that owns the repository the handler writes to`

Before the fix, the code does:

- Signature check: `repository_owner = params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` then `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`. [1](#0-0) 
- Handler dispatch/target resolution: `Repository.from_github_repo_name(payload.dig('repository', 'full_name'))`. [2](#0-1) 
- `PushHandler#process` uses `stacks` (scoped by the `full_name`-derived repository) to call `stack.sync_github(expected_head_sha: params.after)`. [3](#0-2) 
- `CheckSuiteHandler#process` similarly scopes by `stacks.where(branch: ...)`. [4](#0-3) 

`repository.owner.login` and `repository.full_name`'s owner segment are two independent JSON fields; the controller never checks that `repository.full_name` starts with `repository.owner.login`. In a Shipit deployment configured for multiple GitHub organizations (the engine explicitly supports this — see the multi-org secrets template), an attacker who knows (or can leave blank) the `webhook_secret` of *any one* configured organization can craft a payload where `repository.owner.login` names that weakly-protected org (satisfying `verify_signature`) while `repository.full_name` names a repository belonging to a different, properly-secret-protected organization whose Stack actually exists in Shipit. `Shipit::GitHubApp#verify_webhook_signature` trivially returns `true` when that organization's `webhook_secret` is blank. [5](#0-4) 

Because `verify_signature` binds trust to `repository.owner.login` but `Handler#stacks` binds action to `repository.full_name`, an attacker satisfies authentication for org A while causing effects on a Stack that belongs to org B.

### Impact Explanation
This is an authentication-bypass class issue: HMAC signature verification is supposed to prove GitHub, not an attacker, produced the payload for the target repository. Because verification is keyed off a field the handlers ignore, an attacker with no `webhook_secret`, no session, and no repository access can inject forged `push` / `check_suite` events that are accepted as authentic for a Stack under an org whose secret they never had. The most severe consequence is that a forged `push` event triggers `stack.sync_github(expected_head_sha:)` → `GithubSyncJob`, which resyncs commits from GitHub and can feed `CacheDeploySpecJob` and, for stacks with continuous deployment enabled, `trigger_continuous_delivery`, causing an unscheduled/attacker-timed deploy to occur (of legitimate GitHub content, but at attacker-chosen timing and via a completely unauthenticated request path), plus wasted GitHub API calls and log/DB pollution scoped to a stack the attacker was never authorized to interact with. This satisfies the High-tier bar ("unauthenticated read/actuation of stack state" and adjacent to "unauthorized deploy").

### Likelihood Explanation
Requires a multi-organization Shipit installation (documented and supported configuration, e.g., `config/secrets.development.shopify.yml` lists multiple orgs) where at least one configured organization has a blank/no `webhook_secret`, or where the attacker separately knows one org's secret. Given `verify_webhook_signature` explicitly treats a blank secret as "verified", any org left unconfigured (e.g. during setup, or intentionally public) becomes a skeleton key for forging events attributed to any other org's repositories, since the controller never cross-checks `repository.owner.login` against `repository.full_name`.

### Recommendation
In `WebhooksController#verify_signature`, derive the organization strictly from `repository.full_name`'s owner segment (the same field the handlers use to resolve the Stack), or explicitly validate that `repository.owner.login`/`organization.login` matches the owner portion of `repository.full_name` before verifying the signature. Do not allow any code path where a webhook without a valid HMAC (via blank secret bypass) can still cause `Handler#stacks` to resolve to a Stack belonging to an organization other than the one being verified.

### Proof of Concept
1. Configure Shipit with two GitHub Apps: `org-a` (no `webhook_secret` set) and `org-b` (has a `webhook_secret`, and owns a tracked repository/stack, e.g. `org-b/private-repo`).
2. Send an unauthenticated POST to `/github/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "<any sha>",
  "repository": {
    "owner": {"login": "org-a"},
    "full_name": "org-b/private-repo"
  }
}
```
3. `verify_signature` computes `repository_owner = "org-a"`, calls `Shipit.github(organization: "org-a").verify_webhook_signature(...)`, which returns `true` immediately because `org-a`'s `webhook_secret` is blank — no valid `X-Hub-Signature` is required at all.
4. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("org-b/private-repo")` and calls `stack.sync_github(expected_head_sha: ...)`, acting on the `org-b` stack despite the request never being authenticated against `org-b`'s secret.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```
