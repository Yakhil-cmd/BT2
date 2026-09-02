### Title
Signature verification uses the org derived from the unauthenticated payload, letting an attacker forge webhooks for any repository via an org configured without a `webhook_secret` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to validate the `X-Hub-Signature` against by reading `repository_owner` straight out of the *unverified* JSON body, and then the event handlers act on a completely different, also attacker-controlled field (`repository.full_name`) from that same body. This breaks the intended binding "organization whose secret authenticated the signature == repository the handler writes to."

### Finding Description
`verify_signature` picks the verifying app like this: [1](#0-0) 

`repository_owner` is derived purely from the request body before any signature check occurs: [2](#0-1) 

`Shipit.github(organization:)` looks up per-organization config and, critically, `GitHubApp#verify_webhook_signature` treats a blank `webhook_secret` as automatic success: [3](#0-2) 

Multi-org installations are an explicitly documented and supported configuration (`docs/setup.md`, `config/secrets.development.shopify.yml`, `test/dummy/config/secrets_double_github_app.yml`), where each organization can independently have `webhook_secret: nil`: [4](#0-3) 

Meanwhile, once `verify_signature` passes, `Handler#stacks` resolves the target `Stack` from a *different* attacker-controlled field, `repository.full_name`, with no relation whatsoever to `repository_owner`: [5](#0-4) 

Because `repository_owner` (used to select the verifying secret) and `repository.full_name` (used to select the acted-upon stack) are two independent JSON keys in the same unauthenticated body, an attacker can set `repository.owner.login` to an organization configured with `webhook_secret: nil` (or otherwise weakly configured) while setting `repository.full_name` to a repository belonging to a *different*, properly-secured organization that is actually tracked by Shipit. `verify_webhook_signature` will short-circuit to `true` because the selected app has no secret, and the handler will then process the forged event as if it legitimately came from GitHub for the targeted repository.

`StatusHandler` is even more permissive: it does not scope by repository at all and updates `Commit` status purely by `sha`, matching against any commit in the datastore regardless of which repository it belongs to: [6](#0-5) 

### Impact Explanation
An unauthenticated, unprivileged party who knows (a) that a target Shipit instance is configured for multiple GitHub organizations and (b) that at least one configured organization has no `webhook_secret` (a documented default/placeholder value, `# nil`), can forge `push`, `status`, `check_suite`, or `membership` events for repositories/stacks belonging to a *different*, secured organization. This can:
- Trigger `stack.sync_github(expected_head_sha:)` via a forged `push` event on `PushHandler`, forcing an unauthorized sync/GithubSyncJob against a real tracked stack [7](#0-6) .
- Inject arbitrary CI/commit statuses on arbitrary commits via `StatusHandler`, which is not even repository-scoped [6](#0-5) , potentially marking a commit as CI-passing (`deployable?`) to unlock deploy eligibility for that commit.
- Falsify `membership` events to create/delete `Team`/`Membership`/`User` records for the `shopify_membership`-style organization hooks, indirectly affecting `Shipit.github_teams`-based authorization.

This crosses the "organization authenticated vs repository written" binding and can lead to unauthorized state changes feeding into deploy eligibility, which aligns with the High-impact bucket ("escalation into `Shipit.github_teams` authorization" / unauthorized effect on deploy state) once a real deploy is subsequently triggered against the falsely-marked-deployable commit.

### Likelihood Explanation
Requires no credentials, no session, no `ApiClient` token, and no GitHub webhook secret knowledge from the attacker — only that the operator has configured Shipit for multiple organizations and left at least one org's `webhook_secret` unset, which is exactly the value shipped in the example/documentation configs (`# nil`). This is a plausible, encouraged-by-defaults operational state for multi-org deployments, not a purely theoretical edge case, but it does depend on that specific multi-org/no-secret configuration being present, which is not guaranteed for every deployment.

### Recommendation
Do not let any field from the unauthenticated payload determine which secret is used to authenticate that same payload. Alternatives:
- Require and mandate a `webhook_secret` for every configured organization (fail closed rather than "verify_webhook_signature returns true unless webhook_secret").
- After signature verification succeeds for a given `repository_owner`, additionally verify that the `repository.full_name`'s owner matches the same `repository_owner`/organization the verified secret belongs to, before dispatching to handlers.
- Scope `StatusHandler` (and any other handler that doesn't already do so) by repository, not just by global commit `sha`.

### Proof of Concept
1. Configure Shipit with two organizations: `OrgA` (properly secured, tracks `OrgA/real-repo` as a stack) and `OrgB` (`webhook_secret: nil`, matching the documented default).
2. As an anonymous attacker, POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": { "owner": { "login": "OrgB" }, "full_name": "OrgA/real-repo" }
}
```
   with any garbage `X-Hub-Signature` value.
3. `verify_signature` computes `repository_owner == "OrgB"`, loads `Shipit.github(organization: "OrgB")`, whose `webhook_secret` is `nil`, so `verify_webhook_signature` returns `true` unconditionally regardless of the header value [8](#0-7) .
4. `PushHandler#process` then resolves the stack via `repository.full_name = "OrgA/real-repo"` [9](#0-8)  and triggers `sync_github` on the real `OrgA` stack, despite the request never being validated with `OrgA`'s actual webhook secret.

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

**File:** config/secrets.development.shopify.yml (L5-10)
```yaml
github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
