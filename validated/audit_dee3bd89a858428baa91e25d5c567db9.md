Confirmed: `Handler#stacks` (and every event handler) resolves the target repository from `payload.dig('repository', 'full_name')`, a field completely independent of `repository_owner` (`payload.dig('repository', 'owner', 'login')`) that `WebhooksController#verify_signature` uses to select which GitHub App/secret to validate the signature against. This is the exact analog of the escrow bug: the credential context that is authenticated (`Shipit.github(organization: repository_owner)`) is not bound to the object that is actually acted upon (`repository.full_name`).

### Title
Webhook signature verified against attacker-chosen organization while the action executes against an unrelated `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App config (and thus the HMAC secret) to validate a webhook against using `repository_owner`, a value read straight from the untrusted JSON body [1](#0-0) [2](#0-1) . The event handlers that subsequently act on the payload, however, resolve the target `Stack`/`Repository` via a completely different field, `repository.full_name` [3](#0-2) . Additionally, `GitHubApp#verify_webhook_signature` returns `true` unconditionally whenever no `webhook_secret` is configured for the selected organization: `return true unless webhook_secret` [4](#0-3) .

### Finding Description
The binding that should hold is: `organization authenticated == repository acted upon`. Instead, the engine authenticates the request against whatever `Shipit.github(organization: repository_owner)` resolves to [5](#0-4) [6](#0-5) , using the attacker-controlled `repository.owner.login` (or `organization.login`) field of the raw JSON body [2](#0-1) , before any signature check has run. If an attacker crafts a payload where `repository.owner.login` names an organization/App config that has no `webhook_secret` configured (or one whose secret they don't need to forge because verification degenerates to `return true`), `verify_signature` passes trivially regardless of the actual `X-Hub-Signature` header [7](#0-6) . The `create` action then dispatches the full payload to the event handlers unmodified [8](#0-7) , and those handlers locate the affected `Stack` purely from `repository.full_name`, a field never covered by the (bypassed) authentication decision [3](#0-2) [9](#0-8) . This lets an attacker point `repository.full_name` at any repository tracked by Shipit (in any organization) while satisfying signature verification using the identity of a different, unsecured organization config.

### Impact Explanation
This directly maps to the "authenticated organization vs. repository written" binding called out in scope. A successful forgery lets an unauthenticated attacker trigger `PushHandler` (queues `GithubSyncJob`, which fast-forwards the deployed commit state) or `StatusHandler`/`CheckSuiteHandler` (fabricates commit statuses that gate deploy eligibility) against a legitimate, unrelated stack, effectively enabling an unauthorized deploy/rollback trigger without possessing that organization's real webhook secret.

### Likelihood Explanation
Exploitability depends entirely on host-application configuration: it requires at least one configured GitHub organization (in `Shipit.secrets.github`) with a blank/missing `webhook_secret`, which the deployer's own multi-org config could plausibly have (e.g., a staging/demo org added without a secret) while other orgs are properly secured. Given that dependency on operator configuration rather than an inherent code defect, likelihood is lower than the escrow analog (where any deployed instance is affected once ownership is renounced), but the underlying binding gap (organization authenticated ≠ repository acted upon) is unconditionally present in the code regardless of configuration.

### Recommendation
Bind the verified organization to the repository being modified: after determining `repository_owner`/selecting the GitHub App, verify that `repository.full_name`'s owner segment matches `repository_owner` before dispatching to handlers, and/or require a non-blank `webhook_secret` for every configured organization (fail-closed instead of `return true unless webhook_secret` in `GitHubApp#verify_webhook_signature`) [7](#0-6) .

### Proof of Concept
1. Host configures `Shipit.secrets.github` with two orgs: `secured-org` (has `webhook_secret`) and `unsecured-org` (no `webhook_secret` set, e.g. left blank in a staging config).
2. Attacker POSTs to `/webhooks` with header `X-Github-Event: push`, no valid `X-Hub-Signature`, and body:
```json
{ "repository": { "owner": { "login": "unsecured-org" }, "full_name": "secured-org/prod-repo" }, "ref": "refs/heads/master", "after": "<attacker-controlled sha>" }
```
3. `verify_signature` calls `Shipit.github(organization: "unsecured-org")` [1](#0-0) , whose `verify_webhook_signature` returns `true` unconditionally since `webhook_secret` is blank [7](#0-6) .
4. `create` dispatches to `PushHandler`, which resolves `Repository.from_github_repo_name("secured-org/prod-repo")` from `full_name` [3](#0-2)  and enqueues `sync_github(expected_head_sha: params.after)` on the matching stack [9](#0-8) , despite the request never being authenticated for `secured-org`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-29)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
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

**File:** app/controllers/shipit/github_authentication_controller.rb (L0-0)
```ruby

```

**File:** lib/shipit.rb (L170-181)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
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
