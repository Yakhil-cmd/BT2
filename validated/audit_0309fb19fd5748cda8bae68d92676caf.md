### Title
Cross-organization authentication bypass via blank `webhook_secret` decouples the org used for signature verification from the repository whose data is mutated - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and thus which `webhook_secret`) to validate the request signature against, based solely on `params.dig('repository', 'owner', 'login')` (or `organization.login`) taken from the unauthenticated JSON body itself. [1](#0-0)  The event handlers, however, resolve the repository/stack whose data is actually written using a *different* field of the same attacker-supplied body, `payload.dig('repository', 'full_name')`. [2](#0-1)  These two fields are never checked for consistency. If the `github_app` selected via `repository_owner` has no configured `webhook_secret` (an explicitly supported, documented configuration — see `docs/setup.md` "Webhook secret (optional)" and the `webhook_secret: # nil` fixtures), `verify_webhook_signature` unconditionally returns `true`, skipping signature verification entirely. [3](#0-2) 

### Finding Description
The binding that should hold is: **organization authenticated == organization whose repository is written**. In this engine, the organization used to *authenticate* the request (`repository_owner`, from `params.dig('repository','owner','login')`) and the repository that ends up being *acted on* (`repository.full_name`, consumed later by every `Handler` subclass via `repository_name`) are independent fields of the same untrusted JSON payload:

- `WebhooksController#verify_signature` computes `repository_owner` and calls `Shipit.github(organization: repository_owner)` to fetch that org's `GitHubApp`, then verifies `X-Hub-Signature` against that org's `webhook_secret`. [4](#0-3) 
- `Handler#stacks` / `#repository_name` instead reads `payload.dig('repository', 'full_name')` — a separate JSON field that is not covered by the org-selection logic and is not cross-checked against `repository_owner`. [2](#0-1) 
- `GitHubApp#verify_webhook_signature` returns `true` unconditionally when no `webhook_secret` is configured for the selected organization. [3](#0-2) 
- Multi-organization deployments are an explicitly supported configuration, each org with its own independent `webhook_secret` (see `test/dummy/config/secrets_double_github_app.yml`, showing `OrgOne`/`OrgTwo` each with their own, possibly blank, `webhook_secret`). [5](#0-4) 

Because `repository_owner` and `repository.full_name`'s owner segment are never required to match, an attacker with no credentials at all can craft a JSON body where `repository.owner.login` names an organization that happens to have a blank/unset `webhook_secret` (bypassing signature verification unconditionally), while `repository.full_name` names an entirely different, sensitive repository/stack tracked by the same Shipit instance. The handler dispatch loop (`Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`) then processes the full, unverified body against that unrelated target repository. [6](#0-5)  For the `push` event, `PushHandler#process` resolves stacks by `repository_name` (i.e. the spoofed `full_name`) and calls `stack.sync_github(expected_head_sha: params.after)` for every matching, non-archived stack on the matching branch, with `after` fully attacker-controlled. [7](#0-6) 

### Impact Explanation
This breaks the "organization authenticated versus the repository that is written" trust binding explicitly called out in scope. An unauthenticated, unprivileged attacker (no `webhook_secret`, no API token, no repository access) can inject arbitrary webhook events attributed to any repository tracked by the Shipit instance, as long as any one configured GitHub App organization on that instance has a blank `webhook_secret`. This can drive unintended `GithubSyncJob` enqueues with attacker-chosen `expected_head_sha` against unrelated stacks, i.e., an unauthorized cross-repository write/trigger path with no credential requirement, matching the report's "front-runnable/stale-trust binding" bug class (verified field ≠ acted-upon field) in the same way the original oracle heartbeat bug let stale/mismatched data be trusted implicitly.

### Likelihood Explanation
Requires that at least one organization configured on the Shipit instance has a blank `webhook_secret` — an explicitly documented, supported configuration (`docs/setup.md` calls it "optional"; the shipped `secrets.yml`/`secrets_double_github_app.yml` fixtures ship with `webhook_secret: # nil`). No credentials, tokens, or prior access are needed to exploit it once that condition holds; likelihood scales with the (common, documented) practice of leaving `webhook_secret` unset during initial setup or for lower-risk orgs.

### Recommendation
- Require `webhook_secret` to be present for every configured GitHub App organization, or fail closed (reject the request) rather than returning `true` in `GitHubApp#verify_webhook_signature` when `webhook_secret` is blank.
- Bind the organization used to select the verification secret to the actual owner of the repository whose data is subsequently processed: after verification, re-derive the acting organization from the same `repository.owner.login`/`full_name` used by the `Handler`, and reject the request if they diverge.

### Proof of Concept
1. Configure a multi-org Shipit deployment where `OrgLowSecurity` has no `webhook_secret` set (a supported, documented configuration) and `OrgHighValue/important-repo` is a tracked, non-archived stack with a configured secret.
2. Send an unauthenticated `POST /webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "OrgLowSecurity" },
    "full_name": "OrgHighValue/important-repo"
  }
}
```
3. `verify_signature` selects `OrgLowSecurity`'s `GitHubApp` (via `repository_owner`), whose blank `webhook_secret` makes `verify_webhook_signature` return `true` unconditionally. [3](#0-2) 
4. `create` dispatches to `PushHandler`, which resolves the stack via `full_name` = `"OrgHighValue/important-repo"` and calls `sync_github(expected_head_sha: "<attacker-chosen-sha>")`, despite no valid signature ever having been produced by `OrgHighValue`. [7](#0-6)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
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
