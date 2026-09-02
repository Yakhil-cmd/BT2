### Title
Webhook Signature Scope Bypass via Organization/Repository Field Mismatch - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App config (and therefore which `webhook_secret`) to validate an inbound webhook against using `repository_owner`, derived from `params.dig('repository', 'owner', 'login')` [1](#0-0) . Once the signature check passes, every event `Handler` instead resolves the *actual* repository/stack to act on from a completely different payload field, `payload.dig('repository', 'full_name')` [2](#0-1) . Nothing in the request pipeline enforces that these two attacker-supplied fields describe the same repository.

### Finding Description
`Shipit::GithubApp#verify_webhook_signature` also has a permissive fallback: if the resolved organization has no `webhook_secret` configured, verification unconditionally succeeds: [3](#0-2) 

`webhook_secret` is explicitly documented as optional per organization [4](#0-3) , and the shipped configuration template shows it commonly left `nil` for one or more configured organizations [5](#0-4) .

Because `verify_signature` picks the secret using `repository.owner.login` while `Handler#repository_name`/`Handler#stacks` act on `repository.full_name` [2](#0-1) , an attacker can craft a raw JSON body where:
- `repository.owner.login` = an organization configured in this Shipit instance **without** a `webhook_secret` (or one the attacker otherwise controls), causing `verify_signature` to pass trivially.
- `repository.full_name` = `"<protected-org>/<repo>"`, i.e., a completely different, secret-protected organization's tracked repository.

The signature check never inspects `repository.full_name`, so the forged event is accepted and dispatched to handlers that act on the targeted repository regardless of which organization's (lack of) secret validated the request. For example, `StatusHandler` writes a forged commit status for any `sha` in the payload [6](#0-5) , and `PushHandler` triggers a `sync_github` for the targeted stack's branch [7](#0-6) .

Binding broken: `organization authenticated (repository.owner.login, secret-checked)` ≠ `repository actually written (repository.full_name, unchecked)`.

### Impact Explanation
A forged `status` event can mark an arbitrary commit as passing all required CI checks on a stack belonging to an organization whose webhook secret the attacker never possessed, which is exactly the kind of check `MergeRequest#all_status_checks_passed?` / deploy safety checks rely on [8](#0-7) . This can enable an unauthorized merge/deploy on a repository the attacker has no legitimate signing credentials for, satisfying the "unauthorized deploy/merge" High-impact bar.

### Likelihood Explanation
Exploitability depends entirely on the deployment having at least one organization configured without a `webhook_secret` — a state the documentation explicitly supports as "optional" rather than treating as a hard requirement [4](#0-3) . Any Shipit instance managing multiple GitHub organizations where even one is left unsecured is exposed; the attacker needs no session, token, or org-specific secret for the *targeted* organization at all.

### Recommendation
In `WebhooksController#verify_signature`, derive the organization used for authentication from the same repository field used by handlers (`repository.full_name`'s owner segment), and/or have `Shipit::Webhooks::Handlers::Handler` validate that `payload.dig('repository', 'owner', 'login')` matches the segment of `payload.dig('repository', 'full_name')` before resolving `stacks`. Additionally, consider making `webhook_secret` mandatory (or requiring an explicit opt-out) rather than silently returning `true` when absent in `Shipit::GithubApp#verify_webhook_signature`.

### Proof of Concept
1. Configure a Shipit instance tracking two orgs: `unsecured-org` (no `webhook_secret`) and `secured-org` (repo `secured-org/app` tracked as a stack).
2. POST to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "sha": "<commit sha of secured-org/app HEAD>",
  "state": "success",
  "context": "ci/build",
  "repository": {
    "full_name": "secured-org/app",
    "owner": { "login": "unsecured-org" }
  }
}
```
3. `verify_signature` resolves `Shipit.github(organization: "unsecured-org")`, whose `webhook_secret` is nil, so `verify_webhook_signature` returns `true` unconditionally [9](#0-8) .
4. `StatusHandler` then creates a forged successful status against the `secured-org/app` commit [6](#0-5) , without ever validating `secured-org`'s own webhook secret.

### Citations

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

**File:** docs/setup.md (L26-30)
```markdown
  - Homepage URL: The URL where Shipit will be deployed, e.g. `https://example.com`.
  - User authorization callback URL: It must be set to `<homepage>/github/auth/github/callback`, e.g. `https://example.com/github/auth/github/callback`.
  - Setup URL: Leave it empty.
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
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

**File:** app/models/shipit/merge_request.rb (L193-197)
```ruby
    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end
```
