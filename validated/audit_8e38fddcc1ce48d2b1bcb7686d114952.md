### Title
Webhook signature is verified against `repository.owner.login`/`organization.login` but event handlers act on the independently-supplied `repository.full_name` field, allowing cross-organization/cross-repository forgery when Shipit is configured with multiple GitHub orgs - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which org's `webhook_secret` to check the HMAC signature against using `repository_owner`, computed as `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`. Once the signature check passes for that organization, the actual event handlers (`PushHandler`, `StatusHandler`, etc.) do **not** re-derive the target repository/commit from the same, signature-verified field — they instead trust a separate payload field (`repository.full_name` for `Handler#repository_name`, or a bare `sha` lookup with no repo scoping in `StatusHandler`) to decide which `Stack`/`Commit` to mutate.

### Finding Description [1](#0-0) 

The binding that should hold is:
`organization whose webhook_secret authenticated the request == organization that owns the repository being written to`.

In this engine, that equality is never enforced:

1. `verify_signature` authenticates the payload against the org derived from `repository_owner` [2](#0-1) , using `Shipit.github(organization: repository_owner).verify_webhook_signature(...)` [3](#0-2) .
2. Handlers such as `PushHandler` and the base `Handler` class resolve the *actual* stack to mutate using `payload.dig('repository', 'full_name')` [4](#0-3) , a field that is completely independent of `repository.owner.login` used in step 1, and is under full control of whoever crafts the JSON body.
3. `StatusHandler#process` goes even further and looks up commits purely by `sha` with **no repository scoping at all**, applying the status to any matching `Commit` across the whole Shipit instance [5](#0-4) .

`Shipit.github` supports multiple named organizations, each with its own independently configured `webhook_secret` (which can legitimately be blank/absent, in which case `verify_webhook_signature` returns `true` unconditionally: `return true unless webhook_secret`) [6](#0-5) [7](#0-6) . If any one configured organization has no `webhook_secret` (a documented/supported configuration, not a misuse of the API), an attacker can send an unauthenticated POST to `/webhooks` claiming `repository.owner.login` (or `organization.login`) equal to that weakly-configured org — satisfying `verify_signature` — while setting `repository.full_name` (for push/etc.) or `sha` (for status) to point at a stack/commit that actually belongs to a completely different, securely configured organization tracked by the same Shipit instance.

This breaks exactly the "organization that authenticated vs. repository that is written" binding called out as an accepted analog class.

### Impact Explanation
This allows an unauthenticated external attacker to:
- Trigger `GithubSyncJob`/`stack.sync_github` on arbitrary stacks belonging to unrelated, correctly-secured organizations via a forged `push` event whose signature only needed to satisfy the weak org, achieving unauthorized cross-repository writes to Shipit's internal state (commits, sync).
- Forge arbitrary commit statuses (`StatusHandler`) on any known SHA regardless of which repository/org the signature was verified against, since `Commit.where(sha:)` is not scoped by repository at all. This can be used to fake green CI status on a commit belonging to another team's stack, which several parts of Shipit's deployability/merge-status logic rely on to gate deploys — an unauthorized-deploy vector.

This qualifies as High/Critical under the rules ("cross-repository writes" / "an unauthorized deploy").

### Likelihood Explanation
Requires a Shipit instance configured with at least two GitHub organizations where one has no `webhook_secret` set (a supported, documented configuration state per `lib/shipit/github_app.rb`), or more generally any scenario where an attacker can predict/observe a `repository.owner.login` value that maps to a weak-secret org while a different `repository.full_name`/`sha` targets the real victim stack. No authentication, session, or API token is required to reach `WebhooksController#create` (authenticity token and normal Shipit authentication are explicitly skipped). Multi-org support and blank-secret handling are both first-class, intentional features, so this is a realistic misconfiguration surface rather than a purely theoretical one.

### Recommendation
- After verifying the signature for `repository_owner`, re-validate that the *same* organization owns the repository/stack that the handler is about to mutate (compare `repository_owner` against the resolved `Repository#owner` before dispatching to handlers), rejecting mismatches.
- In `StatusHandler`, scope the `Commit` lookup by the repository derived from the verified payload (e.g., join through `Stack`/`Repository`) instead of a bare `Commit.where(sha:)`.
- Consider requiring a non-blank `webhook_secret` for every configured organization, or at minimum warn/refuse to boot when any organization has signature verification disabled while other organizations are configured with secrets.

### Proof of Concept
Assume Shipit is configured with two orgs: `weak-org` (no `webhook_secret`) and `victim-org` (properly secured, hosting a tracked stack `victim-org/app`).

```
POST /webhooks
X-Github-Event: push
X-Hub-Signature: sha1=anything   # ignored because weak-org has no webhook_secret

{
  "repository": { "owner": { "login": "weak-org" }, "full_name": "victim-org/app" },
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>"
}
```

- `repository_owner` resolves to `weak-org` → `verify_signature` passes unconditionally (`return true unless webhook_secret`).
- `PushHandler#repository_name` resolves to `"victim-org/app"` → `Repository.from_github_repo_name` finds the real victim stack and calls `stack.sync_github(expected_head_sha: ...)`, all without ever validating a signature scoped to `victim-org`.

Similarly, a forged `status` event with the same `weak-org` owner but `sha` equal to a known commit in `victim-org/app` will have `StatusHandler` create a status for that commit, with no org/repo check at all.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
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
