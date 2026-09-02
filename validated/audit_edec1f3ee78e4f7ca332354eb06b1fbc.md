### Title
Cross-organization webhook forgery via organization-selectable signature verification — ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary

### Finding Description
In multi-org deployments, `Shipit.github(organization: ...)` looks up a distinct GitHub App/`webhook_secret` per organization, as configured in `secrets.yml` [1](#0-0) . `WebhooksController#verify_signature` selects *which* organization's secret to verify the HMAC signature against using `repository_owner`, a value read directly out of the unauthenticated, attacker-controlled JSON body (`params.dig('repository', 'owner', 'login')` or `params.dig('organization', 'login')`), before any signature has been checked: [2](#0-1) [3](#0-2) 

Once the signature is deemed valid (using the secret chosen from that same untrusted field), the actual event is dispatched to a handler that determines the repository/stack to act on using a *different* field of the same payload — `repository.full_name` — via `Handler#repository_name` / `Handler#stacks`: [4](#0-3) 

This creates a broken binding: **organization whose secret authenticated the request ≠ repository that gets written to**. Because the entire raw body is attacker-supplied (the attacker crafts and signs it themselves with a secret they legitimately possess for *their own* org "A"), they can set `repository.owner.login`/`organization.login` to `"A"` (so `verify_signature` picks `A`'s `webhook_secret` and the HMAC computed over their own crafted body validates), while setting `repository.full_name` to `"B/target-repo"` — a completely different organization/repository configured on the same Shipit instance.

`PushHandler` then resolves stacks via `Repository.from_github_repo_name(repository_name)` using the forged `full_name` and calls `stack.sync_github(expected_head_sha: params.after)` [5](#0-4) , and `StatusHandler` writes arbitrary commit statuses for any `sha` in the database regardless of which org actually owns it [6](#0-5) , all without ever needing organization B's webhook secret.

This is a structural analog of the reported Shardus bug: data used to authorize/scope an action (`appData`/staking fields in Shardus; `repository.full_name` here) is never covered by the same trust check applied to a different field (`nominee`/validated fields in Shardus; `repository.owner.login` used only to pick the HMAC key here).

### Impact Explanation
An attacker who is a legitimate, low-privilege participant of one organization configured on a shared multi-org Shipit instance (i.e., possesses that org's `webhook_secret`, which is not a privileged credential — it's handed out to configure a GitHub webhook) can forge and self-sign webhook payloads that are processed as if they originated from a different, unrelated organization's repository. This allows triggering `GithubSyncJob` (`sync_github`) and status writes for stacks belonging to org B, causing unauthorized/forced-sync behavior and injected commit statuses across the organization boundary Shipit is supposed to isolate — a cross-organization write that the signature check was specifically meant to prevent.

### Likelihood Explanation
Requires the target Shipit instance to be configured with `Shipit.github` for multiple organizations (a documented, supported configuration) and the attacker to control (or have compromised) the webhook secret for at least one of those organizations — a comparatively low bar, since webhook secrets are shared with whoever sets up the GitHub App/webhook for that org, and are not tied to a specific repository within the org. The attack is a single crafted HTTP request to `/webhooks`, no session or `ApiClient` token needed.

### Recommendation
`verify_signature` must not use attacker-supplied payload fields to choose which secret to verify against without cross-checking the result against the same, already-authenticated identity used later. Concretely: after verifying the signature with the org selected by `repository_owner`, re-derive and assert that `payload.dig('repository', 'full_name')` (used in `Handler#repository_name`) belongs to that same verified organization (e.g., `full_name.split('/').first == repository_owner`), rejecting the request otherwise. Alternatively, look up the `Repository`/`Stack` record independently and confirm its configured organization matches the one whose secret validated the signature before invoking any handler.

### Proof of Concept
1. Configure Shipit with two orgs, `OrgA` and `OrgB`, each with its own `webhook_secret` (per `docs/setup.md`'s "Using Multiple Github Applications" section) [1](#0-0) .
2. Attacker knows `OrgA`'s `webhook_secret` (e.g. they legitimately configured a webhook for a repo they own in `OrgA`).
3. Attacker crafts a JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/target-repo"
  }
}
```
4. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(OrgA_webhook_secret, body)>` and sends `POST /webhooks` with `X-Github-Event: push`.
5. `verify_signature` resolves `repository_owner` → `"OrgA"`, calls `Shipit.github(organization: "OrgA")`, and the signature validates against the attacker's own known secret [7](#0-6) .
6. `PushHandler#process` runs using `repository.full_name = "OrgB/target-repo"`, resolves `OrgB`'s stacks via `Repository.from_github_repo_name`, and calls `sync_github` on them, all without ever supplying `OrgB`'s webhook secret [4](#0-3) [5](#0-4) .

### Citations

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
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
