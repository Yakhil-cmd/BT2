### Title
Webhook signature verification is keyed to an attacker-controlled `repository.owner.login`/`organization.login`, decoupled from the `repository.full_name` the handlers actually act on - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which GitHub App/organization's `webhook_secret` to validate a webhook's HMAC signature against using `repository_owner`, a value read directly out of the unauthenticated JSON body. If that organization has no `webhook_secret` configured (an explicitly supported, "optional" configuration per the setup docs), `GitHubApp#verify_webhook_signature` unconditionally passes. The event is then dispatched to handlers that resolve the *actual* target repository/stack from a different, equally attacker-controlled body field, `repository.full_name`. An attacker can therefore forge a webhook naming a low-value/unsecured organization in `repository.owner.login` (to sail through signature verification) while pointing `repository.full_name` at any other repository/stack configured in the Shipit instance, causing unauthorized writes (triggering syncs, commit statuses, merges, etc.) on a repository that was never actually verified.

### Finding Description
`verify_signature` derives the organization used for verification from the request body itself, before any cryptographic check has taken place: [1](#0-0) [2](#0-1) 

That organization is used to fetch a `GitHubApp` instance whose `webhook_secret` gates verification: [3](#0-2) 

Note the `return true unless webhook_secret` short-circuit: if the organization resolved from `repository.owner.login`/`organization.login` has no `webhook_secret` configured, *any* payload signature (or none at all) is accepted, regardless of the actual repository/stack the payload will be applied to. `Shipit.github_app_config` treats `webhook_secret` as fully optional per-organization, and this optionality is documented and exercised in the multi-org secrets fixture (`test/dummy/config/secrets_double_github_app.yml`), so it's a legitimate, supported deployment shape, not a misconfiguration outside scope.

Once `verify_signature` passes, `create` dispatches the raw JSON body to the relevant handler: [4](#0-3) 

Handlers determine the actual target stack from a *different* field, `repository.full_name`, completely independent from `repository.owner.login`/`organization.login` used during verification: [5](#0-4) 

For example, `PushHandler` looks up stacks by branch on whatever repository `repository.full_name` resolves to and triggers a sync: [6](#0-5) 

and `StatusHandler` writes commit statuses purely by SHA lookup, with no cross-check against the organization used for verification: [7](#0-6) 

**The broken binding, stated as an equality that fails to hold:**
`organization authenticated (repository.owner.login / organization.login used to select webhook_secret)` ≠ `repository actually written (repository.full_name used by Handler#stacks / repository_name)`.

Before the attack: for organization `A` (no `webhook_secret` configured) and organization `B` (properly secured with a `webhook_secret`), a legitimate webhook for `B/some-repo` must carry a valid HMAC computed with `B`'s secret.

After the attacker's crafted request: a POST to `/webhooks` with `repository.owner.login = "A"` (or `organization.login = "A"`) and `repository.full_name = "B/some-repo"` passes `verify_signature` unconditionally (because `A` has no secret), then is dispatched with the full unmodified body to the handler, which acts on `B/some-repo` exactly as if GitHub itself had sent it.

### Impact Explanation
This allows an unauthenticated, unprivileged attacker to forge arbitrary webhook events (`push`, `status`, `check_suite`, `pull_request`, `membership`, etc.) targeting any repository/stack configured in the Shipit instance, as long as any single organization in the multi-tenant config lacks a `webhook_secret`. Concretely this can: force `Stack#sync_github` with an attacker-chosen `expected_head_sha` via a forged `push` event, inject arbitrary commit statuses via a forged `status` event to unblock deploy gating, or manipulate PR/merge-status handling — all without possessing any `webhook_secret`, `ApiClient` token, or GitHub credentials. This crosses the "unauthorized deploy/rollback/merge" impact bar since forged commit statuses and sync triggers can unblock or trigger deploys that should have required a verified GitHub-originated event.

### Likelihood Explanation
Likelihood depends on the deployment having at least one configured organization without a `webhook_secret` in a multi-org setup — a configuration explicitly documented as optional and exercised in the engine's own multi-org fixtures. No credentials, session, or prior access are required; the attacker only needs to know (or guess) the name of one under-configured organization in the target Shipit instance and craft a single unauthenticated HTTP POST to `/webhooks`.

### Recommendation
Do not let attacker-controlled body fields determine which secret gates verification independently from what's acted upon. At minimum: (1) require `webhook_secret` to be present for every configured organization (reject config where it's blank in production), removing the `return true unless webhook_secret` bypass, or (2) after selecting the app/secret via `repository_owner`, re-validate that `repository.full_name`'s owner matches the same organization actually used for verification before dispatching to handlers.

### Proof of Concept
1. Configure Shipit in multi-org mode with organization `unsecured-org` (no `webhook_secret`) and organization `victim-org` (with `webhook_secret` set), both installed, with `victim-org/target-repo` tracked as a Shipit stack.
2. Send:
```
POST /webhooks
X-Github-Event: push
X-Hub-Signature: sha1=anything-or-omitted

{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "full_name": "victim-org/target-repo",
    "owner": { "login": "unsecured-org" }
  }
}
```
3. `verify_signature` resolves `repository_owner` = `"unsecured-org"`, fetches its `GitHubApp`, and `verify_webhook_signature` returns `true` immediately because `unsecured-org` has no `webhook_secret`.
4. `create` dispatches the payload to `PushHandler`, which resolves `repository_name` = `"victim-org/target-repo"` and calls `sync_github(expected_head_sha: "<attacker-chosen-sha>")` on all matching stacks — a forged, unverified event acting on `victim-org`'s repository.

### Citations

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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
