### Title
Webhook signature check authenticates a payload-supplied organization while stack-mutating handlers act on a payload-supplied `repository.full_name` string, letting a webhook to an unsecured/less-trusted org drive writes against any other organization's stack - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` derives the GitHub organization used to select the HMAC secret from `params.dig('repository','owner','login') || params.dig('organization','login')` [1](#0-0) , and hands the raw request body to `Shipit.github(organization: repository_owner).verify_webhook_signature`, which explicitly returns `true` ("verified") whenever that organization has no `webhook_secret` configured: `return true unless webhook_secret` [2](#0-1) . Once "verified", the event is handed unchanged to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [3](#0-2) . Every mutating handler (push, pull_request, check_suite, status) resolves the target `Stack`/`Repository` from a **different** field of the same untrusted payload - `payload.dig('repository','full_name')` - via `Handler#repository_name`/`#stacks` [4](#0-3)  and equivalently in each pull-request handler [5](#0-4) .

### Finding Description
The security property the webhook signature is supposed to enforce is: *the organization whose secret validated this request equals the organization/repository that gets written to*. In this engine those are two independent fields inside the same attacker-suppliable JSON body:

- Verification key selection: `repository.owner.login` (or `organization.login`) → `repository_owner` [1](#0-0) .
- Write target selection: `repository.full_name` → `Repository.from_github_repo_name(repository_name)` → `.stacks` [4](#0-3) .

`verify_webhook_signature` only proves that *if a secret exists for the org named in `repository.owner.login`*, the request producer knew that secret. But when that particular org has **no** `webhook_secret` configured (an explicitly supported, documented configuration - "Webhook secret (optional)" in `docs/setup.md` [6](#0-5) ), the check is a no-op: `return true unless webhook_secret` [7](#0-6) . An unauthenticated internet client can then send `POST /webhooks` with:
- `X-Github-Event: push`
- body: `{"repository": {"owner": {"login": "<org-without-secret>"}, "full_name": "<victim-org>/<victim-repo>"}, "ref": "refs/heads/<branch>", "after": "<attacker-chosen-sha>"}`

`verify_signature` resolves `Shipit.github(organization: "<org-without-secret>")`, finds no secret, returns `true`, and logs success [8](#0-7) . `PushHandler#process` then looks up stacks for `full_name == "<victim-org>/<victim-repo>"` (a completely different org whose secret is/was never checked) and calls `stack.sync_github(expected_head_sha: params.after)` for every matching, non-archived stack on the matching branch [9](#0-8) , forcing a sync against an attacker-chosen `expected_head_sha` for a repository/organization that the request was never authenticated against.

The same split applies to `check_suite`, `status`, and all `pull_request` sub-handlers, each of which independently trusts `repository.full_name` (or `organization.login` for `membership`) taken from the same unverified-per-target payload [5](#0-4) .

### Impact Explanation
This breaks the binding "organization authenticated == repository written." Any stack belonging to any other organization configured in this Shipit instance (as long as at least one configured org lacks a `webhook_secret`, which the setup docs present as an optional field, not a requirement) can have its GitHub-sync state, check-suite refresh, or commit-status data force-updated by a fully unauthenticated, credential-less HTTP request. `sync_github` with an attacker-controlled `expected_head_sha` can move a stack's understanding of "what SHA is deployable" and drive it toward triggering continuous-deployment tasks/deploys on the target stack, which maps to the report's "unauthorized deploy" impact category. No GitHub App private key, `webhook_secret`, `api_clients_secret`, or session is required by the attacker for the specific org they name in `repository.owner.login` — that is precisely the org configuration that skips verification.

### Likelihood Explanation
Likelihood depends on operational configuration: it requires at least one organization configured in `Shipit.github` without a `webhook_secret`. Since the setup documentation frames the webhook secret as optional (`docs/setup.md` line 30: "Webhook secret (optional)"), and multi-tenant Shipit deployments commonly maintain several org configs (e.g. `config/secrets.development.shopify.yml` shows a multi-org shape with `webhook_secret: # nil` for both entries) [10](#0-9) , this is a realistic and even sample-encouraged deployment pattern, not a contrived edge case.

### Recommendation
Bind verification and write target to the same field: derive `repository_owner` for signature lookup from the exact same `repository.full_name` (or a canonicalized owner+repo pair) that handlers use to resolve the target `Stack`, and refuse to treat "no configured secret" as automatically verified when the resolved repository/stack belongs to a different, secret-protected organization. At minimum, require `webhook_secret` for every configured organization and reject webhooks for organizations without one instead of silently succeeding, and re-verify that the organization used for signature verification matches the owner encoded in `repository.full_name` before dispatching to handlers.

### Proof of Concept
1. Deploy this Shipit instance with two orgs configured under `Shipit.github`: `victim-org` (has `webhook_secret: <secret>`, owns a tracked `Stack` for `victim-org/app`) and `open-org` (no `webhook_secret`, e.g. per the template's optional field).
2. As an unauthenticated client, POST to `/webhooks`:
   ```
   POST /webhooks
   X-Github-Event: push
   {
     "repository": {"owner": {"login": "open-org"}, "full_name": "victim-org/app"},
     "ref": "refs/heads/main",
     "after": "<attacker-chosen-sha>"
   }
   ```
3. `verify_signature` computes `repository_owner = "open-org"`, calls `Shipit.github(organization: "open-org").verify_webhook_signature(...)`, which returns `true` because `open-org` has no `webhook_secret` [7](#0-6) .
4. `Shipit::Webhooks.for_event('push')` dispatches to `PushHandler`, which resolves `Repository.from_github_repo_name("victim-org/app")` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on the `victim-org` stack [9](#0-8)  - an org whose webhook secret was never checked.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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
