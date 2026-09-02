### Title
Webhook signature verification is bound to the payload's `repository.owner.login` GitHub App config while the actual write target is resolved from the unrelated `repository.full_name` field, allowing cross-repository webhook forgery when any configured organization has no `webhook_secret` - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate a webhook against based solely on `repository.owner.login` (or `organization.login`) from the *unverified* JSON payload, via `Shipit.github(organization: repository_owner)`. `GitHubApp#verify_webhook_signature` unconditionally returns `true` when that organization's `webhook_secret` is blank. Meanwhile, every event handler (`Shipit::Webhooks::Handlers::Handler#repository_name`) resolves which local `Repository`/`Stack` to act on using a completely different field, `repository.full_name`. Because the field used to pick the authentication context and the field used to pick the affected repository are not the same, and because the authentication check can be trivially bypassed for one organization, a payload can authenticate as an unprotected organization while acting on a stack that belongs to a different, protected repository/organization.

### Finding Description
Verification path: [1](#0-0) [2](#0-1) 

The GitHub App/secret used for verification is chosen using `repository_owner`, taken straight out of the still-unauthenticated JSON body. The actual HMAC check is: [3](#0-2) 

`return true unless webhook_secret` means that for any organization configured in `Shipit.github` **without** a `webhook_secret` (an explicitly optional setting per the setup docs, and a realistic state for a secondary/legacy organization in a multi-org install such as the one exercised by `test/dummy/config/secrets_double_github_app.yml`), the signature check is skipped entirely — any payload claiming to belong to that organization is accepted regardless of the `X-Hub-Signature` header.

Once accepted, `params` (the raw untrusted body) is dispatched to handlers: [4](#0-3) 

Handlers resolve the affected `Stack`s using a *different* payload field, `repository.full_name`, not `repository.owner.login`: [5](#0-4) 

For example `PushHandler` forces a GitHub sync for any stack matching that `full_name`: [6](#0-5) 

The binding that should hold is:
`organization used to select/verify the webhook secret == organization/repository actually written to by the handler`

but the engine instead enforces only:
`repository.owner.login (used for auth selection) ⊥ repository.full_name (used for the actual write)` — two independent, attacker-controlled fields inside the same unauthenticated JSON body, joined only by an authentication step that can degrade to a no-op for organizations without a `webhook_secret`.

### Impact Explanation
An unprivileged attacker who knows (or guesses) that at least one GitHub organization configured on the Shipit instance has no `webhook_secret` set can send a forged webhook whose `repository.owner.login`/`organization.login` matches that unprotected organization while `repository.full_name` names an arbitrary tracked repository belonging to a *different, protected* organization. This bypasses the intended per-organization trust boundary and lets the attacker:
- Force `GithubSyncJob`/`sync_github` runs and inject fabricated `expected_head_sha` values for any tracked stack (`PushHandler`).
- Inject fabricated commit statuses / check-run results (`StatusHandler`, `CheckSuiteHandler`) for arbitrary tracked commits, which can flip a commit's CI state to `success` and, on stacks with continuous deployment enabled, trigger an unauthorized deploy.
- Drive other webhook-consuming state (merge/PR handlers) for repositories the attacker has no access to.

This crosses the "unauthorized deploy" / cross-repository-write bar defined as Critical impact in this engine.

### Likelihood Explanation
Exploitability depends entirely on whether any configured GitHub organization in `Shipit.github` has an unset `webhook_secret`. This is an explicitly supported and documented configuration (multi-organization Shipit installs are a first-class feature, evidenced by `test/dummy/config/secrets_double_github_app.yml`, and `webhook_secret` is documented as optional). No credentials, session, or repository access are required to send the forged HTTP request to the public `/webhooks` endpoint. Given multi-org installs are common in shared Shipit deployments and per-org `webhook_secret` configuration is easy to omit for a secondary/legacy org, likelihood is Medium-to-High wherever such multi-org configurations exist.

### Recommendation
- Never allow `verify_webhook_signature` to short-circuit to `true` when `webhook_secret` is blank; either require a `webhook_secret` for every configured organization or fail closed (reject the webhook) rather than treating "no secret configured" as "trust everything."
- After signature verification succeeds, re-derive the acting organization from the *same* field (`repository.owner.login`) used to select the verifying secret, and assert it matches the organization owning the repository resolved via `repository.full_name` inside each handler, rejecting the request if they diverge.

### Proof of Concept
1. Configure (or find) a Shipit instance with two GitHub organizations in `Shipit.github` config, where `OrgB` has no `webhook_secret` set (legal per docs, mirrors `test/dummy/config/secrets_double_github_app.yml`).
2. As an unauthenticated attacker, `POST /webhooks` with header `X-Github-Event: push` and no valid `X-Hub-Signature` (or any arbitrary value), and body:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "owner": { "login": "OrgB" },
    "full_name": "OrgA/private-production-app"
  }
}
```
3. `verify_signature` calls `Shipit.github(organization: 'OrgB').verify_webhook_signature(...)`, which returns `true` immediately because `OrgB` has no `webhook_secret` — the forged signature is accepted.
4. `PushHandler#stacks` resolves `Repository.from_github_repo_name('OrgA/private-production-app')` and calls `stack.sync_github(expected_head_sha: 'deadbeef...')`, forcing a sync/behavior on a stack belonging to the unrelated, protected `OrgA`, entirely under attacker control and without ever presenting a valid signature for `OrgA`.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-17)
```ruby
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
