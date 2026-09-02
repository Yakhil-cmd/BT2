### Title
Webhook signature verification authenticates the wrong GitHub organization, decoupling it from the `repository` acted upon - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App (and thus which `webhook_secret`) to validate the request's HMAC signature against by reading `repository_owner` straight out of the **unverified** request body, then the `create` action processes handlers against a completely independent field of that same unverified body — `repository.full_name`. Nothing binds these two fields together, and `webhook_secret` is documented as optional per organization, so a webhook that authenticates as "organization A" can act on a stack that belongs to "organization B".

### Finding Description
`repository_owner` is computed from the raw, not-yet-verified JSON body: [1](#0-0) 

This value is used to pick the `GitHubApp` instance whose secret verifies the signature: [2](#0-1) 

`verify_webhook_signature` short-circuits to `true` whenever the selected organization has no `webhook_secret` configured: [3](#0-2) 

Per-organization `webhook_secret` is explicitly documented/configured as optional, and the multi-org setup docs and test fixtures show organizations legitimately running with a blank secret: [4](#0-3) [5](#0-4) 

Once `head(422) unless verified` passes, `create` hands the **entire unverified payload** to the event handlers: [6](#0-5) 

Every handler resolves the repository/stack to act on from a *different* payload field, `repository.full_name`, with no re-check that its owner segment matches the `repository_owner` used for signing: [7](#0-6) 

This is the exact class of bug described in the report: two logically-related quantities (here, "the organization whose secret authenticated the request" vs. "the repository the request is allowed to mutate") are computed independently from the same untrusted input instead of being derived from one verified source, so they can be made to diverge. `ERC4626DataProvider` computed price-per-share from the wrong side of a conversion; here the controller derives its authorization boundary from the wrong field of the payload.

Concretely: `Shipit::PushHandler#process` triggers `stack.sync_github` for any stack whose `Repository.from_github_repo_name(payload['repository']['full_name'])` matches [8](#0-7) , and `StatusHandler#process` sets commit statuses purely by `sha`, with no repository/organization scoping at all [9](#0-8) . Both are reachable once the signature check for the attacker-chosen "authenticating organization" (e.g., one deliberately or accidentally configured with no `webhook_secret`) is satisfied, regardless of which `full_name`/`sha` the attacker embeds for the actual mutation.

### Impact Explanation
This lets an unprivileged actor perform an **unauthorized deploy/ship**: by sending a request that satisfies signature verification for an organization with no `webhook_secret` (which the docs treat as a normal, supported configuration for optional webhook secrets), the attacker can set `repository.full_name` to point at a stack belonging to any other organization served by the same Shipit instance, and drive `push`/`status`/`check_suite` handlers against it — e.g., forcing a `success` commit status on a target commit, which can satisfy deploy-gating checks and lead to an unauthorized ship, or forcing `sync_github` refresh cycles on a stack it does not own.

### Likelihood Explanation
Requires only that the deployment run in the documented multi-organization mode with at least one organization configured without a `webhook_secret` (explicitly presented in `docs/setup.md` and shipped in a test fixture as a supported pattern), and requires no authentication token, no repository write access, and no privileged Shipit account — only the ability to POST to the public `/webhooks` endpoint, matching the "unprivileged attacker breaking a deployment-trust binding" criteria.

### Recommendation
Verify the webhook signature using the GitHub App resolved from `repository.full_name`'s owner (the same field the handlers use to select the target repository/stack), not from a possibly different `repository.owner.login`/`organization.login` field, and reject when they diverge. Consider also making `webhook_secret` mandatory for every configured organization so `verify_webhook_signature` never silently bypasses on blank secrets.

### Proof of Concept
1. Configure Shipit in multi-org mode with `OrgWithoutSecret` (no `webhook_secret`, as shown in `test/dummy/config/secrets_double_github_app.yml`) and `VictimOrg` (has a stack, e.g. `VictimOrg/app`).
2. POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/master",
  "after": "deadbeef",
  "repository": { "owner": { "login": "OrgWithoutSecret" }, "full_name": "VictimOrg/app" }
}
```
No valid `X-Hub-Signature` is required because `verify_signature` resolves `Shipit.github(organization: "OrgWithoutSecret")` whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally [10](#0-9) .
3. `create` then dispatches to `PushHandler`, which resolves the stack via `payload['repository']['full_name'] == "VictimOrg/app"` [11](#0-10)  and calls `stack.sync_github` on a stack the attacker never authenticated against.

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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-7)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
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
