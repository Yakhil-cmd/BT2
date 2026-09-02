### Title
Webhook organization used for signature verification is decoupled from the repository resolved for action, allowing cross-repository webhook forgery when any configured GitHub organization has no `webhook_secret` - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to validate a webhook against using one field of the attacker-supplied JSON body (`repository.owner.login` / `organization.login`), while every webhook `Handler` resolves the repository/stack to act on using a *different, independently-controlled* field of the same body (`repository.full_name`). Nothing binds these two fields together. Combined with `GitHubApp#verify_webhook_signature` returning `true` unconditionally when `webhook_secret` is blank (an explicitly documented/optional setting), this lets anyone who can produce a validly-signed body for *one* configured organization (including an organization with no secret configured) direct the resulting action at a stack belonging to a *different* organization.

### Finding Description
`verify_signature` derives the organization used to pick the verification secret from the payload itself: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` looks up the org-specific config and calls `verify_webhook_signature`, which is a no-op when the org has no `webhook_secret` set: [3](#0-2) 

`webhook_secret` is documented as optional (“If you've set a webhook secret during the App creation, you should copy it here”), and example/reference configs ship it commented out as `nil`, meaning an organization can legitimately be configured in Shipit without one: [4](#0-3) [5](#0-4) 

Once past `verify_signature`, every webhook `Handler` resolves the target repository/stack from an entirely different, attacker-controlled JSON field (`repository.full_name`), with no cross-check against the organization that was actually verified: [6](#0-5) 

This is the exact "decimals mismatch" analog: the code assumes `repository_owner` (the value covered by/used for the security check) and `repository.full_name` (the value the code actually acts on) always refer to the same repository, but never verifies this invariant. The `WebhooksController` is a public, unauthenticated endpoint (only `verify_signature` gates it), so any actor who can produce a request body is fully in control of both fields independently.

### Impact Explanation
An attacker who knows (or is not required to know, because it's unset) the `webhook_secret` for organization A can craft a raw POST to the webhooks endpoint with `repository.owner.login = "A"` (or `organization.login = "A"`) to pass `verify_signature`, while setting `repository.full_name = "B/target-repo"` for a completely different, properly-secured organization B's stack. Handlers such as `PushHandler` will then act on stack B: [7](#0-6) 

This breaks the intended equality "organization that authenticated == organization/repository being written," and can be used to trigger `sync_github`/status/PR-driven actions on any stack tracked by Shipit regardless of which organization's credentials were actually verified — a cross-repository-write style compromise of the deployment-trust boundary the signature check is meant to enforce.

### Likelihood Explanation
Requires that at least one GitHub organization configured in the Shipit instance has no `webhook_secret` set — an explicitly supported, documented configuration state, not a hardening failure the engine itself prevents or warns about. In any deployment using the documented multi-org config pattern where one org is left with the default/optional (nil) secret, exploitation requires only unauthenticated HTTP access to the public webhooks endpoint.

### Recommendation
1. In `Handler#stacks`/`#repository_name`, cross-validate that the repository/organization resolved from the payload matches the organization that was actually verified in `verify_signature` (e.g., pass the verified organization into the handler and assert `repository.owner.login == verified_organization`).
2. Do not treat a missing `webhook_secret` as "verification passed" — either require a secret for every configured organization or fail closed (reject) instead of returning `true` in `GitHubApp#verify_webhook_signature`.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` (no `webhook_secret` set) and `OrgB` (has a stack, e.g. `OrgB/prod-app`, with a real secret).
2. POST directly to the webhooks endpoint with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "full_name": "OrgB/prod-app",
    "owner": { "login": "OrgA" }
  }
}
```
No `X-Hub-Signature` value is needed to pass verification because `OrgA` has no secret (`verify_webhook_signature` returns `true` unconditionally).
3. `WebhooksController#repository_owner` resolves to `"OrgA"`, so `verify_signature` passes trivially.
4. `PushHandler#stacks` resolves `Repository.from_github_repo_name("OrgB/prod-app")`, and `sync_github(expected_head_sha: "<attacker-chosen-sha>")` is invoked on `OrgB`'s stack — action taken on an organization's repository never covered by any verified signature.

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

**File:** config/secrets.development.example.yml (L8-16)
```yaml
github:
  app_id:
  installation_id:
  webhook_secret: # nil
  private_key:
  oauth:
    id:
    secret:
    teams: # Optional
```

**File:** docs/setup.md (L117-119)
```markdown
**`github.bot_login`** The login of the App [bot] user. Every GitHub App have an associated `[bot]` user which acts as the author of the App actions through the API, for example when an App merges a Pull Request. It should be the App "slug" with the suffix `[bot]`. For example if your app settings URL is `https://github.com/organizations/ACME/settings/apps/acme-shipit/installations`, the bot user should be `acme-shipit[bot]`. If you are unsure, you can leave it empty.

**`github.webhook_secret`** If you've set a webhook secret during the App creating, you should copy it here.
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
