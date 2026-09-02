### Title
Webhook signature verification keyed by attacker-controlled `repository.owner.login`/`organization.login`, while handlers act on the independently-controlled `repository.full_name` - authentication bypass ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate the HMAC signature against using a field taken from the untrusted JSON payload (`repository.owner.login`, falling back to `organization.login`), not from the field the event handlers actually use to decide which `Stack`/`Repository` to act on (`repository.full_name`). This is the same class of bug as the Sherlock finding: a value that is verified/authorized (here, "which org's secret legitimizes this request") is decoupled from the value that is actually acted upon (here, "which repository/stack receives the effect"), letting an attacker substitute one for the other.

### Finding Description
In `app/controllers/shipit/webhooks_controller.rb`: [1](#0-0) 
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
``` [2](#0-1) 
```ruby
def repository_owner
  # Fallback to the organization sub-object if repository isn't included in the payload
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

The webhook secret itself is optional per organization/app config (see `config/secrets.development.example.yml` / `config/secrets.development.shopify.yml`, `webhook_secret: # nil`), and `lib/shipit/github_app.rb` explicitly treats an unconfigured secret as "always verified": [3](#0-2) 
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret

  algorithm, signature = signature.split("=", 2)
  return false unless algorithm == 'sha1'

  SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
end
```

Meanwhile, none of the actual event handlers use `repository.owner.login`/`organization.login` to determine what is acted on. They resolve the target `Repository`/`Stack` from `repository.full_name`, a completely separate, independently-attacker-controlled JSON field: [4](#0-3) 
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [5](#0-4) 

Because `repository.owner.login`/`organization.login` and `repository.full_name` are two unrelated fields inside the same unsigned-until-verified JSON body, an attacker can craft a payload where:
- `repository.owner.login` (or `organization.login`) = an organization configured in Shipit with no `webhook_secret` (or one whose secret the attacker knows), causing `verify_webhook_signature` to short-circuit and return `true`.
- `repository.full_name` = a different, victim organization's repository that Shipit actually tracks stacks for.

The signature check passes (against the "wrong" org's non-existent/weak secret), yet the handler dispatched in `WebhooksController#create` executes against the victim repository's real `Stack` records: [6](#0-5) 
```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
  head(:ok)
end
```

This breaks the intended equality: `organization whose credential authenticated the request == organization owning the repository the effect is applied to`. That equality is never enforced — verification uses one org-derived field, execution uses an unrelated repository-full-name field.

### Impact Explanation
This is an authentication-bypass class issue affecting webhook-driven state mutation for stacks belonging to *other, unrelated* organizations/repositories than the one whose (possibly absent) secret validated the request. Concretely, with multi-organization Shipit deployments (the supported `config/secrets*.yml` multi-org format), an attacker who can reach the `/webhooks` endpoint and knows (or exploits an org with no configured `webhook_secret`) can:
- Trigger `Handlers::PushHandler#process`, causing `stack.sync_github(expected_head_sha:)` against any tracked stack belonging to a different organization — an unauthenticated/unauthorized action on state the attacker was never entitled to influence via that org's credentials.
- Similarly influence `StatusHandler`, `MembershipHandler`, `CheckSuiteHandler`, and `PullRequest::*` handlers for stacks/teams that have nothing to do with the "verified" organization, since none of those handlers re-check that the acted-upon repository belongs to the org that was cryptographically verified.

This satisfies the High-severity bucket ("escalation into authorization boundaries / unauthenticated read or mutation of stack state") because the attacker forges a request that is accepted as authentic for organization A but is used to mutate/observe stack state that legitimately belongs to organization B, entirely bypassing the per-organization webhook trust boundary Shipit is designed to enforce.

### Likelihood Explanation
Exploitability depends on the deployment having at least one configured GitHub organization with a blank/absent `webhook_secret` (explicitly supported and shown as the default in the example secrets files) while other organizations' repositories are tracked in the same Shipit instance — a realistic multi-tenant configuration. No authentication token, session, or GitHub App private key is required; the attacker only needs network access to the public `/webhooks` endpoint and knowledge of which organization is unprotected (discoverable by trial, since a failed match on `repository_owner` triggers a distinguishable `422`/log difference from a genuinely wrong signature vs. an unknown organization).

### Recommendation
Bind the verified identity to the acted-upon entity: after selecting `github_app` based on `repository_owner`, require that the same value equals the owner parsed out of `repository.full_name` (i.e., `full_name.split('/').first`) before dispatching handlers, rejecting mismatches with `422`. Alternatively, refuse to treat `verify_webhook_signature` as satisfied when `webhook_secret` is blank in any multi-organization configuration, or require every configured organization to have a non-blank `webhook_secret` when more than one organization is configured.

### Proof of Concept
1. Configure Shipit with two organizations in `secrets.yml`: `attacker-org` (no `webhook_secret` set) and `victim-org` (has a `webhook_secret`, tracks a real `Stack` for `victim-org/victim-repo`).
2. POST to `/webhooks` with header `X-Github-Event: push` and a body:
```json
{
  "ref": "refs/heads/main",
  "after": "<sha>",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
}
```
3. `repository_owner` resolves to `attacker-org`; `Shipit.github(organization: "attacker-org")` has no `webhook_secret`, so `verify_webhook_signature` returns `true` regardless of the (even absent/garbage) `X-Hub-Signature` header.
4. `Shipit::Webhooks.for_event('push')` runs `PushHandler`, which resolves the target stack via `repository.full_name` = `"victim-org/victim-repo"` and calls `stack.sync_github(expected_head_sha: ...)` on the real victim stack — an action performed without ever presenting a valid signature for `victim-org`.

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
