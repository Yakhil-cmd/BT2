### Title
Webhook signature verification is scoped by `repository.owner.login`, but repository resolution for the actual write action uses `repository.full_name` from the same attacker-controlled payload — ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to validate the HMAC signature against using the organization derived from `repository.owner.login` (or `organization.login`) in the JSON body. However, every `Webhooks::Handlers::Handler` subclass (e.g. `PushHandler`) resolves the `Stack`/`Repository` to act upon using a *different* field from the same body: `repository.full_name`. Because the HMAC only proves "this body was signed with organization X's secret", not "the repository named in this body belongs to organization X", an attacker who controls one legitimate GitHub App/organization onboarded to a multi-tenant Shipit instance can forge a payload whose `owner.login` matches their own org (so it authenticates) while `full_name` names a stack belonging to a *different* organization, causing Shipit to act on that victim stack.

### Finding Description
`verify_signature` computes the authenticating organization like this: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` looks up the `webhook_secret` configured for that organization (per the "Using Multiple GitHub Applications" setup documented in `docs/setup.md`, each org has its own `webhook_secret`). The HMAC is verified over the *entire* raw body using that org's secret: [3](#0-2) 

Once verification passes, `WebhooksController#create` dispatches to handlers with the same raw params: [4](#0-3) 

But every handler resolves the target `Repository`/`Stack` using a completely different key from the payload — `repository.full_name`, not `repository.owner.login`: [5](#0-4) 

`PushHandler`, for example, uses this `stacks` scope to trigger a GitHub sync for every matching, non-archived stack on the matching branch: [6](#0-5) 

Since the attacker constructs the whole JSON body themselves and only needs to know the `webhook_secret` of an organization they legitimately control (their own GitHub App installation), they can freely set `repository.owner.login` to their own org (satisfying `verify_webhook_signature`) while setting `repository.full_name` to `"victim-org/victim-repo"` — a repository belonging to a different, unrelated organization also configured on the same multi-tenant Shipit instance. The signature is a property of "which secret signed this exact byte-string", it carries no binding that `owner.login` and `full_name` refer to the same tenant. This is the same class of bug as the audited report: a value that is trusted and acted upon (`full_name` → the repository written to) is never actually covered/bound by the field that was cryptographically checked (`owner.login` → the organization that authenticated).

### Impact Explanation
This breaks the equality that should hold: `organization that authenticated == organization owning the repository being acted upon`. An attacker who is a legitimate GitHub App/organization admin on a shared, multi-org Shipit deployment can forge webhook events (push, pull_request, membership, etc.) that are cryptographically valid (signed with their own secret) but are routed to and executed against stacks belonging to a different organization/repository they do not control. For `push` events this triggers `stack.sync_github(expected_head_sha:)` on the victim's stack — a cross-organization action against a stack the attacker has no legitimate access to, and (depending on the target stack's continuous-deployment configuration) can feed into automatic deploy triggering. This matches the in-scope impact category of cross-repository writes / unauthorized deploy triggering across a repository authorization boundary that the attacker should not be able to cross.

### Likelihood Explanation
Likelihood is Medium: it requires the host application to be configured with the documented multi-organization GitHub App setup (`docs/setup.md`, "Using Multiple GitHub Applications"), and the attacker must control at least one legitimate organization/app onboarded to that same Shipit instance (a realistic scenario for a shared internal deploy tool used by multiple teams/orgs). No GitHub webhook secret theft, session, or `ApiClient` token is required — only knowledge of a secret the attacker legitimately possesses for their own org.

### Recommendation
Bind the field used for signature-verification scoping to the field used for repository resolution. Concretely, `WebhooksController#repository_owner` and every `Handler#repository_name` should derive their organization/repo values from the same trusted source, and handlers should additionally assert that `repository.full_name.split('/').first == repository_owner` (or equivalent) before acting, rejecting the payload if they diverge. Alternatively, verify the signature per-repository (looking up the `webhook_secret` via the resolved `full_name`'s registered `Repository`) rather than via the loosely related `owner.login`/`organization.login` field.

### Proof of Concept
1. Shipit is configured with two GitHub Apps/organizations in `secrets.yml`: `attacker-org` (secret known to the attacker, who administers that org's GitHub App) and `victim-org` (contains stack `victim-org/victim-repo`).
2. Attacker crafts a JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(attacker-org_webhook_secret, body)`.
4. POSTs to `/webhooks` with `X-Github-Event: push`.
5. `verify_signature` calls `Shipit.github(organization: 'attacker-org')` and successfully verifies the HMAC against the attacker's own secret — request passes.
6. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name('victim-org/victim-repo')`, and calls `stack.sync_github(expected_head_sha: '<attacker-chosen sha>')` on the victim's stack, an action the attacker was never authorized to trigger.

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
