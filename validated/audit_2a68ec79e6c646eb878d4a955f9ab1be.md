### Title
Webhook signature verification is bound to an attacker-controlled `repository.owner.login` while the write target is taken from an independent `repository.full_name` field - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization config (and thus which `webhook_secret`) to validate a webhook against using a value read straight out of the *unverified* JSON body, while the code path that actually performs the write (finding the `Repository`/`Stack` and mutating state) reads a *different* field from that same unverified body. Because these two fields are never cross-checked, and because signature verification is trivially bypassed for any organization configured without a `webhook_secret`, an attacker can make Shipit accept an unsigned/forged payload that is "verified" against one (weakly-configured) organization but whose effects are applied to a completely unrelated repository/stack.

### Finding Description
`verify_signature` computes `repository_owner` from the raw, not-yet-verified request body: [1](#0-0) [2](#0-1) 

It then fetches the per-organization GitHub App config with `Shipit.github(organization: repository_owner)` and calls `verify_webhook_signature`: [3](#0-2) 

Critically, `verify_webhook_signature` returns `true` unconditionally whenever that organization's `webhook_secret` is blank, i.e. verification is silently skipped for any org that doesn't have a secret configured.

Meanwhile, once the request passes (or bypasses) verification, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches to handlers whose write target is derived from a *different* JSON field, `repository.full_name`, not `repository.owner.login`: [4](#0-3) [5](#0-4) 

Because `repository.owner.login` (used to pick which org's secret gates the request) and `repository.full_name` (used to pick which repository/stack is actually mutated) are independent, attacker-controlled fields inside the same unauthenticated JSON body, the "organization that authenticated" and "the repository that is written" are not the same binding. If Shipit hosts multiple organizations (`secrets.github` keyed by org) and any one of them has no `webhook_secret` configured — a plausible misconfiguration, since the multi-org schema is explicitly supported (`TOP_LEVEL_GH_KEYS`, `github_app_config`) — an attacker can craft a payload such as:
```json
{ "repository": { "owner": { "login": "org-with-no-secret" }, "full_name": "victim-org/victim-repo" } }
```
`verify_signature` resolves the org via the forged `owner.login`, finds no secret, and accepts the request with no valid signature at all, while the handlers act on `victim-org/victim-repo`, a repository belonging to a different, correctly-configured organization.

### Impact Explanation
This lets an unauthenticated attacker inject forged GitHub events (e.g. `status`, `membership`, `push`, `check_suite`, `pull_request`) against any repository/stack tracked by the Shipit instance, as long as one org in the multi-tenant configuration lacks a `webhook_secret`. Concretely reachable effects include fabricating commit statuses on a victim repository's commits via the `status` handler (which directly persists attacker-supplied `state`/`target_url`/`description` for a real commit) and creating/removing team memberships via the `membership` handler — both cross-repository/cross-tenant writes that should require possession of that repository's own webhook secret. This is a cross-repository-write class issue.

### Likelihood Explanation
Exploitability depends on the deployment having more than one organization configured under `secrets.github` with at least one entry missing a `webhook_secret`; this is a realistic operational misconfiguration rather than a code path requiring any credential, but it is not guaranteed to exist in every deployment, and I could not verify from the indexed engine code whether the documented setup process enforces `webhook_secret` presence for every org entry (that enforcement, if any, would live in host-application config, which is out of scope here).

### Recommendation
Verify the webhook signature using the secret resolved from the same repository object that will be acted upon, and require signature verification to fail closed (return `false`, not `true`) when no `webhook_secret` is configured for an organization, or reject requests for organizations without a configured secret. Additionally, cross-check that `repository.owner.login` and the owner segment of `repository.full_name` refer to the same organization before dispatching handlers.

### Proof of Concept
1. Configure (or discover) a Shipit deployment with `secrets.github` containing two orgs, where `orgA` has no `webhook_secret`.
2. Send `POST /webhooks` with `X-Github-Event: status` and body:
```json
{
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/victim-repo" },
  "sha": "<real commit sha in orgB/victim-repo>",
  "state": "success",
  "target_url": "https://attacker.example/fake-ci",
  "description": "forged",
  "context": "ci/forged"
}
```
No `X-Hub-Signature` header is required.
3. `verify_signature` resolves `Shipit.github(organization: "orgA")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally: [6](#0-5) .
4. The `status` handler then resolves the target repository via `payload.dig('repository', 'full_name')` = `orgB/victim-repo` and persists the forged commit status on that unrelated repository's commit: [4](#0-3) .

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
