### Title
Webhook signature verified against `repository.owner.login`/`organization.login` while all event handlers act on the independent `repository.full_name` field, allowing signature bypass for arbitrary tracked repositories - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to validate a payload against using `repository.owner.login` (falling back to `organization.login`), but every `Shipit::Webhooks::Handlers::Handler` subclass (push, status, check_suite, pull_request, etc.) resolves the actual repository/stack to write to using the unrelated `repository.full_name` field of the same JSON body. Nothing ties these two fields together, so the org whose secret authenticates the request is not guaranteed to be the org whose repository is mutated.

### Finding Description
`verify_signature` picks the signing organization like this: [1](#0-0) [2](#0-1) 

```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

The chosen `GitHubApp` (and its `webhook_secret`) is looked up via `Shipit.github(organization: repository_owner)` and used to validate `X-Hub-Signature`. `verify_webhook_signature` intentionally treats an unconfigured secret as “trusted”: [3](#0-2) 

```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
```

`webhook_secret` is explicitly documented as optional per organization, and Shipit supports multiple independently configured GitHub Apps/organizations sharing one `/webhooks` endpoint (`docs/setup.md`, `test/dummy/config/secrets_double_github_app.yml`), so it is realistic for at least one configured organization to have no secret set while others do.

Meanwhile, every webhook handler ignores `repository.owner.login`/`organization.login` entirely and instead resolves the target repository/stack from `repository.full_name`: [4](#0-3) 

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

This is precisely the same class of bug as the referenced report: two values that *should* represent the same underlying entity (here: “the organization whose credentials authorize this event” vs. “the repository this event is applied to”) are computed from different fields, and the code that performs the security check (`repository_owner`) is never cross-checked against the field the mutating logic actually consumes (`repository.full_name`). The binding that should hold — `authenticating_org == owner(repository.full_name)` — is never enforced.

Concretely: `StatusHandler` (exercised in `test/controllers/webhooks_controller_test.rb:42-59`) copies `sha`, `state`, `description`, `target_url`, and `context` straight from the payload onto a `Commit#statuses` record for whatever repository `repository.full_name` names — with no re-verification against GitHub's API.

### Impact Explanation
If any organization configured in `Shipit.secrets.github` has no `webhook_secret` set (an explicitly supported/optional configuration per `docs/setup.md`), an unauthenticated attacker can POST to the public `/webhooks` endpoint with:
- `repository.owner.login` (or `organization.login`) = the unconfigured/secret-less organization (so `verify_webhook_signature` short-circuits to `true`), and
- `repository.full_name` = any other tracked repository (e.g. a victim organization's stack that Shipit does have installed with real deploy permissions).

The forged event then flows into the real handler for that victim stack. For `status` events this injects a forged commit status (state/description/target_url/context) onto an arbitrary commit of a stack the attacker has no push/write access to. Since Shipit's CI/merge gating (`ci.require`, `merge.require`) is driven by these stored `Status` records, this can be used to make a commit that never passed real CI appear to satisfy deploy/merge requirements, contributing to an unauthorized deploy or merge — this crosses the "authentication bypass" / "unauthorized deploy, rollback or merge" impact bar, breaking the authentication boundary the webhook signature is supposed to provide.

### Likelihood Explanation
The `/webhooks` endpoint is intentionally unauthenticated at the HTTP layer (`skip_before_action :verify_authenticity_token`), and reachable by anyone; the only gate is `verify_signature`. The precondition (one configured organization without a webhook secret) is a documented, supported configuration, not a hypothetical — `docs/setup.md` calls the webhook secret "optional." No attacker credential, GitHub session, or Shipit account is required; the only requirement is knowledge of the name of any organization/app configured in the target Shipit instance without a secret, and the target repository's `full_name`, both of which are typically public GitHub metadata.

### Recommendation
Cross-validate that the organization used to select/verify the webhook signature actually matches the owner of `repository.full_name` (or the target `organization.login`) before dispatching to handlers, instead of trusting `repository.full_name` independently of the field used for signature selection. Additionally, consider requiring `webhook_secret` to be present for every configured organization (removing the `return true unless webhook_secret` bypass), so an unconfigured secret can never silently authenticate arbitrary payloads.

### Proof of Concept
Given a Shipit deployment configured with two GitHub organizations (mirroring `test/dummy/config/secrets_double_github_app.yml`), where `OrgWithoutSecret` has `webhook_secret: nil` and `VictimOrg/victim-repo` is a tracked stack with a real secret:

```
POST /webhooks
X-Github-Event: status
X-Hub-Signature: sha1=anything   # ignored, secret is nil for OrgWithoutSecret

{
  "sha": "<any commit sha on victim-repo>",
  "state": "success",
  "description": "forged",
  "target_url": "https://attacker.example.com",
  "context": "ci/required-check",
  "repository": {
    "owner": { "login": "OrgWithoutSecret" },
    "full_name": "VictimOrg/victim-repo"
  }
}
```

`verify_signature` calls `Shipit.github(organization: "OrgWithoutSecret").verify_webhook_signature(...)`, which returns `true` immediately because that org's `webhook_secret` is blank (`lib/shipit/github_app.rb:76-77`). The request then reaches `Shipit::Webhooks::Handlers::StatusHandler`, which resolves the stack via `payload.dig('repository', 'full_name')` == `"VictimOrg/victim-repo"` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`) and creates/updates a `Status` record on that stack's commit exactly as shown in `test/controllers/webhooks_controller_test.rb:42-59` — with attacker-controlled `state`, `description`, and `target_url`, despite the attacker never having presented a valid signature for `VictimOrg`.

### Citations

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
