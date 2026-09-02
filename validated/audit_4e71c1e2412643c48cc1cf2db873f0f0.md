### Title
Webhook signature is verified against `repository.owner.login`/`organization.login` while event handlers act on the unbound `repository.full_name` field, letting a forged payload target any tracked stack under a different organization - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
Just as the PoolTogether `rngComplete` finding allowed an attacker to supply an unchecked `_rewardRecipient` that diverged from the entity actually completing the auction, `WebhooksController` selects *which* GitHub App/organization secret to verify a webhook against using one payload field, while the handlers that mutate state act on a *different, independently attacker-controlled* payload field. Because both fields live in the same unauthenticated JSON body (the signature has not been checked yet when they are read), an attacker can decouple "the organization whose secret authenticated the request" from "the repository/stack that is actually written to."

### Finding Description
`WebhooksController#verify_signature` picks the GitHub App config to verify against using: [1](#0-0) [2](#0-1) 

`repository_owner` reads `params.dig('repository', 'owner', 'login')` (or `organization.login`) from the still-unverified request body, then `Shipit.github(organization: repository_owner)` is used to pick the app config whose `webhook_secret` is checked via `verify_webhook_signature`: [3](#0-2) 

Note that if that organization's `webhook_secret` is blank/unset (a documented, supported configuration - see `config/secrets.development.example.yml` and `test/dummy/config/secrets.yml` where `webhook_secret: # nil`), `verify_webhook_signature` returns `true` unconditionally, i.e. **no verification occurs at all** for that org.

Once past `verify_signature`, every handler resolves the target `Stack`/`Repository` from a *different* key of the same attacker-supplied JSON: [4](#0-3) 

So `repository.owner.login` (used to select/verify the signing secret) and `repository.full_name` (used to find the actual Stack that gets mutated) are two independent fields inside one unsigned/forge-able JSON body at the time they are read. In a multi-organization deployment (explicitly supported and tested - `test/dummy/config/secrets_double_github_app.yml` configures per-org `webhook_secret`s), or in any deployment where at least one configured organization has `webhook_secret` left blank, an attacker can:

1. Set `repository.owner.login` (or `organization.login`) to the organization whose secret is blank/known, satisfying `verify_signature`.
2. Set `repository.full_name` to `victim-org/victim-repo` - a repository tracked under a completely different, properly-secured organization.

`Handler#stacks` will then resolve and act on the victim organization's `Repository`/`Stack` even though the cryptographic signature check never covered that organization's secret. Concretely: `PushHandler#process` calls `stack.sync_github(expected_head_sha: ...)` on the victim stack, and `StatusHandler`/`CheckSuiteHandler` write forged commit statuses/check results for the victim's commits, all keyed only by the unauthenticated `repository.full_name` field. [5](#0-4) 

This is a direct structural analog to H-02: the field that is authenticated (`repository.owner.login`, which gates which secret is checked) is not the same field that is acted upon (`repository.full_name`, which drives the actual mutation), so verifying "A" does not guarantee the write happens to "A".

### Impact Explanation
An unprivileged, unauthenticated attacker can forge push/status/check_suite webhook events against any Stack tracked by the Shipit instance, provided they can satisfy signature verification for *any one* configured organization (including the trivial case where that organization has no `webhook_secret` configured, which is an explicitly supported configuration). Forged `status` events can manipulate the CI status gate historically consumed by Shipit to authorize deploys, and forged `push`/`check_suite` events can trigger repository synchronization jobs against a repository the attacker does not control and whose real webhook secret was never validated. This crosses the "unauthorized deploy" / cross-repository write trust boundary described in scope, since state belonging to one repository/organization is mutated on the strength of a signature that only ever covered a different, attacker-chosen organization.

### Likelihood Explanation
Likelihood is high for any Shipit deployment that (a) tracks repositories across more than one GitHub organization (the multi-org config format is a first-class, tested feature - `test/dummy/config/secrets_double_github_app.yml`), or (b) has any organization configured with a blank `webhook_secret` (also a documented, supported configuration). No credentials, session, or repository write access are needed - only a raw HTTP POST to the public `/github/webhooks` endpoint with a crafted JSON body and a matching (or absent) signature header for the weak/target org.

### Recommendation
Bind signature verification to the same field that determines which repository/stack is mutated: derive `repository_owner` from the exact same `repository.full_name` value used by `Handler#repository_name`/`stacks` (e.g., split `full_name` rather than trusting a sibling `owner.login`/`organization.login` field), and reject webhooks whose `repository.owner.login` does not match the owner segment of `repository.full_name`. Additionally, do not silently treat a missing `webhook_secret` as "verification passed" - require every configured GitHub App/organization to have a non-blank `webhook_secret` in any environment that reaches this code path, or explicitly fail closed instead of returning `true`.

### Proof of Concept
1. Configure (or find) a Shipit deployment tracking two organizations, `OrgA` (attacker-known/blank `webhook_secret`) and `OrgB` (victim, properly configured), as supported by `test/dummy/config/secrets_double_github_app.yml`.
2. POST to `/github/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/victim-repo"
  }
}
```
No `X-Hub-Signature` header is required if `OrgA.webhook_secret` is blank; otherwise sign the body with `OrgA`'s known secret.
3. `WebhooksController#verify_signature` resolves and validates against `OrgA`'s (blank/known) secret and passes.
4. `PushHandler` resolves the stack via `repository.full_name = "OrgB/victim-repo"` [6](#0-5)  and calls `stack.sync_github` on the victim organization's stack, despite `OrgB`'s webhook secret never having been checked.

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
