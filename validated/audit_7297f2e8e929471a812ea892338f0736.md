### Title
Webhook signature is verified against the GitHub App selected by `repository.owner.login`, but handlers act on the repository identified by `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` picks the GitHub App / `webhook_secret` used to validate the HMAC signature based on `repository_owner` (derived from `params.dig('repository', 'owner', 'login')`), while every `Webhooks::Handlers::Handler` subclass resolves the target `Repository`/`Stack` to mutate using `payload.dig('repository', 'full_name')` (`repository_name` in `app/models/shipit/webhooks/handlers/handler.rb`). These are two different fields of the same attacker-controlled JSON body, and nothing binds them together.

### Finding Description [1](#0-0) 
`verify_signature` computes `github_app = Shipit.github(organization: repository_owner)` and then calls `github_app.verify_webhook_signature(signature, raw_post)`, which only checks that the HMAC over the *entire raw body* matches the secret configured for that one organization's app: [2](#0-1) [3](#0-2) 

In a Shipit deployment configured with multiple GitHub Apps/organizations (an explicitly supported and documented configuration, see `docs/setup.md` "Using Multiple Github Applications" and `lib/shipit.rb#github_app_config`), each organization has its own independent `webhook_secret`. An attacker who legitimately controls one configured organization (e.g. they created and installed their own GitHub App per the setup docs) knows that organization's own `webhook_secret` and can therefore produce a validly-signed webhook body for it.

However, the handlers never re-check that the signed organization matches the repository actually acted upon. `Handler#repository_name` uses `payload.dig('repository', 'full_name')` to look up the target `Repository`/`Stack`: [4](#0-3) 
`Repository.from_github_repo_name` just splits this string and does a DB lookup with no ownership/organization cross-check: [5](#0-4) 

So an attacker can send a JSON payload where `repository.owner.login = "attacker-org"` (satisfying `verify_signature`, since they know `attacker-org`'s webhook secret) but `repository.full_name = "victim-org/victim-repo"` (used by the handler to select the real target). The binding the system relies on - "the organization whose secret authenticated this webhook" == "the repository the webhook acts upon" - is never actually enforced.

This directly parallels the reported bug class: a verification step (nonce increment / HMAC check) covers only part of the intended state, while a different, unverified field is what downstream logic actually consumes and acts on.

### Impact Explanation
Exploiting this lets an attacker who controls webhook delivery for any one configured organization forge events (`push`, `status`, `check_suite`, `membership`, `pull_request`) against stacks belonging to a *different, victim* organization/repository configured in the same Shipit instance:
- `PushHandler` triggers `stack.sync_github(expected_head_sha: ...)` on the victim's stack - forcing Shipit's git sync of the target branch to an attacker-chosen SHA. [6](#0-5) 
- `StatusHandler` can inject arbitrary commit statuses onto any `Commit` matching a `sha` across the whole installation (statuses are looked up globally by `sha`, not scoped by the verified organization at all): [7](#0-6) 
- `CheckSuiteHandler` can trigger check-run refresh scheduling on victim stacks. [8](#0-7) 

Forged/poisoned statuses and forced git-sync to attacker-controlled SHAs can influence Shipit's merge-queue/CI-gating and deploy pipeline decisions on a repository the attacker does not control, which maps to "an unauthorized deploy" / cross-repository write impact category.

### Likelihood Explanation
This requires a Shipit instance configured with multiple GitHub organizations (a documented, supported configuration) and requires the attacker to control at least one of those configured organizations' GitHub App webhook secret - not the victim's. This is a real but non-trivial precondition (multi-tenant Shipit configuration + attacker being one of the legitimate lower-trust tenants), so likelihood is Medium: it is not exploitable by a fully anonymous internet attacker with zero relationship to the Shipit instance, but it does cross a genuine trust boundary between tenants that the code implies should be isolated by organization.

### Recommendation
After verifying the HMAC signature, re-validate that `repository.owner.login` (or `organization.login`) in the payload matches the owner portion of `repository.full_name` before dispatching to handlers, and/or have `Repository.from_github_repo_name` / each handler reject repositories whose owner differs from the organization whose secret validated the signature. Alternatively, scope `Shipit.github(organization:)` lookups and handler processing strictly to the same field used for signature verification instead of using two different payload fields for two different trust decisions.

### Proof of Concept
1. Configure Shipit with two organizations, `attacker-org` and `victim-org`, each with its own GitHub App and `webhook_secret` (per `docs/setup.md` multi-org setup).
2. Attacker crafts a `push` webhook JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature` as `sha1=HMAC(attacker-org's webhook_secret, raw_body)`, which they know because it's their own org's secret.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "attacker-org")` (from `repository.owner.login`) and successfully verifies the signature. [1](#0-0) 
5. `PushHandler#process` resolves stacks via `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on the victim's stack. [6](#0-5)

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```
