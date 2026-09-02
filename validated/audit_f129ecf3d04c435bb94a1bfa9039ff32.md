### Title
Webhook signature verifier selected via `organization.login` fallback diverges from `repository.full_name` acted on by `ClosedHandler` — cross-tenant forged `pull_request.closed` archives arbitrary `ReviewStack` - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#repository_owner` picks the `GitHubApp` (and thus the HMAC secret) used to authenticate a webhook from `params.dig('repository','owner','login')` or, if omitted, `params.dig('organization','login')`, while `ClosedHandler` independently resolves the target `Repository`/`ReviewStack` from `params.repository.full_name`. Because these two fields are attacker-controlled and unrelated, an attacker who knows of any org configured in Shipit **without** a `webhook_secret` can get their forged request accepted unconditionally and then point `repository.full_name` at any other org/repo's stack, causing `ReviewStack#archive!` to run against a victim repository that never authenticated the request.

### Finding Description
The broken binding: the code implicitly assumes `repository_owner == owner(params.repository.full_name)`. In fact these are set independently by the attacker.

Path:
1. `WebhooksController#verify_signature` computes `github_app = Shipit.github(organization: repository_owner)` [1](#0-0)  where `repository_owner` falls back to `params.dig('organization','login')` when `repository.owner.login` is absent [2](#0-1) .
2. `GitHubApp#verify_webhook_signature` unconditionally returns `true` if that org's config has no `webhook_secret` set: `return true unless webhook_secret` [3](#0-2) , and `@webhook_secret = @config[:webhook_secret].presence` [4](#0-3) . Any signature header (or none) passes.
3. `ClosedHandler`'s params schema only `requires :repository do requires :full_name, String end` — it never requires or checks `repository.owner.login` [5](#0-4) .
4. `ClosedHandler#repository` resolves the actual DB `Repository` purely from `params.repository.full_name` via `Shipit::Repository.from_github_repo_name` [6](#0-5) , and `process` calls `review_stack.archive!` when `action == "closed"` [7](#0-6) .

Exploit request: attacker sends `POST /webhooks` with header `X-Github-Event: pull_request` and a body:
```json
{
  "action": "closed",
  "number": 1,
  "pull_request": { ... },
  "organization": { "login": "attacker-org-without-secret" },
  "repository": { "full_name": "victim-org/victim-repo" },
  "sender": { "login": "attacker" }
}
```
`repository.owner.login` is omitted, so `repository_owner` resolves to `"attacker-org-without-secret"`, an org configured in Shipit but lacking `webhook_secret`. `verify_signature` authenticates against that org's `GitHubApp`, which trivially returns `true` regardless of the (even garbage) `X-Hub-Signature` header. The handler then archives the `ReviewStack` bound to `victim-org/victim-repo`, an org/repo the attacker never authenticated against and does not control.

Existing guards do not stop this: `drop_unhandled_event` only checks event type presence; `ExplicitParameters` schema for `ClosedHandler` validates types/presence but never cross-checks `repository.full_name`'s owner against `repository_owner`; there is no `force_github_authentication`/`User#authorized?` check on this unauthenticated webhook endpoint by design; `Repository` model validations only constrain format, not tenant binding to the authenticating org.

### Impact Explanation
An unprivileged internet attacker can cause a **write for a repository that did not authenticate the request** — the `ReviewStack` of any victim org/repo (regardless of whether that org properly configured a `webhook_secret`) gets archived via forged input, purely by knowing the name of one Shipit-configured org lacking `webhook_secret`. This is a cross-tenant authorization bypass: forged webhook accepted as trusted, and it mutates a different tenant's stack state (Critical category: "a payload for one repository mutating another's stack ... or an unauthorized deploy/rollback"). It is fully repeatable against any repository/PR number in the system, blast radius spans all tenants sharing the Shipit instance.

### Likelihood Explanation
Precondition: at least one org must be configured in Shipit without a `webhook_secret` (a real, documented misconfiguration scenario explicitly named in the question, and the code path in `GitHubApp#verify_webhook_signature` treats this as "no verification required" rather than rejecting). Attacker cost is a single unauthenticated HTTP POST with a hand-crafted JSON body — no secrets, sessions, or GitHub access required. Fully repeatable and scriptable against arbitrary repositories.

### Recommendation
Bind the repository resolved by the handler to the same owner used for signature verification: require `repository.owner.login` in the webhook payload/schema and assert it equals `repository_owner`/`organization.login` before dispatching to handlers, or better, derive `repository_owner` strictly from `repository.owner.login` (reject the `organization.login` fallback for any handler that also reads `repository.full_name`), and treat orgs without `webhook_secret` as a hard verification failure (`head(422)`) rather than an automatic pass.

### Proof of Concept
minitest under `test/controllers/webhooks_controller_test.rb` or `test/models/shipit/webhooks/handlers/pull_request/closed_handler_test.rb`:
1. Configure two orgs in test credentials: `victim-org` (with `webhook_secret: "s3cr3t"`) and `attacker-org` (no `webhook_secret`).
2. Create `Repository` and `ReviewStack` for `victim-org/victim-repo`, assert `review_stack.archived_since.nil?` (not archived) before the request — LHS binding: `repository_owner == organization("victim-org/victim-repo")`.
3. POST to `/webhooks` with `X-Github-Event: pull_request`, no/garbage `X-Hub-Signature`, body `{"action":"closed","organization":{"login":"attacker-org"},"repository":{"full_name":"victim-org/victim-repo"}, ...}`.
4. Assert response is `200 OK` (not `422`), then assert `review_stack.reload.archived?` is `true` — demonstrating the RHS (actual mutated repo `victim-org/victim-repo`) diverges from the LHS authenticating org (`attacker-org`), proving the invariant "a pull_request event only affects the repository/stack whose secret authenticated it" is violated.

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

**File:** lib/shipit/github_app.rb (L44-51)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]
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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L33-35)
```ruby
            requires :repository do
              requires :full_name, String
            end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-45)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
