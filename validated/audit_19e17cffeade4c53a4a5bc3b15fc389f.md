### Title
Webhook signature verification keys on `repository.owner.login`/`organization.login` while every handler acts on `repository.full_name` — organization-authenticated ≠ repository-written - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to validate the incoming request against based on `repository.owner.login` (or `organization.login`) taken from the *same untrusted JSON body* it is about to verify, while every event handler resolves the `Repository`/`Stack` to mutate using an entirely different field, `repository.full_name`. Because nothing enforces that these two fields agree, and because signature verification is a no-op whenever the selected organization has no `webhook_secret` configured, an unauthenticated attacker can pick any organization entry in `Shipit`'s `github:` config that lacks a secret and forge a payload whose `repository.full_name` points at a totally unrelated, victim-owned repository tracked by Shipit.

### Finding Description
The binding that should hold is: **organization authenticated == repository/stack written**. It is broken as follows:

- `verify_signature` derives the verification key strictly from the owner/organization login embedded in the attacker-supplied body: [1](#0-0) [2](#0-1) 

- `GitHubApp#verify_webhook_signature` short-circuits to `true` whenever that organization's `webhook_secret` is blank/unset — a documented "optional" setting: [3](#0-2) 

- The actual dispatch/mutation path re-parses the same raw body and calls handlers with it, without any re-check tying the verified organization to the acted-upon repository: [4](#0-3) 

- Every handler resolves its target strictly from `repository.full_name`, a field never consulted during signature verification: [5](#0-4) [6](#0-5) 

- `Repository.from_github_repo_name` performs a plain lookup by the parsed `owner/name` pair with no cross-check against any authenticated identity: [7](#0-6) 

So the "authentication" step and the "authorization scope" step consult two different, independently attacker-controlled fields of the same JSON body, and the authentication step can be trivially satisfied for any org whose `webhook_secret` is unset.

### Impact Explanation
An attacker who identifies (from the multi-tenant `github:` config, e.g. `config/secrets.development.shopify.yml`, which shows multiple orgs can share one Shipit instance) any configured organization key with no `webhook_secret` set can send a `POST /webhooks` request with `X-Github-Event: push` (or `status`, `pull_request`, `check_suite`, `membership`, etc.) and a body like:
```json
{"repository": {"owner": {"login": "org-with-blank-secret"}, "full_name": "victim-org/victim-repo"}, ...}
```
`verify_signature` will select `Shipit.github(organization: "org-with-blank-secret")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally — no valid `X-Hub-Signature` is even required. The request then proceeds to `create`, and the handler resolves the target repository/stack from `full_name`, i.e. `victim-org/victim-repo`, a repository the attacker has no relationship to. Depending on event type this enables forged `push` events (enqueuing `GithubSyncJob` against the victim stack), forged `status`/`check_suite` updates, or forged `pull_request` events driving review-stack provisioning/merge logic — a cross-repository write / unauthorized action against a stack the attacker does not control, satisfying the "unauthorized deploy/merge, cross-repository writes" High/Critical impact bar.

### Likelihood Explanation
Exploitability depends entirely on operator configuration: it requires at least one organization entry in the shared Shipit `github:` config to have no `webhook_secret` set (explicitly documented as "optional" in `docs/setup.md`), and for that instance to also track a "victim" repository under a different organization. In single-org deployments with a webhook secret always configured, this path is not reachable. In multi-tenant Shipit deployments (a supported/documented configuration per `config/secrets.development.shopify.yml` and `test/dummy/config/secrets_double_github_app.yml`), likelihood is meaningfully higher, since any org with a blank secret becomes a skeleton key for signature bypass across all repositories the instance tracks.

### Recommendation
- Do not select the verification key from attacker-controlled payload fields alone; instead verify the signature first using a per-request expected secret tied to the actual target repository (derived and validated from `repository.full_name`, not `repository.owner.login`), and cross-check that `repository.owner.login` matches the owner half of `repository.full_name` before trusting the payload.
- Do not treat a missing `webhook_secret` as "verification passed" — either require `webhook_secret` for all configured organizations, or reject unsigned/verifiable-as-blank requests outright.
- After verification, assert that the authenticated organization equals the owner of the repository the handler is about to mutate, rejecting mismatches.

### Proof of Concept
1. Deploy Shipit configured with two organizations, e.g. `OrgA` (no `webhook_secret` set) and `victim-org` (tracked stacks exist), similar to `test/dummy/config/secrets_double_github_app.yml`.
2. Send, without any authentication:
```
POST /webhooks
X-Github-Event: push
Content-Type: application/json

{
  "repository": {"owner": {"login": "OrgA"}, "full_name": "victim-org/victim-repo"},
  "after": "<any_sha>",
  "ref": "refs/heads/main"
}
```
3. `verify_signature` calls `Shipit.github(organization: "OrgA")`; because `OrgA`'s `webhook_secret` is blank, `verify_webhook_signature` returns `true` (`lib/shipit/github_app.rb:76-77`) regardless of the (absent) `X-Hub-Signature` header.
4. `create` dispatches to the `push` handler, which resolves the stack via `payload.dig('repository', 'full_name')` → `victim-org/victim-repo` (`app/models/shipit/webhooks/handlers/handler.rb:36-38`), enqueuing a sync/deploy-relevant job against a stack the attacker never authenticated for.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
