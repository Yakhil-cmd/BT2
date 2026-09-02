### Title
Webhook signature is verified against the payload's `repository.owner.login`, but every event handler acts on `repository.full_name` — allowing one onboarded GitHub organization to forge events against another tenant's repository - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret to validate a webhook against using `repository_owner`, i.e. `params.dig('repository', 'owner', 'login')` (or `organization.login` as fallback). [1](#0-0) [2](#0-1)  Once the signature is accepted, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the *entire, attacker-controlled* JSON body to handlers. [3](#0-2)  Every handler resolves the target `Repository`/`Stack` via `Handler#repository_name`, which reads a *different* field: `payload.dig('repository', 'full_name')`. [4](#0-3)  `Repository.from_github_repo_name` splits that string on `/` to find the target repository row, independent of which owner's secret signed the request. [5](#0-4) 

Because the HMAC only proves "this byte string was signed with organization X's secret" and never asserts that `repository.owner.login == X` is consistent with `repository.full_name`'s owner, an administrator of one onboarded GitHub organization (who legitimately possesses their own `webhook_secret` in a multi-org Shipit deployment, as documented in `config/secrets.development.shopify.yml`) can construct a JSON payload where `repository.owner.login` (or `organization.login`) is their own org (so the signature check passes), while `repository.full_name` names a repository belonging to a completely different tenant/organization hosted on the same Shipit instance. This breaks the binding: `organization that authenticated == repository that is written`.

### Finding Description
The verification and consumption of the field are split across two independent JSON paths of the same signed payload:

- Signature/organization selection: `repository_owner` in `WebhooksController` — `params.dig('repository', 'owner', 'login')` fallback `params.dig('organization', 'login')`. [2](#0-1) 
- Target-repository resolution used by every handler: `payload.dig('repository', 'full_name')`. [6](#0-5) 

Nothing in `verify_signature` or in `Handler#stacks`/`Handler#repository_name` cross-checks that the owner segment of `full_name` matches `repository.owner.login`. Since the entire raw POST body is what's HMAC-signed (`request.raw_post`), the signature is valid as long as it was produced with the correct secret for whichever value happens to sit at `repository.owner.login` — it says nothing about which repository the payload's other fields describe. [1](#0-0) 

Shipit explicitly supports hosting multiple GitHub organizations, each with its own independently configured `webhook_secret`, in a single instance (see the multi-org secrets format). [7](#0-6)  The owner of one such onboarded org's GitHub App configures/knows their own `webhook_secret` legitimately (it's their own app's secret) but has no privileged access to Shipit itself, satisfying the "unprivileged attacker" bar — they can only speak as their own organization, yet the code lets that identity write events against any other tenant's repository merely by mismatching two fields inside the same signed body.

Concretely, all four registered webhook handlers key off `Handler#stacks` / `repository_name`, none of which re-validate the owner:
- `PushHandler#process` calls `stacks.not_archived.where(branch:).find_each { |stack| stack.sync_github(expected_head_sha: params.after) }` — forcing Shipit to sync a foreign stack to an attacker-chosen `after` SHA. [8](#0-7) 
- `CheckSuiteHandler#process` schedules check-run refreshes on a foreign stack's commits. [9](#0-8) 
- `StatusHandler#process` looks up commits purely by `sha` (global, not scoped to the signing org at all) and calls `commit.create_status_from_github!(params)`, letting the forged payload inject/forge a CI status (`state`, `context`, `target_url`, `description`) onto any commit that matches that SHA anywhere in the Shipit instance. [10](#0-9) 

### Impact Explanation
This maps to the "authentication bypass" category from the impact list because the cross-tenant equality `signing organization == acted-upon repository` is broken: an entity authenticated as organization A can cause Shipit to write state (sync a stack's head, forge a commit status, trigger check-run refreshes) for repository/organization B, despite never being authenticated for B. The `StatusHandler` case is the most severe: because `ci.require` gates continuous deployment and human deploy safety checks on commit statuses (`README.md`, `ci.require`), a forged "success" status delivered by an unrelated organization's webhook secret can flip the CI gate for an unrelated stack and enable/accelerate an unauthorized deploy through the continuous-delivery path — satisfying "unauthorized deploy" under Critical impact. At minimum it is unauthenticated write of another tenant's stack/commit state (High: escalation past the tenant boundary).

### Likelihood Explanation
This requires only: (1) Shipit configured for multiple GitHub organizations (a documented, supported configuration — `config/secrets.development.shopify.yml`), and (2) knowledge of the attacker's *own* organization's webhook secret, which the attacker legitimately possesses since it is their own GitHub App configuration. No compromise of Shipit itself, no `ApiClient` token, and no privileged Shipit account is required — only the ability to send a crafted HTTP POST to the public `/webhooks` endpoint with a valid signature for their own org while forging the `repository.full_name`/`sha` fields to target another tenant. This is a realistic, low-effort attack path in any multi-tenant Shipit deployment.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler`), after signature verification, assert that the owner derived from `repository.owner.login` (the value used to select the webhook secret) matches the owner segment parsed out of `repository.full_name` before dispatching to handlers; reject the request (422) on mismatch. Additionally, `StatusHandler` should scope its `Commit.where(sha:)` lookup to commits belonging to the repository named in the (now-validated) payload rather than matching any commit sha instance-wide.

### Proof of Concept
1. Shipit instance hosts two tenants: organization `alpha` (attacker-controlled GitHub App, attacker knows `alpha`'s `webhook_secret`) and organization `beta` (victim tenant with a `beta/victim-repo` stack).
2. Attacker computes `sha1=HMAC(alpha_webhook_secret, body)` over a crafted JSON body:
```json
{
  "repository": { "owner": { "login": "alpha" }, "full_name": "beta/victim-repo" },
  "sha": "<beta's currently deployed commit sha>",
  "state": "success",
  "context": "ci/required-check"
}
```
3. POST to `/webhooks` with header `X-Github-Event: status` and `X-Hub-Signature: sha1=<computed>`.
4. `verify_signature` calls `Shipit.github(organization: 'alpha')` and validates against `alpha`'s secret — passes. [1](#0-0) 
5. `StatusHandler#process` matches `Commit.where(sha: params.sha)` — including `beta/victim-repo`'s commit — and calls `create_status_from_github!`, forging a passing CI status for the victim's stack despite the attacker never authenticating as `beta`. [10](#0-9)

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

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
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
