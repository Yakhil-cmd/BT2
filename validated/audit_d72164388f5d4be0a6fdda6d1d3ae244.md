### Title
Cross-organization webhook forgery via mismatched `repository.owner.login` and `repository.full_name` fields - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which `GitHubApp`/`webhook_secret` to validate a webhook against using `repository.owner.login` (or `organization.login`), but the handlers that actually act on the payload (`Handler#stacks`/`Handler#repository_name`) resolve the target `Repository`/`Stack` using the independent `repository.full_name` field from the very same JSON body. Because these two fields are never cross-checked against each other, a valid signature computed with organization A's own `webhook_secret` can be replayed to act on a stack belonging to organization B on the same multi-tenant Shipit instance.

### Finding Description
`verify_signature` computes `repository_owner` purely from unvalidated JSON: `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`, and uses it to look up the `GitHubApp` config (`Shipit.github(organization: repository_owner)`), whose `webhook_secret` is then used to HMAC-verify the raw request body: [1](#0-0) [2](#0-1) 

`lib/shipit/github_app.rb#verify_webhook_signature` only checks the HMAC of the *entire* raw body against the secret chosen above — it has no notion of which repository/org the payload content should be for: [3](#0-2) 

Once signature verification passes, the event is dispatched to a handler (e.g. `PushHandler`, `StatusHandler`, `CheckSuiteHandler`) whose base class resolves the affected `Stack`/`Repository` using a *different* field of the same payload — `repository.full_name` — with no re-validation against the org used to select the secret: [4](#0-3) [5](#0-4) 

`repository.owner.login` (used for authentication/secret-selection) and `repository.full_name` (used for authorization/target-selection) are independent, attacker-controlled JSON keys inside the same signed body. Nothing forces `full_name`'s owner segment to equal `owner.login`. Shipit explicitly supports hosting multiple GitHub organizations with per-organization `webhook_secret`s (`config/secrets.development.example.yml`, `docs/setup.md`), so on such a multi-tenant install, an attacker who legitimately knows organization A's `webhook_secret` (e.g. as an admin of a tenant org configured on the same Shipit instance) can craft a webhook body where:
- `repository.owner.login` = `"orgA"` (so the controller picks orgA's `GitHubApp` and the attacker's own known secret verifies the HMAC), and
- `repository.full_name` = `"orgB/some-repo"` (so the handler acts on a stack belonging to a different tenant, orgB).

This breaks the binding: *the organization whose credential authenticated the request* ≠ *the repository/stack the handler subsequently writes to*.

### Impact Explanation
Depending on event type, this enables:
- `push` → `PushHandler` triggers `stack.sync_github(expected_head_sha:)` on orgB's stacks matching the branch, forcing unwanted sync/refresh activity on a foreign tenant's stack: [6](#0-5) 
- `status` → `StatusHandler` injects a forged CI status (`state`, `description`, `target_url`, `context`) onto any commit matching `sha` regardless of which org it belongs to, via `Commit#create_status_from_github!`: [7](#0-6)  — since Shipit uses commit statuses/checks to gate deploy eligibility, an attacker able to forge a "success" status on an arbitrary commit in a foreign tenant's repository can influence deploy-readiness checks for that stack, contributing to an unauthorized deploy.

This crosses a genuine tenant/credential boundary (an unprivileged attacker relative to organization B, using only credentials they legitimately hold for organization A) and directly maps to the "High/Critical" categories: unauthenticated write of stack state / potential unauthorized deploy pathway across repositories on a shared Shipit instance.

### Likelihood Explanation
Requires: (1) a multi-organization Shipit deployment (explicitly documented/supported configuration), and (2) the attacker holding legitimate `webhook_secret` knowledge for at least one configured organization (e.g., as an admin of a tenant org, which is a normal, unprivileged-relative-to-other-tenants position). No access to orgB's secret, no Shipit session, and no `ApiClient` token is required. This is a realistic multi-tenant configuration mistake rather than a purely theoretical one, but it only applies to installs configuring more than one GitHub organization on the same engine instance.

### Recommendation
After signature verification, require that the `owner` segment of `repository.full_name` (or `organization.login`) used by handlers matches the `repository_owner` that was used to select the verifying secret, and reject the webhook (422) on mismatch. Alternatively, resolve the `Repository`/`Stack` scoped to the authenticated organization instead of trusting the payload's `full_name` independently.

### Proof of Concept
1. Shipit is configured with two tenants: `orgA` (secret `SECRET_A`) and `orgB` (secret `SECRET_B`), per the multi-org config format in `config/secrets.development.example.yml`.
2. Attacker, an admin of `orgA`, knows `SECRET_A` (their own webhook secret) but not `SECRET_B`.
3. Attacker crafts a `push` event JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "deadbeef",
  "repository": {
    "owner": { "login": "orgA" },
    "full_name": "orgB/private-repo"
  }
}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC(SECRET_A, body)` and sends it with `X-Github-Event: push`.
5. `WebhooksController#verify_signature` computes `repository_owner` = `"orgA"`, fetches `Shipit.github(organization: "orgA")`, and `verify_webhook_signature` succeeds because the attacker used `SECRET_A` correctly [1](#0-0) .
6. `PushHandler#process` is invoked; `Handler#stacks` resolves `Repository.from_github_repo_name("orgB/private-repo")` [4](#0-3) , and `stack.sync_github` is triggered for orgB's stack — despite the request never being authenticated by orgB's secret.

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
