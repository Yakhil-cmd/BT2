### Title
Cross-organization signature confusion lets an attacker forge webhook events against a different, secured GitHub repository via `WebhooksController#verify_signature` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and therefore which `webhook_secret`) to validate an incoming webhook against based on `repository.owner.login`/`organization.login` taken directly from the untrusted JSON body, while every downstream `Handler` resolves the *target* repository/stack from a completely different field of that same untrusted body (`repository.full_name`). If any configured organization has no `webhook_secret` set, HMAC verification is unconditionally skipped for payloads claiming that organization, letting an attacker forge a payload that "authenticates" as the unsecured org but whose `repository.full_name` points at a different, secured repository's stack.

### Finding Description
`verify_signature` computes the organization used to pick the GitHub App/secret purely from the JSON body: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` returns the `GitHubApp` configured for that org, and `verify_webhook_signature` explicitly bypasses HMAC verification when that org's config has no `webhook_secret`: [3](#0-2) 

Multi-organization installations where only some orgs set a `webhook_secret` are an explicitly supported/tested configuration: [4](#0-3) 

Once `verify_signature` passes (trivially, because the "authenticating" org has no secret), the event is dispatched to handlers that never re-check `repository.owner.login`; they instead resolve the actual target purely from `repository.full_name`: [5](#0-4) [6](#0-5) 

For example, `PushHandler` uses only `repository_name` (i.e. `repository.full_name`) to look up stacks and calls `stack.sync_github`, and `StatusHandler` writes a `Commit` status purely from an attacker-supplied `sha`/`state` with no repository-ownership check at all: [7](#0-6) [8](#0-7) 

This breaks the binding: **organization authenticated by `verify_signature` (`repository.owner.login`) ≠ repository actually written to by the handler (`repository.full_name`)**. An attacker who knows (or guesses) that one configured organization has no webhook secret can craft `{"repository": {"owner": {"login": "<org-without-secret>"}, "full_name": "<victim-org>/<victim-repo>"}, ...}` and have it accepted as authentic, then acted upon against the victim repository's stack.

### Impact Explanation
This qualifies as unauthenticated write access to stack state for any repository configured in Shipit, sourced from an unprivileged, unauthenticated HTTP request (no GitHub App key, no `webhook_secret`, no session required) — matching the "unauthenticated read/write of stack state" and, via `StatusHandler`, the ability to inject fabricated commit statuses that continuous-deployment/CI-gating logic (`ci.require`) may rely on to allow auto-deploys, which can escalate to an unauthorized deploy.

### Likelihood Explanation
Requires: (1) the deployment to configure at least two GitHub organizations in `Shipit.github`, and (2) at least one of them to omit `webhook_secret` (a configuration explicitly exercised in the test fixtures, suggesting it's a supported, not merely theoretical, setup). Given that, exploitation requires no credentials at all — just an HTTP POST to the public webhook endpoint with a crafted `X-Github-Event` header and JSON body.

### Recommendation
Bind verification and action to the same field: derive `repository_owner` for signature selection from the same repository object used by handlers (`repository.full_name`'s owner segment), and additionally re-validate in each `Handler` that the verified organization matches the repository being mutated. Also disallow/flag `webhook_secret`-less GitHub App configs as insecure, or require a secret for any org registered with more than one configured organization.

### Proof of Concept
1. Configure Shipit with two organizations as in `test/dummy/config/secrets_double_github_app.yml`: `OrgOne` (has `webhook_secret`) and `OrgTwo` (`webhook_secret` is blank).
2. Send `POST /webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker chosen sha>",
  "repository": {
    "owner": { "login": "OrgTwo" },
    "full_name": "OrgOne/protected-repo"
  }
}
```
No `X-Hub-Signature` header (or any garbage value) is required — `verify_webhook_signature` returns `true` unconditionally because `OrgTwo`'s `webhook_secret` is blank, satisfying `app/controllers/shipit/webhooks_controller.rb:24-30`.
3. `PushHandler` then resolves the stack from `full_name` = `OrgOne/protected-repo` and calls `stack.sync_github`, or for a `status` event, `StatusHandler` writes an arbitrary commit status for any `sha` in the database — all without ever validating against `OrgOne`'s real webhook secret.

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

**File:** test/dummy/config/secrets_double_github_app.yml (L42-46)
```yaml
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
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
