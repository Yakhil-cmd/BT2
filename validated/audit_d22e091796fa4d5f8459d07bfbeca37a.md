### Title
Webhook organization selected for signature verification differs from the repository the handler writes to, allowing signature bypass to spoof events against unrelated repositories - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and therefore which `webhook_secret`) to check against based on `repository.owner.login` (or `organization.login`), but the event handlers that subsequently act on the payload (`PushHandler`, and all other `Shipit::Webhooks::Handlers::Handler` subclasses) resolve the target `Repository`/`Stack` from a **different** JSON field: `repository.full_name`. When Shipit is configured with multiple GitHub organizations (a documented, supported configuration) and at least one of them has no `webhook_secret` configured (also documented as optional), the equality `organization authenticated == repository written` breaks: an attacker can pick the field used for authentication to route to the unsecured org (bypassing signature verification entirely) while setting the field used for action-taking to point at any other, secured victim repository registered in Shipit.

### Finding Description
`verify_signature` computes the organization used for authentication from the payload itself: [1](#0-0) [2](#0-1) 

The org-specific `webhook_secret` check is skipped entirely when that org has no secret configured: [3](#0-2) 

Shipit explicitly supports configuring several GitHub organizations simultaneously, and documents `webhook_secret` as optional per-organization: [4](#0-3) [5](#0-4) 

Once verification passes (trivially, for an org with no secret), the actual event handler resolves the target repository not from `repository.owner.login`, but from an independently-controlled field, `repository.full_name`: [6](#0-5) 

`PushHandler` (and structurally every other handler built on `Handler`) uses that `stacks` lookup to act on real, registered stacks: [7](#0-6) 

Since the raw HTTP body is never validated when the routing org has no `webhook_secret`, an attacker fully controls both JSON fields independently — nothing forces `repository.owner.login` to equal the owner encoded in `repository.full_name`.

### Impact Explanation
An unprivileged external attacker (anyone who can POST to `/webhooks` — no Shipit session, `ApiClient` token, or GitHub credentials required) can craft a forged webhook body where:
- `repository.owner.login` (or `organization.login`) = the login of any GitHub organization configured in Shipit's multi-org `github:` block that happens to have no `webhook_secret` set, causing `verify_webhook_signature` to unconditionally return `true`.
- `repository.full_name` = `"<victim-org>/<victim-repo>"`, a completely unrelated, secured repository that is registered as a real `Stack` in this Shipit instance.

The forged, unauthenticated request is then dispatched to real handlers (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, pull-request handlers) which resolve stacks via `repository.full_name` and act on the victim stack — e.g. forcing `Stack#sync_github` with an attacker-chosen `expected_head_sha`, or injecting forged commit/check statuses that Shipit's own deploy-readiness logic depends on. This crosses a genuine authentication boundary (webhook signature verification) to write into a different repository's trust domain than the one that was "authenticated," fulfilling the required binding break "an organization that authenticated versus the repository that is written."

### Likelihood Explanation
Requires only: (1) the deployment operator has configured more than one GitHub organization (a documented, supported setup), and (2) at least one configured organization omits `webhook_secret` (explicitly documented as optional, with example configs shipping it commented out/nil). Given this is a documented supported configuration and no additional credentials are needed, likelihood is realistic wherever multi-org mode is used without uniformly enforcing secrets on every org.

### Recommendation
Use the same payload field for both authentication and action: verify the signature using the organization derived from `repository.full_name`'s owner segment (not a separate `repository.owner.login`/`organization.login` field), or reject any request where these two fields disagree. Additionally, do not allow `verify_webhook_signature` to silently return `true` when `webhook_secret` is blank for one org in a multi-org configuration — either require all configured orgs to set a secret, or refuse events whose declared organization has no secret configured while other orgs do.

### Proof of Concept
1. Configure Shipit with two GitHub orgs: `OrgA` (has a `webhook_secret`) and `OrgB` (no `webhook_secret`, per `test/dummy/config/secrets_double_github_app.yml`).
2. Register a Stack for `OrgA/victim-repo` (a real, security-sensitive repository).
3. POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "full_name": "OrgA/victim-repo",
    "owner": { "login": "OrgB" }
  }
}
```
4. `verify_signature` resolves `Shipit.github(organization: "OrgB")`, whose `verify_webhook_signature` returns `true` unconditionally (no secret configured) — no valid `X-Hub-Signature` needed.
5. `PushHandler#process` resolves `stacks` via `repository.full_name = "OrgA/victim-repo"`, finds the real Stack, and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")`, entirely bypassing `OrgA`'s webhook secret.

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

**File:** config/secrets.development.example.yml (L18-38)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
```

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

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
