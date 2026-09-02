### Title
Webhook signature verified against organization from `repository.owner.login` while event processing targets a different repository from `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App / `webhook_secret` to validate the incoming `X-Hub-Signature` against using `repository_owner`, a value read directly from the attacker-supplied JSON body (`params.dig('repository', 'owner', 'login')` or `params.dig('organization', 'login')`). [1](#0-0) [2](#0-1)  Once the signature check passes, `Handler#stacks`/`#repository_name` independently derives the target repository from `payload.dig('repository', 'full_name')`, a separate JSON field in the same body. [3](#0-2) 

### Finding Description
In a multi-organization Shipit deployment (`config/secrets.development.example.yml` documents configuring one GitHub App per organization), each organization has its own `webhook_secret`. [4](#0-3) 

The controller never verifies that the `owner.login` used to pick the signing secret is the same repository whose events are actually acted upon. It picks the app/secret via:

```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [2](#0-1) 

and validates with `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`. [5](#0-4) 

But downstream handlers resolve which `Repository`/`Stack` to write to using a *different* field of the same JSON body:

```ruby
def repository_name
  payload.dig('repository', 'full_name')
end
``` [6](#0-5) 
which feeds `Repository.from_github_repo_name` → `find_by(owner:, name:)`. [7](#0-6) 

Because HMAC-SHA1 signature verification only proves the raw request body was signed by *some* organization's secret, not that the fields inside that body are internally consistent, an attacker who legitimately controls a GitHub App/organization onboarded into the same Shipit instance (e.g. Org B, which they administer and for which they therefore know or can trigger a validly-signed webhook body) can craft a payload where `repository.owner.login` = `"org-b"` (so the signature validated against Org B's secret succeeds) while `repository.full_name` = `"org-a/victim-repo"` (a stack belonging to a different, unrelated organization/tenant on the same Shipit instance). The check-suite/push/status/pull_request handlers then act on `org-a/victim-repo`'s stacks using data entirely dictated by the attacker, even though only Org B's authenticity was actually proven.

This breaks the equality that should hold: **organization authenticated by signature == organization/repository whose stack is written to**. Concretely this allows an attacker who controls one legitimately-onboarded organization to forge `push` (queues `GithubSyncJob` against another org's stack), `status` (creates/mutates CI status on another org's commits, influencing `deployable?`), `check_suite` (queues `RefreshCheckRunsJob`), and `pull_request`/`membership` events targeting stacks/repositories they do not own.

### Impact Explanation
This crosses a tenant/repository trust boundary: a party who is only entitled to act as Org B is able to inject/forge GitHub events for Org A's repository and stacks, corrupting CI/commit state (`Status`, `CheckRun`) that gates `deployable?`/`Commit#success?` used to decide whether a commit is safe to deploy. Falsifying these signals can push a stack into believing a bad commit is green, or can push team membership changes (`membership` event creates users/teams) — an unauthorized, cross-repository write into another tenant's data, matching the "cross-repository writes" Critical impact bucket. It does not directly hand over `GITHUB_TOKEN` or RCE, but it is a genuine authentication/authorization-binding bypass between two organizations sharing one Shipit installation.

### Likelihood Explanation
Requires a multi-organization Shipit deployment (explicitly supported/documented) where the attacker administers or has webhook access to at least one onboarded organization/app, and knowledge that Shipit does not cross-validate `repository.owner.login` against `repository.full_name`'s owner. This is a config/architecture-specific but realistic scenario for any Shipit instance shared across multiple GitHub orgs.

### Recommendation
In `WebhooksController#verify_signature`, and in `Webhooks::Handlers::Handler`, derive the organization used for both signature selection and repository/stack resolution from the *same* single trusted field (e.g. always use `repository.owner.login`, and require that `repository.full_name`'s owner matches `repository.owner.login`/`organization.login` before processing). Reject the webhook if these fields diverge.

### Proof of Concept
1. Configure Shipit with two GitHub Apps: `org-a` (victim, has a stack `org-a/victim-repo` tracked in Shipit) and `org-b` (attacker-controlled, has its own webhook secret known to the attacker because they administer the app installation).
2. Attacker computes a valid `X-Hub-Signature` for a JSON body using `org-b`'s `webhook_secret`, where the body is:
```json
{
  "repository": { "owner": { "login": "org-b" }, "full_name": "org-a/victim-repo" },
  "sha": "<victim-commit-sha>",
  "state": "success",
  ...
}
```
3. POST this to `/webhooks` with header `X-Github-Event: status`.
4. `verify_signature` computes `repository_owner = "org-b"`, calls `Shipit.github(organization: "org-b").verify_webhook_signature(sig, body)`, which succeeds since the attacker signed with `org-b`'s real secret. [1](#0-0) 
5. The `StatusHandler` (a `Handler` subclass) resolves `repository_name = "org-a/victim-repo"` and writes a forged `success` status onto `org-a`'s commit, despite the signature only proving authenticity for `org-b`. [3](#0-2)

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
