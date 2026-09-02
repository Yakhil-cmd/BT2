### Title
Cross-organization webhook forgery: signing organization is never bound to the repository the webhook handler acts on - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to validate a webhook against using the untrusted `repository.owner.login` (or `organization.login`) field of the JSON body, while the handlers that actually act on the payload (`Shipit::Webhooks::Handlers::Handler#stacks`) independently pick the target `Repository`/`Stack` using the *same* body's `repository.full_name` field. Because the HMAC signature only proves "this exact body was signed with organization X's secret," and nothing forces `repository.owner.login == owner-segment-of(repository.full_name)`, an operator of one legitimately-configured tenant organization can forge a webhook body that authenticates as their own org but targets a completely different org's repository/stack.

### Finding Description
`verify_signature` picks the `GithubApp` instance (and therefore the `webhook_secret` used to validate the `X-Hub-Signature`) from the payload itself: [1](#0-0) [2](#0-1) 

Separately, every webhook `Handler` (e.g. `PushHandler`) resolves the `Stack`/`Repository` to operate on from a *different* field of the same payload — `repository.full_name` — via `Repository.from_github_repo_name`: [3](#0-2) [4](#0-3) [5](#0-4) 

The signature check only proves the raw body was HMAC-signed with the secret belonging to whichever organization `repository.owner.login` names — it says nothing about whether that same body's `repository.full_name` actually belongs to that organization. Shipit explicitly supports multiple, independently-configured GitHub Apps/organizations on one instance (each with its own `webhook_secret`), as documented: [6](#0-5) 

This is exactly the trust binding the report's bug class targets: **the organization that authenticated (via its own known `webhook_secret`) vs. the repository whose Stack the payload is written to/acted upon**. Nothing enforces `authenticated_org == full_name.split('/').first`.

### Impact Explanation
An operator of one configured tenant organization (`OrgA`) — who legitimately knows `OrgA`'s own `webhook_secret` because they configured/created that GitHub App — can craft an arbitrary JSON body where:
- `repository.owner.login = "OrgA"` (so `verify_signature` selects and validates against `OrgA`'s secret, which the attacker knows and signs correctly), and
- `repository.full_name = "OrgB/victim-repo"` (targeting any other tenant's `Stack` hosted on the same Shipit instance).

Because `PushHandler#process` uses `repository.full_name` to locate `Stack`s and calls `stack.sync_github(expected_head_sha: params.after)` with an attacker-controlled `expected_head_sha`, this lets an attacker with no privileges on `OrgB`/`victim-repo` force a resync of that victim stack with a SHA of their choosing. On stacks with continuous deployment enabled, syncing new commits is the mechanism that triggers automatic deploys, so this can result in an unauthorized deploy trigger on a repository the attacker has no access to — matching the report's "Critical - unauthorized deploy" impact tier. Other handlers (`status`, `pull_request`, `membership`, `check_suite`) are reachable the same way and can corrupt commit statuses, PR/merge-queue state, or team membership records for a victim org's stacks.

### Likelihood Explanation
Likelihood depends on Shipit being deployed with multiple independently-administered organizations sharing one instance (a documented, supported configuration). Any tenant admin who legitimately possesses their own `webhook_secret` can exploit this without any credentials belonging to the victim organization, and without ever needing a Shipit session, `ApiClient` token, or repository write access on the victim side — satisfying the "unprivileged attacker" requirement.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler#stacks`), require that the organization used to select/verify the webhook secret matches the owner segment of `repository.full_name` (and `organization.login` when present) before dispatching to handlers; reject the webhook (422) on mismatch.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` and `OrgB`, each with its own GitHub App and `webhook_secret` (per `config/secrets.development.example.yml`).
2. As the administrator of `OrgA` (who knows `OrgA`'s `webhook_secret`), craft:
   ```json
   {
     "ref": "refs/heads/main",
     "after": "<attacker-chosen-sha>",
     "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" }
   }
   ```
3. Compute `X-Hub-Signature: sha1=<hmac-sha1(OrgA_webhook_secret, body)>` and `POST` to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` resolves `repository_owner` = `"OrgA"`, validates successfully against `OrgA`'s secret.
5. `PushHandler#process` resolves the target `Stack` via `Repository.from_github_repo_name("OrgB/victim-repo")` and invokes `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on a stack the attacker has no relationship to.

Note: I was unable to fully trace `Stack#sync_github`/continuous-deployment trigger logic within the available iterations to conclusively confirm an automatic deploy fires from this path; that portion of the impact is inferred from the documented `continuous_deployment` feature and should be verified directly in `app/models/shipit/stack.rb` before treating the deploy-trigger impact as fully confirmed. The cross-organization repository/stack-selection mismatch itself, however, is confirmed directly from the cited code.

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
