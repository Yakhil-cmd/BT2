### Title
Webhook signature is verified against the organization derived from `repository.owner.login`, but the target repository is resolved from the independent `repository.full_name` field, allowing cross-organization event forgery - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App (and therefore which `webhook_secret`) to validate the HMAC signature against using `repository_owner`, computed as `params.dig('repository', 'owner', 'login')`. [1](#0-0) [2](#0-1) 

However, once the signature check passes, every event handler resolves the actual repository/stack it will act on from a *different* JSON field, `repository.full_name`, via `Handler#repository_name`/`Handler#stacks`. [3](#0-2) 

These two values (`repository.owner.login` used to pick the signing secret, and `repository.full_name` used to pick the record acted upon) are never cross-checked against each other. In a multi-organization deployment (`config/secrets.yml` supports one GitHub App/`webhook_secret` per organization, as documented), an attacker who legitimately administers their own onboarded organization — and therefore knows *that org's* `webhook_secret` — can forge a payload where `repository.owner.login` is their own org (so the signature validates against their known secret) while `repository.full_name` names a completely different, victim-owned repository tracked by the same Shipit instance. [4](#0-3) 

### Finding Description
This is the same class of bug as the report: the component that authenticates the request (CometBFT vote extensions from height N-1) is bound to different data than the component that acts on it (voting power at height N). Here, `verify_signature` "authenticates" the request as belonging to organization X, but `PushHandler`, `StatusHandler`, `CheckSuiteHandler`, etc., operate on the repository named by a completely separate `full_name` field that is not covered by that authentication decision:

- `WebhooksController#repository_owner` — the authenticated identity: `params.dig('repository', 'owner', 'login')`. [2](#0-1) 
- `Handler#repository_name` — the acted-upon identity: `payload.dig('repository', 'full_name')`. [5](#0-4) 

The `StatusHandler` is the most damaging consumer of this gap: it writes a `Status` record directly from attacker-controlled payload fields (`sha`, `state`, `description`, `target_url`, `context`) with no additional call back to GitHub to confirm the status actually exists. [6](#0-5) 

Because the signature check never verifies that the org that signed the payload actually owns the repository named in `full_name`, an attacker holding a valid secret for *any* one org configured in the Shipit instance can forge a `status` (or `push`, `check_suite`) event for a repository belonging to a completely different, unrelated organization also tracked by that Shipit install.

### Impact Explanation
Forged `status` webhooks let an attacker inject arbitrary commit statuses (e.g., a fabricated `success` state for a required CI context) on commits belonging to a victim repository/stack they do not own. Since Shipit's deploy gating (`ci.require`) relies on `Status` records populated exactly through this webhook path, this can be used to make an unreviewed or CI-failing commit appear "green," letting anyone with deploy access to that stack ship it — an unauthorized-deploy-adjacent integrity break. This satisfies the "High" bar (escalation of authorization/state) and edges toward "unauthorized deploy" impact depending on how `ci.require` is configured for the victim stack.

### Likelihood Explanation
Requires the Shipit operator to run a multi-org configuration where multiple, mutually-untrusted organizations are each granted their own configured GitHub App/`webhook_secret` under the same Shipit instance (a supported and documented configuration). Any org admin who is a legitimate one of those tenants, but not a collaborator on the victim's repository, can exploit this without needing GitHub write access to the victim's repo, a Shipit session, or an `ApiClient` token — only their own tenant's `webhook_secret`, which they are entitled to know.

### Recommendation
In `WebhooksController#verify_signature`, after resolving the signing organization, cross-check that the `repository.full_name` (or `organization.login` for org-scoped events) actually belongs to the same organization used for signature verification before dispatching to handlers — e.g., reject the event unless `repository_owner == payload.dig('repository', 'full_name')&.split('/')&.first`. Alternatively, look up the target `Repository`/`Stack` first and verify the signature using the secret configured for that repository's actual organization, rather than trusting an unauthenticated field to select the verification key.

### Proof of Concept
1. Shipit is configured with two GitHub App entries, one for `org-a` (attacker-controlled, webhook_secret known to attacker) and one for `org-b` (victim, tracks `org-b/victim-repo`).
2. Attacker computes `X-Hub-Signature` using `org-a`'s known `webhook_secret` over a JSON body:
```json
{
  "sha": "<victim-commit-sha>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "org-a" }, "full_name": "org-b/victim-repo" }
}
```
3. `POST /webhooks` with header `X-Github-Event: status` and the computed signature.
4. `verify_signature` computes `repository_owner == "org-a"`, fetches `Shipit.github(organization: "org-a")`, and validates successfully against the attacker's own secret. [1](#0-0) 
5. `StatusHandler#process` then finds `Commit.where(sha: params.sha)` for the real `org-b/victim-repo` commit and creates a forged `success` status on it, even though the request was never signed by `org-b`'s secret. [7](#0-6)

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L6-24)
```ruby
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
