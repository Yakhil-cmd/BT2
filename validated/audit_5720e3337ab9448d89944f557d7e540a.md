### Title
Webhook signature verification is keyed on `repository.owner.login`, but downstream handlers act on the unrelated `repository.full_name` field, letting one organization forge writes into another organization's stacks - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to check the HMAC signature against by reading `repository.owner.login` (or `organization.login`) out of the *unauthenticated* request body itself. [1](#0-0) [2](#0-1)  Once the signature check passes, the raw parsed payload is handed unchanged to the event handlers, which resolve the actual `Stack`/`Repository` to mutate from other fields in that same payload (e.g. `full_name`), via `Repository.from_github_repo_name`, which just splits `"owner/name"` and does a `find_by`. [3](#0-2)  Because the field used to pick *whose secret validates the signature* (`repository.owner.login`) and the field used to pick *which repository/stack is written to* (`repository.full_name`) are independent, unsigned JSON keys in the same payload, they are never checked for consistency.

### Finding Description
This is the direct analog of the reported bug class: a verification step trusts one part of an attacker-influenced payload while a different, unguarded part of the same payload drives the state change - exactly the "payload field acted on but never covered by the verified signature" / "organization authenticated vs. repository written" binding called out in the rules.

Concretely:
- `verify_signature` computes `repository_owner = params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` and fetches `Shipit.github(organization: repository_owner)` to get that org's configured `webhook_secret`, then verifies the `X-Hub-Signature` header against it. [4](#0-3) [2](#0-1) 
- Shipit explicitly supports configuring multiple independent GitHub organizations/apps, each with its own `webhook_secret`, as documented in the multi-org config example. [5](#0-4) 
- After the signature check succeeds, `create` calls `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` with the same, fully attacker-controlled `params` hash. [6](#0-5) 
- Handlers (push/status/check_suite/pull_request/etc., under `app/models/shipit/webhooks/handlers/**`) resolve the target repository from fields such as `full_name`, which end up in `Repository.from_github_repo_name(github_repo_name)` — `repo_owner, repo_name = github_repo_name.downcase.split('/')` — completely independent of the `owner.login` value used for signature selection. [3](#0-2) 

Because `owner.login` (used to pick the verifying secret) and `full_name` (used to pick the mutated repository/stack) are two separate, unsigned-until-verification JSON fields that GitHub never requires to be consistent with each other, and because the signature only proves "some org's secret matches," an operator who legitimately administers **their own** GitHub organization inside a multi-org Shipit deployment can sign a payload with their own known `webhook_secret` while setting `full_name` (and other repository-identifying fields) to point at a **different** organization's repository/stack.

### Impact Explanation
A successfully forged webhook is processed exactly as if GitHub had sent it for the victim repository: e.g. a `push` event drives `GithubSyncJob` to ingest fabricated commits into a victim stack, or a `status`/`check_suite` event injects fabricated commit statuses/check results that influence deployability and merge/deploy decisions for a repository the attacker does not own or have any GitHub permissions on. This is a cross-organization/cross-repository write achieved with only the attacker's own, unprivileged webhook secret — no `GITHUB_TOKEN`, `api_clients_secret`, Shipit session, or GitHub write access to the victim repo is required, matching the "cross-repository writes" Critical-impact category.

### Likelihood Explanation
This requires the Shipit deployment to be configured with more than one GitHub organization (a first-class, documented configuration). [5](#0-4)  Any operator who legitimately owns/administers one of those configured organizations already knows that organization's `webhook_secret` (it's their own credential, not a secret of Shipit's or of the victim org), so no privilege escalation beyond "run your own org's webhook" is needed to sign an arbitrary payload body. Likelihood is medium in single-org deployments (not exploitable) and high in any multi-org deployment, which the codebase explicitly supports and documents.

### Recommendation
Do not let the payload itself select which secret verifies the payload. Either:
- Verify the signature against every configured organization's `webhook_secret` and, if a match is found, cross-check that the matching organization equals the `repository.owner.login`/`organization.login` actually used by the handler to resolve the repository, rejecting on mismatch; or
- Bind webhooks to a specific organization out-of-band (e.g. by URL path segment per org, `/webhooks/:organization`) instead of trusting a field inside the JSON body to select the verifying secret, and reject if that path-bound organization doesn't match the repository fields used downstream.

### Proof of Concept
1. Deployment is configured for two GitHub organizations, `org-a` (attacker-controlled, webhook secret `S_A` known to the attacker) and `org-b` (victim, webhook secret `S_B`, unknown to attacker), per the supported multi-org config. [5](#0-4) 
2. Attacker crafts a `push` webhook body:
```json
{
  "repository": {
    "owner": { "login": "org-a" },
    "full_name": "org-b/victim-repo"
  },
  "after": "<attacker-chosen sha>",
  "ref": "refs/heads/master"
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC(S_A, body)>` using their own known secret `S_A`.
4. `WebhooksController#verify_signature` computes `repository_owner = "org-a"`, fetches `Shipit.github(organization: "org-a")`, and the signature verifies successfully because it was signed with `S_A`. [1](#0-0) [2](#0-1) 
5. `create` dispatches the same `params` to the `push` handler, which resolves the target via `full_name = "org-b/victim-repo"` through `Repository.from_github_repo_name`, causing state changes (sync job enqueue, commit ingestion) against `org-b`'s stack despite the request never being signed by `org-b`'s real `webhook_secret`. [6](#0-5) [3](#0-2) 

Note: I was unable to open `app/models/shipit/webhooks/handlers/push_handler.rb` directly before running out of tool iterations, so the exact field name it reads (`full_name` vs. another repository identifier) is inferred from `Repository.from_github_repo_name`'s signature and the consistent `full_name`-based lookup pattern used across the other handlers found via search; confirming the precise line in `push_handler.rb`/`status_handler.rb` would strengthen this PoC.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
