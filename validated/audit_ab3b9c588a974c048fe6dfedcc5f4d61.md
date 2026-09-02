### Title
Cross-organization webhook forgery: signature verified against `repository.owner.login`, but writes are keyed on unverified `repository.full_name` — ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App/organization secret to use for HMAC verification based on `repository.owner.login` (or `organization.login`) from the *unverified* JSON body, then verifies the signature against that org's `webhook_secret`. Once verification passes, every webhook `Handler` (e.g. `PushHandler`) resolves the affected `Stack`/`Repository` using a *different* field of the same unverified body: `repository.full_name`. Nothing enforces that `full_name`'s owner segment matches the `repository.owner.login` used to select the signing secret, so an attacker who legitimately controls one configured organization's webhook secret can forge a payload whose `repository.full_name` names a repository belonging to a different organization, causing Shipit to act on that unrelated stack.

### Finding Description
The controller derives the signing organization from an unauthenticated payload field: [1](#0-0) [2](#0-1) 

`verify_webhook_signature` only checks the HMAC against whichever org's secret was selected by `repository_owner`: [3](#0-2) 

After the signature check passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches to handlers built from the raw, still-unauthenticated JSON. Every handler resolves the target repository via `repository.full_name`, a field completely independent from `repository.owner.login`: [4](#0-3) 

`Repository.from_github_repo_name` performs a straight DB lookup on the owner/name parsed out of that string, with no cross-check against the organization whose secret produced a valid signature: [5](#0-4) 

`PushHandler` (and equivalently the pull-request handlers) uses this repository resolution to find and act on `Stack` records, e.g. triggering a GitHub sync: [6](#0-5) 

Shipit supports multiple independently configured GitHub Apps/organizations, each with its own `webhook_secret`: [7](#0-6) 

Because the org used to select the verifying secret (`repository.owner.login`) and the org whose stack is actually mutated (`repository.full_name`) are two independent, attacker-controlled strings inside the same JSON body, an attacker who holds the webhook secret for *Org A* (e.g., because they administer Org A's own GitHub App integration with Shipit) can send a POST to `/webhooks` with:
- `repository.owner.login = "org-a"` (so `verify_signature` picks Org A's secret and the HMAC validates), and
- `repository.full_name = "org-b/some-repo"` (so the dispatched handler operates on Org B's stack).

This breaks the intended binding: `organization that authenticated == repository that is written`.

### Impact Explanation
This allows an attacker who is not authorized on Org B (has no push access, no webhook secret, no App installation there) to trigger writes against Org B's Shipit-tracked repository/stack purely by forging a signed-looking payload using Org A's secret. Depending on which webhook event/handler is targeted, this can:
- Force a `GithubSyncJob` / `sync_github` call for Org B's stack via `PushHandler`, injecting a fabricated `expected_head_sha` and potentially triggering continuous-deployment machinery tied to that stack.
- Manipulate pull-request lifecycle state (archive/unarchive review stacks, edit stored PR metadata, capture labels) for Org B's repositories via the PR handlers, all of which resolve `repository` the same way from `repository.full_name`.

This matches the "unauthorized deploy" / "cross-repository writes" class of Critical/High impact: an attacker crosses an organizational trust boundary that Shipit's per-organization GitHub App architecture is meant to enforce.

### Likelihood Explanation
Requires the attacker to already control (or have configured) at least one organization's Shipit GitHub App/webhook secret — a real but bounded precondition in multi-org Shipit deployments (this is not "no credential at all", but it is not credentials for the *target* org). No `ApiClient` token, no `github_access_token`, no Shipit session and no access to Org B is required. Given Shipit explicitly documents and supports the multi-org configuration schema, this is a realistic deployment topology, and the mismatch between the field used for authentication (`repository.owner.login`) and the field used for authorization/target-resolution (`repository.full_name`) is a straightforward, reachable code path with no additional obstacles.

### Recommendation
After `verify_webhook_signature` succeeds, enforce that the `repository.full_name` (or `organization.login`, for org-scoped events) used by handlers is consistent with the `repository_owner`/organization that produced the valid signature — e.g., reject the webhook if `repository.full_name.split('/').first.casecmp(repository_owner) != 0`. Alternatively, thread the verified `repository_owner`/organization through to `Handler#stacks`/`Handler#repository_name` resolution instead of re-deriving it independently from the same untrusted payload.

### Proof of Concept
1. Configure Shipit with two organizations, `org-a` and `org-b`, each with its own `github.webhook_secret` (per the documented multi-org `config/secrets.yml` schema).
2. As an attacker who administers Org A's GitHub App (and thus knows/controls Org A's `webhook_secret`), craft a `push` event JSON body:
   ```json
   {
     "ref": "refs/heads/main",
     "after": "<attacker-chosen-sha>",
     "repository": {
       "full_name": "org-b/target-repo",
       "owner": { "login": "org-a" }
     }
   }
   ```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(org-a-webhook_secret, body)>` and POST it to `/webhooks` with header `X-Github-Event: push`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "org-a")` and validates the HMAC successfully against `org-a`'s secret [8](#0-7) .
5. `Shipit::Webhooks.for_event('push')` dispatches to `PushHandler`, whose `stacks` method resolves `Repository.from_github_repo_name("org-b/target-repo")` [4](#0-3)  and calls `stack.sync_github(expected_head_sha: params.after)` for Org B's stack [6](#0-5)  — despite the attacker never having presented any credential valid for Org B.

### Citations

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
