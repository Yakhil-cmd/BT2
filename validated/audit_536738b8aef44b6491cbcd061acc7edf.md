### Title
Webhook signature verified against the payload's `repository.owner.login` organization while writes are targeted using the independently-read `repository.full_name` field, allowing cross-organization/cross-repository writes - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/secret to use for HMAC verification based on `repository.owner.login` (or `organization.login`) taken from the *unverified* JSON body, but every webhook `Handler` subclass independently resolves the repository/stack to act on using `repository.full_name` from that same unverified body. Because these two fields are never cross-checked, a payload signed with the webhook secret of organization A can name a completely different repository (belonging to organization B) as the target, and the handler will happily write to B's stack.

### Finding Description
`verify_signature` computes the signing organization from the payload itself: [1](#0-0) 
`repository_owner` is defined as: [2](#0-1) 

The HMAC check itself only proves that *some* configured `webhook_secret` matches the raw body: [3](#0-2) 

Once signature verification passes, `WebhooksController#create` dispatches the raw, attacker-controlled `params` to the event handler without re-deriving the organization from any verified source: [4](#0-3) 

Every handler resolves the target repository/stacks using a *different* field of the same untrusted payload — `repository.full_name` — instead of `repository.owner.login`: [5](#0-4) 

For example, `PushHandler` uses `stacks` (i.e., `repository.full_name`) to find stacks and trigger a GitHub sync with an attacker-chosen `after` SHA: [6](#0-5) 

`CheckSuiteHandler` similarly uses `stacks` (again keyed off `repository.full_name`) to schedule check-run refreshes on commits belonging to a different repository than the one whose secret signed the request: [7](#0-6) 

Shipit explicitly supports hosting multiple organizations, each with its own GitHub App / `webhook_secret`, on a single instance: [8](#0-7) 

**The broken binding:** `repository.owner.login` (the organization whose secret authenticates the request) ≠ `repository.full_name` (the repository the engine actually writes to). Nothing in `verify_signature` or `Handler#stacks` enforces that these two independently-controlled fields refer to the same organization.

### Impact Explanation
On a multi-tenant Shipit deployment (explicitly supported per `config/secrets.development.example.yml` and `docs/setup.md`), an org that legitimately owns its own GitHub App/webhook secret (Org A) can forge a webhook whose `repository.owner.login` is `"org-a"` (so it passes signature verification with Org A's known secret) but whose `repository.full_name` is `"org-b/victim-repo"`. The handler will then:
- Enqueue `GithubSyncJob`/create `Commit` records for Org B's stack with an attacker-chosen `expected_head_sha` (`PushHandler`).
- Schedule check-run refreshes against Org B's commits (`CheckSuiteHandler`).
- Create/update commit statuses on Org B's commits (`StatusHandler`).

This is an unauthorized cross-organization/cross-repository write into another tenant's stack state, performed by an entity authenticated only for its own organization — satisfying the "cross-repository writes" Critical impact criterion.

### Likelihood Explanation
Exploitation requires only that the attacker control (or be an admin of) any one organization onboarded to a shared, multi-org Shipit instance — knowledge of their own organization's `webhook_secret` is a normal, expected capability for any tenant admin who set up their own GitHub App per the documented setup flow. No privileged Shipit account, `ApiClient` token, or GitHub write access to the victim repository is required; only an HTTP POST to `/webhooks` with a crafted, self-signed JSON body.

### Recommendation
After signature verification succeeds, bind the resolved organization to the actual target repository: derive/validate `repository.full_name`'s owner against the same `repository_owner` (or the `Shipit.github(organization:)` instance) that successfully verified the signature, and reject the webhook (422) if they mismatch. Handlers should not independently re-derive the organization/repository from unauthenticated payload fields without that cross-check.

### Proof of Concept
1. Deploy Shipit configured with two organizations, `org-a` and `org-b`, each with its own GitHub App and `webhook_secret` (per `docs/setup.md` multi-org example), where `org-a`'s attacker knows only `org-a`'s `webhook_secret`.
2. Attacker (as `org-a` admin) crafts a `push` webhook body:
```json
{
  "repository": {
    "owner": { "login": "org-a" },
    "full_name": "org-b/victim-repo"
  },
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>"
}
```
3. Sign the raw body with `org-a`'s `webhook_secret` using `sha1=HMAC-SHA1(secret, body)` and send it as `X-Hub-Signature`, with `X-Github-Event: push`, to `POST /webhooks`.
4. `WebhooksController#verify_signature` resolves `repository_owner` = `"org-a"`, fetches `Shipit.github(organization: "org-a")`, and successfully verifies the signature using `org-a`'s secret.
5. `PushHandler#process` resolves `stacks` via `repository.full_name` = `"org-b/victim-repo"`, matching `org-b`'s actual stacks, and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` — a write triggered against `org-b`'s repository despite the request only being authenticated for `org-a`.

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
