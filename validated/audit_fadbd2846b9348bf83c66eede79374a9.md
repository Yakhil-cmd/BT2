### Title
Webhook cross-organization spoofing: signature is verified against `repository.owner.login`/`organization.login` but events are dispatched against the independent `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController` selects which GitHub App/webhook secret to use for HMAC verification based on one JSON field (`repository.owner.login`, falling back to `organization.login`), while the handlers that actually act on the payload resolve the target stack/repository from a completely different, unrelated field (`repository.full_name`). Because these two fields are never cross-checked for consistency, a request that is validly signed for organization A can be crafted to act on a repository belonging to organization B, in Shipit instances configured with multiple GitHub Apps (a documented, supported configuration).

### Finding Description
`WebhooksController#verify_signature` picks the GitHub App used to verify `X-Hub-Signature` via: [1](#0-0) [2](#0-1) 

The organization used for this lookup is taken straight from the attacker-controlled JSON body (`repository.owner.login` or `organization.login`), not from any authenticated channel.

Once verification passes, `create` dispatches the full, unfiltered payload to handlers: [3](#0-2) 

Handlers, however, determine *which repository/stack to act on* using a different field entirely, `repository.full_name`: [4](#0-3) 

This is used directly by `PushHandler` (triggers `stack.sync_github`) and `CheckSuiteHandler` (schedules check-run refresh): [5](#0-4) [6](#0-5) 

`StatusHandler` similarly attaches a fabricated CI status to any commit by `sha` regardless of repository/org: [7](#0-6) 

Shipit explicitly supports hosting multiple GitHub Apps for different organizations in one instance, each with its own `webhook_secret` (some of which may legitimately be left blank/nil, per the example config): [8](#0-7) 

The broken equality is: `organization whose webhook secret authenticated the request` (`repository.owner.login` / `organization.login`) **must equal** `organization/repository the handler is about to mutate state for` (`repository.full_name`'s owner) — but the code never enforces this. An attacker who legitimately controls (or is a bot/collaborator of) one organization/app configured in a shared Shipit instance can sign a payload with their own organization's valid webhook secret, then set `repository.full_name` to point at an entirely different, unrelated organization's repository tracked by the same Shipit instance, and have Shipit act on it as if it came from GitHub for that repository.

### Impact Explanation
This is a cross-repository/cross-organization forgery: an attacker with legitimate signing capability for one low-trust organization's GitHub App (but zero access to the victim organization/repository) can:
- Force `PushHandler` to trigger `GithubSyncJob`/`stack.sync_github` for an arbitrary victim stack with an attacker-chosen `expected_head_sha`.
- Inject fabricated commit statuses via `StatusHandler#process` → `commit.create_status_from_github!`, which can flip CI gating checks used to unblock merges/deploys on the merge queue.
- Trigger `CheckSuiteHandler`'s check-run refresh for arbitrary stacks/commits.

Since Shipit's continuous-deployment/merge-queue logic relies on commit statuses and push events to decide when to deploy or merge, this can lead to an unauthorized deploy/merge decision being made for a repository the attacker has no legitimate access to — matching the Critical "unauthorized deploy, rollback, or merge" impact category.

### Likelihood Explanation
Exploitability requires only that the Shipit instance host more than one GitHub App/organization (a supported, documented configuration) and that the attacker control or sign for at least one of those organizations — no session, `ApiClient` token, or private key for the *victim* organization is needed. This is a realistic operating model for shared/multi-tenant Shipit deployments.

### Recommendation
After identifying the GitHub App/organization used to verify the signature, re-derive the repository/owner used by handlers from the *same*, already-verified field, and reject (422) any webhook whose `repository.full_name` owner does not match the `repository_owner`/`organization.login` used for signature verification. This restores the missing equality check between the authenticated organization and the repository the handler is permitted to mutate.

### Proof of Concept
1. Configure Shipit (per `docs/setup.md`) with two GitHub Apps, `attacker-org` (attacker controls this org's webhook secret) and `victim-org` (tracked stack, attacker has no access).
2. Attacker computes `sha1=HMAC(attacker-org secret, body)` over a crafted JSON body:
```json
{
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  },
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>"
}
```
3. POST to `/webhooks` with `X-Github-Event: push` and `X-Hub-Signature: sha1=<computed>`.
4. `verify_signature` resolves `repository_owner` = `"attacker-org"`, fetches `Shipit.github(organization: "attacker-org")`, and the signature validates successfully against the attacker's own secret.
5. `create` dispatches to `PushHandler`, whose `repository_name` reads `payload.dig('repository','full_name')` = `"victim-org/victim-repo"`, matching the real victim `Repository`/`Stack`, and calls `stack.sync_github(expected_head_sha: ...)` for a stack the attacker never had access to.

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
