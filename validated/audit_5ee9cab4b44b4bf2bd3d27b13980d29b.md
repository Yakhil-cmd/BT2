### Title
Webhook signature is verified against `repository.owner.login`/`organization.login`, but handlers act on the independently-controlled `repository.full_name` (or, for status events, on **any** commit sha in the database) — allowing cross-organization / cross-repository webhook forgery - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary

### Finding Description
`WebhooksController#verify_signature` selects the HMAC secret to validate the incoming webhook using a field taken from the **same untrusted JSON payload** that will later be processed: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` is looked up from `params.dig('repository','owner','login')` (or `organization.login`). In a multi-tenant Shipit install, each GitHub organization has its **own separate `webhook_secret`**, as shown in the supported multi-org configuration schema: [3](#0-2) 

Once the signature check passes, the actual work performed by the handler is derived from a **different, independently-controlled** field of the same payload — `repository.full_name` — which is never cross-checked against the organization whose secret validated the request: [4](#0-3) [5](#0-4) 

The `StatusHandler` is even less scoped: it does not use `stacks`/`repository_name` at all, but matches **any** commit row in the entire installation by `sha`, regardless of which repository it belongs to: [6](#0-5) 

This reproduces the ERC-777 report's bug class: the field that is cryptographically "committed to" (here, the organization used to select/verify the webhook secret) is not the field that is actually acted upon (here, the target repository/stack or, worse, an unscoped commit sha lookup). The binding that must hold is:

`organization_that_authenticated (params.dig('repository','owner','login') used for HMAC selection) == organization_of(repository_that_is_written) (derived from params.dig('repository','full_name') or Commit.where(sha:) in handlers)`

The current implementation never enforces this equality.

### Impact Explanation
An attacker who legitimately administers a webhook on **any** repository/organization tracked by the Shipit install (and therefore knows that organization's `webhook_secret` — a routine, low-privilege capability for any repo admin) can craft a forged webhook whose `repository.owner.login`/`organization.login` matches their own org (so signature verification passes with a secret they know), while `repository.full_name` (push/check_suite events) or `sha` (status events) targets a **different organization's/repository's** stack:
- Via `PushHandler`, this forces `Stack#sync_github` for a victim stack, causing the app's own GitHub credentials to be used to re-sync/fetch history for an arbitrary tracked repository on attacker's command [5](#0-4) .
- Via `StatusHandler`, an attacker can forge a `state: "success"` CI status for **any commit sha in the entire installation** (not limited to their own repo), directly manipulating `commit.deployable?`/`require_ci` gating used by the deploy API (`app/controllers/shipit/api/deploys_controller.rb`), which can enable an otherwise-blocked deploy to proceed or make a stack with `continuous_deployment: true` auto-deploy a commit that never actually passed CI on the real GitHub repository [6](#0-5) .

This crosses the "organization authenticated vs. repository written" trust boundary and can result in an unauthorized deploy being unlocked for a repository the attacker does not control, satisfying the Critical impact bar ("unauthorized deploy").

### Likelihood Explanation
Requires only that the attacker control a webhook secret for **some** organization already integrated with the same Shipit instance (a routine repo-admin capability, not a Shipit credential, `ApiClient` token, or repository write access to the *victim* repo) and knowledge of a target commit sha/repository full name, both of which are public/discoverable. No Shipit session, GitHub App private key, or privileged Shipit account is needed. This is realistically only exploitable in the documented multi-organization deployment mode (separate `webhook_secret` per org), which the engine explicitly supports and documents.

### Recommendation
After parsing and verifying the webhook, derive the organization from the **same** field that is subsequently used to resolve the target repository/stack (i.e., verify against `repository.full_name`'s owner, not a separately-read `repository.owner.login`/`organization.login`), and reject the event if they disagree. For `StatusHandler`, scope the `Commit` lookup by the repository resolved from the verified payload (using `stacks`) instead of a global `Commit.where(sha:)` search.

### Proof of Concept
1. Shipit is configured for two GitHub orgs, `orgA` and `orgB`, each with its own `webhook_secret` (per `config/secrets.development.example.yml` multi-org schema).
2. Attacker administers a repo in `orgA` and thus knows `orgA`'s `webhook_secret`.
3. Attacker POSTs to `/github/webhooks` a `push` event JSON body where:
   - `repository.owner.login = "orgA"` (so `WebhooksController#verify_signature` selects `orgA`'s secret and the HMAC computed with that known secret passes),
   - `repository.full_name = "orgB/victim-repo"`, `ref = "refs/heads/main"`, `after = "<arbitrary-sha>"`.
4. `verify_signature` passes (uses `orgA` secret). `PushHandler#process` then resolves `Repository.from_github_repo_name("orgB/victim-repo")` and calls `stack.sync_github(expected_head_sha: ...)` on the victim's stack — a stack the attacker has no relationship to — using Shipit's own GitHub App credentials.
5. Equivalently, a `status` event with a forged `sha` belonging to `orgB/victim-repo` and `state: "success"` is accepted the same way and updates that commit's status regardless of the requesting org, potentially unblocking `require_ci` deploy gating or triggering continuous deployment.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
