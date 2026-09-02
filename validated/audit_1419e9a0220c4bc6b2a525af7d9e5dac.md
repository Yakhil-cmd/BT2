### Title
Webhook organization used for signature verification is decoupled from the repository the payload actually writes to - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController` picks which GitHub App configuration (and thus which `webhook_secret`) to verify a signature against based on `repository_owner`, but the handlers that actually mutate data resolve the target `Repository`/`Stack` from a different, independently-controlled field of the same attacker-supplied JSON body (`repository.full_name`). Because these two lookups read different parts of an unauthenticated, unverified-until-later payload, an attacker can select a lenient/unconfigured organization for signature checking while pointing the write path at a completely different repository.

### Finding Description
`verify_signature` derives the authenticating organization purely from the JSON body, before the signature is confirmed: [1](#0-0) 

That organization is used to fetch a `GitHubApp` instance and its `webhook_secret`: [2](#0-1) 

Critically, `GitHubApp#verify_webhook_signature` treats a missing `webhook_secret` as automatically valid: [3](#0-2) 

`webhook_secret` is documented as optional per organization in the multi-org configuration schema: [4](#0-3) 

Once past `verify_signature`, `create` dispatches the *entire raw payload* to event handlers: [5](#0-4) 

The base `Handler` class resolves the target `Repository`/`Stack` from a completely different key of the same payload — `repository.full_name` — with no cross-check against the `repository.owner.login`/`organization.login` used earlier for signature selection: [6](#0-5) 

`PushHandler` uses this to trigger a GitHub sync for any stack matching the resolved repository/branch: [7](#0-6) 

`StatusHandler` uses it (indirectly, via `Commit.where(sha:)`, which is scoped by commit rows already imported for real stacks) to write a new commit status sourced entirely from attacker-controlled fields: [8](#0-7) 

**The broken binding, stated as an equality that the code assumes but never enforces:**
`organization authenticated by verify_signature (repository.owner.login / organization.login)` == `repository actually written by the handler (repository.full_name)`.

Before the attacker's request, in legitimate GitHub-originated webhooks both fields come from the same `repository` object GitHub populates, so they are always consistent. After an attacker crafts a raw POST body where `repository.owner.login` is set to an organization that has no `webhook_secret` configured (or one whose secret has leaked separately) while `repository.full_name` is set to `"<other-org>/<other-repo>"` belonging to a *different*, properly-configured organization, `verify_signature` passes (`return true unless webhook_secret`) for the spoofed org, yet the handler mutates state for the unrelated target repository resolved from `full_name`. No component ever confirms that the organization whose secret gated the request is the owner of the repository being modified.

This is the same class of bug as the referenced report: a value that is fine for the check performed with it (`owner.login` used only to pick a signature key) is silently reused to authorize a much stronger effect at a different reference point in the same payload (`full_name` used to find and mutate the target `Stack`), producing a mismatch that an attacker can control.

### Impact Explanation
An unauthenticated attacker can forge webhook events (`push`, `status`, `check_suite`, etc.) against any repository tracked by Shipit as long as any organization in the multi-org `github:` config has no `webhook_secret` set (an explicitly supported, documented configuration). This allows forging arbitrary commit statuses via `StatusHandler#process` (`Commit#create_status_from_github!`) and triggering `Stack#sync_github` via `PushHandler`, both of which feed into deploy-eligibility checks (e.g., required CI statuses gating what commits are deployable). Forged green statuses/pushes on a repository the attacker doesn't own can enable an unauthorized deploy decision on that stack — satisfying the "unauthorized deploy" impact bar.

### Likelihood Explanation
Requires no credentials, tokens, or repository access — only an HTTP POST to the public `/webhooks` endpoint. The only precondition is that the Shipit deployment's multi-org configuration includes at least one organization without a `webhook_secret`, which the shipped documentation explicitly presents as an acceptable, optional setting. Given that precondition, exploitation is a single crafted JSON payload.

### Recommendation
Verify the webhook signature using the organization actually referenced by the repository the handlers will act on (`repository.full_name`'s owner), not a value read independently from the payload before verification. Additionally, reject/hard-fail (rather than silently allow) webhook delivery when `webhook_secret` is blank for a configured organization, or require all organizations in multi-org mode to configure a `webhook_secret`.

### Proof of Concept
1. Configure Shipit in multi-org mode with `github.orgA` having no `webhook_secret` and `github.orgB` (which owns the real, deploy-relevant repository `orgB/critical-app`) having one configured. See `app/controllers/shipit/webhooks_controller.rb:59-62` for the fallback logic used to pick the org.
2. POST to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/critical-app" },
  "sha": "<sha of a real, undeployed commit on orgB/critical-app>",
  "state": "success",
  "context": "required-ci-check"
}
```
No `X-Hub-Signature` (or any garbage value) is required — `verify_webhook_signature` short-circuits to `true` because `orgA`'s `webhook_secret` is blank (`lib/shipit/github_app.rb:76-83`).
3. `WebhooksController#verify_signature` resolves `repository_owner` to `"orgA"`, passes verification, and `create` dispatches the payload to `StatusHandler` (`app/controllers/shipit/webhooks_controller.rb:10-15`).
4. `StatusHandler#process` and `Handler#repository_name` use `payload.dig('repository','full_name')` = `"orgB/critical-app"` to locate the real commit and write a forged success status against it (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`, `app/models/shipit/webhooks/handlers/handler.rb:36-38`), even though the request was never authenticated for `orgB`.

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
