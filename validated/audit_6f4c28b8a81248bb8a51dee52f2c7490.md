### Title
Webhook authenticity check binds to the organization named in `repository.owner.login`, not the repository targeted by the event handlers - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` resolves the signing organization purely from attacker-controlled JSON fields and, when that organization has no `webhook_secret` configured, accepts the request without checking `X-Hub-Signature` at all. The event is then dispatched using `repository.full_name`, a separate field from the same payload that the handlers use to pick the actual `Stack`/`Repository` to act on. Because verification is keyed to `repository.owner.login`/`organization.login` while execution is keyed to `repository.full_name`, an attacker can select an org whose config lacks a `webhook_secret` for the auth check while pointing the actual write at any other repository already known to Shipit.

### Finding Description
`verify_signature` computes the organization used for HMAC verification from the raw payload: [1](#0-0) [2](#0-1) 

`repository_owner` is taken from `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`) — both attacker-controlled JSON values in an unauthenticated request. `Shipit.github(organization: repository_owner)` then returns the `GitHubApp` config for that organization name, and `verify_webhook_signature` explicitly short-circuits to `true` when no `webhook_secret` is configured for that organization: [3](#0-2) 

`webhook_secret` is documented as optional per-organization configuration in multi-org setups: [4](#0-3) 

After `verify_signature` passes (or is bypassed via the no-secret organization), `create` dispatches the entire raw payload to handlers for the declared event: [5](#0-4) 

Handlers resolve the actual `Repository`/`Stack` to mutate using a *different* field from the same payload — `repository.full_name` — completely independent of the `repository.owner.login`/`organization.login` value used for authentication: [6](#0-5) [7](#0-6) 

This breaks the binding `organization authenticated == repository written`. In a multi-org Shipit deployment, if even one configured organization has `webhook_secret` unset (nil/blank, an explicitly supported/optional configuration), an attacker can craft a request with `"repository": {"owner": {"login": "<org-without-secret>"}, "full_name": "<victim-org>/<victim-repo>"}`. The authenticity check passes trivially for `<org-without-secret>`, but the handler acts on `<victim-org>/<victim-repo>`, a repository the attacker never proved control over and whose real organization may have a strong `webhook_secret` that was never checked.

### Impact Explanation
This crosses the "unauthenticated read/write" boundary described as High/Critical impact: an unprivileged network attacker (no Shipit session, no GitHub credentials, no valid signature for the targeted repository) can forge GitHub events against a repository/stack they do not control, as long as any other org in the same Shipit deployment lacks a webhook secret. Concretely reachable handlers include:
- `PushHandler#process`, which calls `stack.sync_github(expected_head_sha:)` on the victim stack, forcing a resync to an attacker-chosen commit SHA on a tracked branch: [7](#0-6) 
- `StatusHandler#process`, which forges CI/commit statuses (`commit.create_status_from_github!`) for arbitrary commits on the victim stack, which can influence deploy-readiness checks: [8](#0-7) 
- Review-stack lifecycle handlers (`ClosedHandler`, `OpenedHandler`) which archive/create review stacks keyed only by `repository.full_name`: [9](#0-8) 

These effects can influence which commit is deployed or how deploy-blocking status checks are evaluated for a repository the attacker does not control, matching "unauthorized deploy" style impact.

### Likelihood Explanation
Likelihood is Medium: it requires a multi-organization Shipit deployment where at least one configured GitHub organization omits `webhook_secret` — an explicitly documented, supported configuration (`webhook_secret (optional)` in `docs/setup.md` and `config/secrets.development.example.yml`). Given that setup, exploitation requires only an unauthenticated POST to `/webhooks` with a crafted JSON body; no credentials, session, or valid GitHub signature are needed.

### Recommendation
Bind the webhook-signature verification to the same repository/organization value the handlers subsequently use to select the target stack, rather than allowing them to diverge:
- Verify against `repository.full_name`'s owner (or otherwise confirm `repository.owner.login == organization.login` when both exist) rather than trusting a loosely-derived `repository_owner`.
- Do not allow a blank `webhook_secret` for one organization to authenticate events whose payload targets a repository belonging to a different, properly-secreted organization. Consider rejecting/quarantining events where the payload's declared repository does not belong to the organization actually used for verification.
- Treat a missing `webhook_secret` as "verification unavailable for this org" rather than "verification passed," and require secrets to be configured for any organization hosting production stacks.

### Proof of Concept
1. Configure Shipit with two organizations in `github:` config, e.g. `victim-org` (has `webhook_secret` set) and `staging-org` (no `webhook_secret`, per the supported optional config).
2. As an unauthenticated attacker, send:
```
POST /webhooks
X-Github-Event: push
Content-Type: application/json

{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "full_name": "victim-org/victim-repo",
    "owner": { "login": "staging-org" }
  }
}
```
3. `WebhooksController#verify_signature` computes `repository_owner = "staging-org"`, calls `Shipit.github(organization: "staging-org")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally — no `X-Hub-Signature` needed.
4. `create` dispatches to `PushHandler`, which resolves `stacks` via `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `sync_github(expected_head_sha: "<attacker-chosen-sha>")` on any matching, non-archived stack tracking the `master` branch — despite the request never being authenticated against `victim-org`'s secret.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-53)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
