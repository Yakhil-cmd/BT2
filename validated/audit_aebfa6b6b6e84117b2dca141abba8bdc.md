## Title
Cross-Organization Webhook Spoofing — Signature Verification Keyed on `repository.owner.login` While Repository Writes Are Keyed on `repository.full_name` - (File: `app/controllers/shipit/webhooks_controller.rb`)

## Summary
`WebhooksController#verify_signature` selects which GitHub App config (and therefore which `webhook_secret`) to verify a payload's HMAC signature against using an attacker-supplied JSON field, `repository.owner.login` (or `organization.login`) [1](#0-0) [2](#0-1) . But every event handler resolves the actual repository/stack to mutate using a *different* attacker-supplied field, `repository.full_name` [3](#0-2) . Since both fields live in the same attacker-controlled JSON body and are never cross-checked against each other, the "organization that authenticated" and the "repository that is written" are two independent bindings that can be desynchronized.

## Finding Description
Shipit supports a multi-organization GitHub App configuration where each organization has its own, independently-configured `webhook_secret` (documented and shown as optionally `nil`) [4](#0-3) . `Shipit.github(organization:)` looks up that per-organization config and, if `webhook_secret` is blank, `GitHubApp#verify_webhook_signature` unconditionally returns `true`, i.e. no verification occurs at all for that organization's traffic:

```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
``` [5](#0-4) 

`WebhooksController#verify_signature` picks which org's config (and secret) to check against purely from the payload:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(...)
  ...
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [6](#0-5) [2](#0-1) 

Once this check "passes," every handler that acts on the payload finds the actual `Repository`/`Stack` to mutate via a completely separate field, `repository.full_name`, inherited from the base `Handler` class:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [3](#0-2) 

For example `PushHandler#process` uses this `stacks` scope to trigger a sync against the resolved stacks: `stacks.not_archived.where(branch:).find_each { |stack| stack.sync_github(...) }` [7](#0-6) .

Because the controller never checks that `repository.owner.login` is a prefix of `repository.full_name`, an attacker can submit a single crafted JSON body where:
- `repository.owner.login` = an organization configured in Shipit with `webhook_secret: nil` (a documented, supported configuration), causing `verify_webhook_signature` to always return `true` for that request, and
- `repository.full_name` = `"victim-org/victim-repo"`, an entirely different, protected repository that Shipit actually tracks.

The signature check "authenticates" the request as belonging to the no-secret organization, but the write action (triggering a `GithubSyncJob`, updating commit/stack state, etc.) is performed against the victim organization's repository — breaking the binding `authenticated_org == written_repository`.

## Impact Explanation
This allows an unauthenticated, unprivileged external attacker to forge webhook events (e.g. `push`) against any repository/stack tracked by Shipit, as long as the Shipit instance is configured with at least one organization lacking a `webhook_secret` in its multi-org GitHub configuration. This directly matches the Critical bar of "cross-repository writes / unauthorized deploy" since `push` events can trigger `stack.sync_github`, altering the commit history and deployable state Shipit believes exists for a repository the attacker does not control on GitHub. Other event types processed the same way (e.g. `status`, `check_suite`, `pull_request`) are equally exposed, since `Handler#repository_name` is shared code.

## Likelihood Explanation
Requires: (1) the operator to run Shipit with the multi-organization GitHub configuration schema, and (2) at least one configured organization with no `webhook_secret`. Both are explicitly supported, documented configurations (see `config/secrets.development.example.yml`), not a misuse of the engine. No credentials, tokens, or session are required — only an unauthenticated POST to the public `/github/webhooks` endpoint (`app/controllers/shipit/webhooks_controller.rb`).

## Recommendation
- Verify webhook signatures using a secret bound to the actual target repository (derived from `repository.full_name`), not from a separate, independently attacker-controlled field (`repository.owner.login`/`organization.login`).
- Reject events where `repository.owner.login` doesn't match the owner segment of `repository.full_name`.
- Disallow (or explicitly opt-in/warn loudly on) `webhook_secret: nil` for any organization in multi-org configurations, since it silently disables authentication for that organization's namespace while other organizations remain protected.

## Proof of Concept
1. Configure Shipit with multi-org GitHub apps, e.g. `github: { free-org: { webhook_secret: nil, ... }, victim-org: { webhook_secret: "real-secret", ... } }`.
2. Shipit already tracks a stack for `victim-org/victim-repo`.
3. Attacker POSTs to `/github/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": { "owner": { "login": "free-org" }, "full_name": "victim-org/victim-repo" }
}
```
4. `verify_signature` calls `Shipit.github(organization: "free-org")`, whose `webhook_secret` is `nil`, so `verify_webhook_signature` returns `true` unconditionally — no valid signature is required [8](#0-7) .
5. `PushHandler` resolves stacks via `repository.full_name` = `"victim-org/victim-repo"` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on the victim's real stack [7](#0-6) , causing Shipit to sync/act on attacker-influenced data for a repository the attacker never authenticated against.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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
