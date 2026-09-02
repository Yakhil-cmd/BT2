### Title
Cross-repository webhook forgery via mismatch between the organization used for signature verification and the repository acted upon - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate an inbound GitHub webhook using the organization name taken from `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`), then verifies the raw body against that org's configured `webhook_secret`. Every event handler, however, resolves the repository/stack to act on using a completely independent field, `payload.dig('repository', 'full_name')`. These two attacker-controlled JSON fields are never checked for consistency with each other. [1](#0-0) [2](#0-1) [3](#0-2) 

### Finding Description
Shipit supports hosting multiple GitHub organizations, each with its own independently configured `webhook_secret` (including the documented, supported value of an unset/`nil` secret): [4](#0-3) [5](#0-4) 

`GithubApp#verify_webhook_signature` explicitly short-circuits to `true` when no `webhook_secret` is configured for the org resolved from the payload: [6](#0-5) 

The controller resolves *which org's secret to use* from `repository.owner.login`: [1](#0-0) [2](#0-1) 

But every handler (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, pull-request handlers, etc.) resolves the *repository actually written to* from `repository.full_name`, via `Handler#repository_name`/`Handler#stacks`: [3](#0-2) [7](#0-6) [8](#0-7) 

Since these two JSON fields are unrelated and both live in the same attacker-supplied body, an unprivileged attacker who knows (or guesses) the name of any organization hosted on the Shipit instance that has `webhook_secret` unset (a documented, legitimate configuration state, not a misconfiguration) can:

1. Set `repository.owner.login` (or `organization.login`) to that unsecured org's name, causing `verify_signature` to trivially pass with no signature required at all.
2. Set `repository.full_name` to `victim-org/victim-repo` — any *other* org/repo actually hosted on the instance.

The request passes signature verification (binding: "organization authenticated" = unsecured org) while the handler acts on an entirely different repository (binding: "repository written" = victim org/repo). The equality the engine is supposed to enforce — *organization whose secret authenticated the request == repository the handler mutates* — never holds.

### Impact Explanation
This breaks authentication entirely for any repository hosted on a multi-org Shipit instance, as long as at least one configured org has no `webhook_secret` (an explicitly supported/documented configuration, e.g. `webhook_secret: # nil` in the example secrets templates). Concretely:

- `push` events let an attacker invoke `stack.sync_github(expected_head_sha: params.after)` for the victim stack with an attacker-chosen `after` SHA, forcing Shipit to pull/track an arbitrary commit as "head" for that stack (`PushHandler#process`).
- `status` events let an attacker forge `Commit#create_status_from_github!` for arbitrary commit SHAs in the victim repository (`StatusHandler#process`), which can satisfy CI/status requirements gating deploys or merges.
- `check_suite`, `membership`, and `pull_request` events are similarly reachable and act on the victim repo/stack based on the forged `full_name`.

This effectively allows an unauthenticated third party to inject forged GitHub events into any repository on a shared multi-tenant Shipit deployment, which can be leveraged toward unauthorized deploys/merges by manipulating the commit/status state that gates them — matching the "unauthorized deploy, rollback or merge" / authentication-bypass impact tier.

### Likelihood Explanation
Requires no credentials, tokens, or prior access — only knowledge that the target Shipit instance hosts multiple GitHub orgs and that one of them (any one) has no `webhook_secret` configured, which is a documented and directly supported configuration shape rather than a misuse of the engine. Any installation following the documented multi-org example without setting a secret on every entry is exposed.

### Recommendation
Bind signature verification to the same repository identity the handlers act on: derive the signing organization from the same `repository.full_name`/owner value used by `Handler#repository_name`, and additionally verify that `repository.owner.login` (used for secret selection) matches the owner segment of `repository.full_name` before dispatching. Consider also disallowing `webhook_secret` from being unset when more than one GitHub organization is configured, or requiring a per-repository secret rather than a per-organization one supplied purely from attacker-controlled payload fields.

### Proof of Concept
Given a Shipit instance configured with two orgs, `OrgTwo` (no `webhook_secret`, per `test/dummy/config/secrets_double_github_app.yml`) and `Shopify` (hosting `shopify/shipit-engine` with a real secret):

```
POST /github/webhooks
X-Github-Event: push
Content-Type: application/json

{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "OrgTwo" },
    "full_name": "shopify/shipit-engine"
  }
}
```

`verify_signature` resolves `repository_owner` = `"OrgTwo"`, whose `webhook_secret` is unset, so `verify_webhook_signature` returns `true` unconditionally regardless of the (missing/arbitrary) `X-Hub-Signature` header. `PushHandler` then resolves `repository_name` from `payload.dig('repository','full_name')` = `"shopify/shipit-engine"`, looks up the real `Repository`/`Stack`, and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` — fully bypassing authentication for the `shopify/shipit-engine` repository despite that org having a correctly configured secret.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** config/secrets.development.example.yml (L18-30)
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
```

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
