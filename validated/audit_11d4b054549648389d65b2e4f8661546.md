### Title
Webhook signature verification is bound to the wrong field, allowing cross-organization/cross-repository event forgery when any single configured GitHub organization lacks a `webhook_secret` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to validate an inbound webhook against using `repository.owner.login` (or `organization.login`), but every event handler that actually mutates state resolves the target `Repository`/`Stack` from a *different*, independent field in the same attacker-controlled JSON body: `repository.full_name`. These two lookups are never cryptographically tied together.

### Finding Description
`WebhooksController#verify_signature` computes `repository_owner` from the payload and uses it purely to pick which org's secret to check against: [1](#0-0) [2](#0-1) 

`GithubApp#verify_webhook_signature` short-circuits to `true` when the selected organization has no `webhook_secret` configured — a supported, documented configuration state (see `config/secrets.development.shopify.yml`, `webhook_secret: # nil`): [3](#0-2) 

Meanwhile, every `Shipit::Webhooks::Handlers::Handler` subclass (push, pull_request opened/closed/reopened/labeled/unlabeled/assigned/edited, etc.) resolves the repository/stack to act on from `payload.dig('repository', 'full_name')`, an entirely separate JSON field that is not covered by the org-selection logic used for signature verification: [4](#0-3) 

Because `owner.login` (used to pick/verify the secret) and `full_name` (used to pick the acted-upon repository) are independent, attacker-controlled fields of the same JSON body, and because `verify_webhook_signature` returns `true` unconditionally whenever the org picked via `owner.login` has no secret configured, the binding "organization whose signature authenticated the request == repository that gets written to" is broken. An attacker only needs one configured, secret-less organization (owner.login) anywhere in the Shipit install to forge events for **any** other tracked repository (full_name) belonging to a different, secured organization.

### Impact Explanation
This crosses the "organization authenticated vs. repository written" trust boundary explicitly called out as an in-scope binding. Concretely:
- `PushHandler#process` calls `stack.sync_github(expected_head_sha: params.after)` on stacks resolved via the forged `full_name`, letting an attacker force a `GithubSyncJob`/deploy pipeline trigger for a repository/organization they do not control: [5](#0-4) 
- `ReopenedHandler#process` / `ClosedHandler#process` can unarchive/archive review stacks belonging to unrelated repositories: [6](#0-5) [7](#0-6) 

This is a cross-repository write / unauthorized-deploy-trigger class issue.

### Likelihood Explanation
Exploitability depends only on one org in the multi-tenant Shipit install having `webhook_secret` unset — a state the engine's own sample config treats as normal/supported (`config/secrets.development.shopify.yml`). No Shipit session, API token, or GitHub write access is needed; the attacker only needs to know that org's login and any other tracked repository's `full_name`, both of which are public metadata.

### Recommendation
Bind the signature-verifying organization to the repository actually acted upon: after resolving the target `Repository`/`Stack` via `full_name`, verify that its owning organization matches the `repository_owner`/App used to validate the signature, and reject (422) on mismatch. Additionally, do not allow `verify_webhook_signature` to trivially pass ("no secret configured") for organizations that own repositories tracked by Shipit — require an explicit secret for any org with active stacks.

### Proof of Concept
1. Deploy Shipit with two orgs configured: `org-empty` (no `webhook_secret`) and `org-secure` (has a `webhook_secret`, owns a tracked repository `org-secure/prod-app`).
2. POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "org-empty" },
    "full_name": "org-secure/prod-app"
  }
}
```
3. `verify_signature` selects `Shipit.github(organization: "org-empty")`, whose `verify_webhook_signature` returns `true` unconditionally (no secret configured) — no valid `X-Hub-Signature` needed.
4. `PushHandler` resolves the stack via `repository.full_name = "org-secure/prod-app"` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")`, forging a sync/deploy trigger for `org-secure`'s protected repository without ever satisfying `org-secure`'s signature check.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L41-45)
```ruby
          def process
            return unless respond_to_pull_request_reopened?

            stack.unarchive!
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-45)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end
```
