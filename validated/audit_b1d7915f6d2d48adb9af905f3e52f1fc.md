### Title
Webhook signature is verified against a secret selected from an unverified organization field, decoupling the org that authenticates from the repository whose stack is actually mutated - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks *which* GitHub App/organization's `webhook_secret` to validate the incoming HMAC signature against by reading `repository.owner.login` (or `organization.login`) straight out of the **unverified** JSON body, before the signature has been checked. Every webhook handler, however, resolves the `Stack`/`Repository` to act on using a *different* field from that same unverified body: `repository.full_name` (`app/models/shipit/webhooks/handlers/handler.rb:36-38`, and every handler such as `push_handler.rb`, `labeled_handler.rb`, `closed_handler.rb`, `opened_handler.rb`, `reopened_handler.rb`, `unlabeled_handler.rb`, `label_capturing_handler.rb`). Nothing ties `repository.owner.login` (the field used to select the signing secret) to `repository.full_name` (the field used to select the target stack). In a multi-organization Shipit deployment (explicitly supported, see `config/secrets.development.shopify.yml` and `test/dummy/config/secrets_double_github_app.yml`), this breaks the equality **"organization authenticated == repository written."**

### Finding Description
```ruby
# app/controllers/shipit/webhooks_controller.rb
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```
`repository_owner` is read from the raw, not-yet-verified JSON payload and used only to look up *which* `webhook_secret` to HMAC-check the raw body against (`lib/shipit/github_app.rb#verify_webhook_signature`). The signature computed by GitHub over the raw body will indeed match if the request was truly sent by that organization's app — so `verify_signature` legitimately proves "this payload's bytes were signed by OrgA's webhook secret."

But the handlers that subsequently execute never re-check that the repository actually acted upon belongs to that same OrgA. They instead trust:
```ruby
# app/models/shipit/webhooks/handlers/handler.rb
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```
Since `repository.owner.login` and `repository.full_name` are two independent JSON fields inside the same signed payload, and the signing organization owns/controls its own webhook secret (they can construct arbitrary valid payload bytes and sign them with their own secret), an attacker who legitimately controls OrgA's GitHub App/webhook secret (a normal, unprivileged position for any org onboarded to a shared multi-tenant Shipit instance) can freely choose `repository.full_name` to point at `"OrgB/some-repo"` while keeping `repository.owner.login == "OrgA"`. The signature will still verify (it's computed over OrgA's own crafted bytes with OrgA's own secret), yet the handler will operate on OrgB's `Stack`/`Repository`.

### Impact Explanation
This crosses an authorization boundary the engine relies on: each organization onboarded onto a shared Shipit instance is only supposed to control webhooks for its own repositories. By decoupling the field used for cryptographic authentication from the field used for target resolution, an organization/app-owner who is authenticated only for their own scope can forge webhook events attributed to arbitrary repositories/stacks belonging to a different organization on the same instance — e.g. forcing `stack.sync_github` (`push_handler.rb`), archiving/unarchiving review stacks (`labeled_handler.rb`, `unlabeled_handler.rb`, `reopened_handler.rb`), or closing/opening review stacks (`closed_handler.rb`, `opened_handler.rb`) for repositories they do not own. This is a cross-repository write performed with credentials that only authorize one, unrelated repository/org — matching the "cross-repository writes" Critical impact criterion, since it lets one tenant manipulate stack state of another tenant's repository without ever presenting valid credentials scoped to that repository.

### Likelihood Explanation
Likelihood is Medium-High in any deployment that follows the documented multi-organization configuration pattern (`config/secrets.development.shopify.yml`, `docs/setup.md`'s multi-org schema). Any org owner permitted to configure a GitHub App on the shared instance has full knowledge of their own `webhook_secret` and full control over the raw JSON body they submit (GitHub webhook delivery is just an HTTP POST with attacker-controlled body content and owner-controlled HMAC key) — no privileged Shipit session, API token, or `github_access_token` theft is required.

### Recommendation
After `verify_signature` succeeds, cross-check that the organization whose secret validated the signature (`repository_owner`) matches the owner segment of `repository.full_name` (or `organization.login`) that the handler will use to resolve the target `Stack`. Reject the webhook (422) if they differ, so the field used for authentication and the field used for authorization/target-resolution are provably the same value.

### Proof of Concept
1. Configure a shared Shipit instance with two organizations, `OrgA` and `OrgB`, each with their own GitHub App and `webhook_secret` (as documented in `config/secrets.development.shopify.yml`).
2. As the legitimate owner of `OrgA`'s GitHub App (an unprivileged party w.r.t. `OrgB`), craft a `push` (or `pull_request`) webhook JSON body:
   ```json
   {
     "ref": "refs/heads/main",
     "after": "<attacker-chosen sha>",
     "repository": {
       "owner": { "login": "OrgA" },
       "full_name": "OrgB/some-repo"
     }
   }
   ```
3. Compute `X-Hub-Signature` using `OrgA`'s own known `webhook_secret` over the exact raw body bytes.
4. POST to `/webhooks` with `X-Github-Event: push`. `verify_signature` calls `Shipit.github(organization: "OrgA")` and validates successfully against `OrgA`'s secret.
5. `PushHandler#stacks` resolves `Repository.from_github_repo_name("OrgB/some-repo")` and invokes `stack.sync_github(expected_head_sha: ...)` (or, with a `pull_request` event, archives/unarchives a review stack belonging to `OrgB`) — an action on `OrgB`'s stack performed using only `OrgA`'s credentials. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-27)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
    end
  end
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

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
```
