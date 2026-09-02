## Title
Cross-organization webhook forgery — verified signing organization is never bound to the repository/commit that gets mutated - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub organization's `webhook_secret` to check the `X-Hub-Signature` against using `repository_owner`, which is read from the same untrusted JSON body it is verifying: `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`. [1](#0-0)  Once the signature check passes for *that* organization, the raw, unvalidated `params` are handed to every matching `Shipit::Webhooks` handler, which independently determine *which repository/commit to mutate* using a different field of the same attacker-controlled body: `payload.dig('repository', 'full_name')` in `Handler#repository_name`, [2](#0-1)  or, worse, no repository scoping at all in `StatusHandler`, which updates commit status purely by `sha` across the entire instance: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`. [3](#0-2) 

### Finding Description
The equality that must hold is:
`organization whose secret authenticated the request == organization owning the repository/stack being mutated`

Nothing enforces this. `repository.owner.login` (used for auth) and `repository.full_name` (used to pick the `Repository`/`Stack`) are two independent, attacker-supplied fields in the same JSON body — GitHub itself keeps them consistent, but a forged POST to the public `/github/webhooks` endpoint does not have to. This is a multi-tenant instance by design: `config/secrets.development.shopify.yml` and `docs/setup.md` show `Shipit.github` configured per-organization, each with its own `webhook_secret`. [4](#0-3)  `lib/shipit/github_app.rb#verify_webhook_signature` only checks the HMAC against the secret for the organization resolved from `repository_owner`; it does not verify the target repository belongs to that same organization: `verify_webhook_signature(signature, message)` compares against `webhook_secret` for `@organization` only. [5](#0-4)  Notably it also `return true unless webhook_secret`, so any organization configured without a secret authenticates unconditionally. [6](#0-5) 

An attacker who legitimately controls one onboarded organization (or finds one configured with a blank `webhook_secret`) can:
1. Craft a JSON body with `repository.owner.login`/`organization.login` set to their own organization (satisfying `verify_signature`), and sign it with that organization's known secret.
2. Set `repository.full_name` (in `push`, `check_suite`) or `sha` (in `status`) to reference a stack/commit belonging to a completely different, victim organization tracked by the same Shipit instance.
3. `PushHandler` will resolve `stacks` via `Repository.from_github_repo_name(repository_name)` — the victim's repo — and enqueue `GithubSyncJob` with an attacker-chosen `expected_head_sha`. [7](#0-6)  `StatusHandler` is even less scoped: it matches by bare `sha` across all commits/stacks in the database and writes an arbitrary CI status (`state`, `description`, `context`) onto that commit. [8](#0-7) 

### Impact Explanation
Shipit gates deploys on required/blocking CI statuses reported through this same status pipeline. Forging a passing `status` webhook for a commit in a victim stack — while authenticating under an unrelated organization's own webhook secret — lets an attacker mark an arbitrary commit as deployable, i.e., manipulate cross-repository deploy-readiness state without any write access to the victim repository. This is a cross-repository write / unauthorized-deploy precondition: an org's own credentials are being leveraged to write into a repository/stack that org does not own, crossing the trust boundary the per-organization `webhook_secret` design is meant to enforce.

### Likelihood Explanation
Requires the Shipit deployment to host more than one GitHub organization (a documented, supported configuration) and requires the attacker to control (or find blank-secret) one onboarded organization — a materially weaker precondition than compromising the victim organization's own secret or gaining repository write access. No code change on the attacker's part beyond crafting the JSON body is needed; the mismatch between the field used for authentication and the field used for authorization is structural.

### Recommendation
After `verify_signature` succeeds, re-derive `repository_owner`/organization from the resolved `Repository`/`Stack` record (not from attacker-controlled payload fields) and reject the webhook if it does not match the organization whose secret validated the signature. Alternatively, scope every handler's lookup (`Handler#stacks`, `StatusHandler#process`, `CheckSuiteHandler#process`) to repositories confirmed to belong to the authenticated organization, and stop treating `webhook_secret.blank?` as an implicit pass.

### Proof of Concept
1. Configure Shipit with two organizations, `attacker-org` (secret known to attacker) and `victim-org` (hosts stack `victim-org/app`).
2. POST to `/github/webhooks` with header `X-Github-Event: status`, body:
```json
{
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/app" },
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/required-check"
}
```
3. Sign with `X-Hub-Signature: sha1=<hmac using attacker-org's webhook_secret>`.
4. `verify_signature` resolves `Shipit.github(organization: "attacker-org")` and succeeds against the attacker's own secret. [9](#0-8) 
5. `StatusHandler#process` locates the commit purely by `sha` (ignoring `repository`) and records a forged successful status on the victim's commit. [3](#0-2)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-24)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
