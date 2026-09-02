### Title
Webhook signature verification keys off `repository.owner.login`/`organization.login`, but event handlers act on the unrelated `repository.full_name` field, letting an org with a valid webhook secret forge events for stacks belonging to any other org on the same instance - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` chooses which GitHub App/webhook secret to validate the HMAC against using `repository_owner`, derived from `params.dig('repository','owner','login')` (falling back to `params.dig('organization','login')`). Once the signature check passes, the payload is dispatched to handlers (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, PR handlers, etc.) that resolve the target `Repository`/`Stack` from a *different* JSON field, `repository.full_name` (or `sha` for status). Nothing ties the two together, so the org whose secret validated the signature is never checked against the repository the event actually mutates.

### Finding Description
`verify_signature` in `app/controllers/shipit/webhooks_controller.rb` does: [1](#0-0) 
which computes the signing org purely from attacker-controlled JSON body fields (`repository_owner`), and: [2](#0-1) 

Every handler that processes the (now "verified") body resolves the actual target repository from a *separate* field of the same body, `repository.full_name`: [3](#0-2) 

For example `PushHandler` triggers a real `sync_github` on every matching stack: [4](#0-3) 

and `StatusHandler` creates a commit status directly from attacker-supplied `state`/`context` for any commit matching `params.sha` — with no repository-ownership check at all, only a SHA match: [5](#0-4) 

`Repository.from_github_repo_name` performs a straight DB lookup with no relation to which org's secret validated the request: [6](#0-5) 

Shipit explicitly supports multiple GitHub organizations/apps configured on a single instance, each with its own `webhook_secret`, as documented in `config/secrets.development.shopify.yml` and `docs/setup.md`: [7](#0-6) 

**The broken binding**: the organization whose webhook secret is used to *authenticate* the request (`repository_owner` → `Shipit.github(organization: repository_owner)`) is not equal to the repository/stack that the handler actually *writes to* (`repository.full_name` / `sha` lookups). An org administrator who legitimately knows their own org's `webhook_secret` (they configured it per `docs/setup.md`) can produce a validly-signed request body in which `repository.owner.login`/`organization.login` is their own org (so it passes `verify_signature`), while `repository.full_name` (or `sha`) references a stack belonging to a completely different, unrelated org hosted on the same Shipit instance.

### Impact Explanation
This crosses the "organization that authenticated versus the repository that is written" binding called out explicitly as in-scope. Concretely:
- Via `StatusHandler`, an attacker can forge `commit_status` events for any commit SHA that happens to exist in another org's stack, setting `state: success` on a required CI context. Combined with `continuous_deployment`/CI-gated auto-deploy, this can cause an **unauthorized deploy** to a victim's stack whose commits never actually passed CI, purely because the attacker's own org secret validated the envelope.
- Via `PushHandler`, arbitrary victim stacks can have `sync_github` triggered with an attacker-chosen `expected_head_sha`, and `CheckSuiteHandler`/PR handlers can similarly be pointed at unrelated repositories.
- This does not require any Shipit session, API token, or repository write access on the target repo — only legitimate control of a *different*, unrelated org's webhook secret that is already configured on the instance, which fits the "unprivileged attacker" framing relative to the victim stack.

### Likelihood Explanation
This requires the deployment to be multi-tenant (multiple organizations configured under `github:` in secrets, as shown in the shipped `config/secrets.development.shopify.yml` example and `docs/setup.md`), which is a documented, supported configuration. Any legitimate owner/admin of one onboarded org (who therefore possesses that org's real webhook secret) can exploit this by hand-crafting a webhook body pointed at another org's repository/stack — no phishing or credential theft needed, and no exotic tooling beyond a valid HMAC computation with a secret they legitimately hold.

### Recommendation
After signature verification, re-derive the authenticated organization and require that `repository.owner.login` (or `organization.login`) used to select the signing key matches the owner of the `Repository` resolved from `repository.full_name` (and, for `StatusHandler`, verify the commit's repository ownership matches the authenticated org) before dispatching to handlers. Reject the request if they diverge.

### Proof of Concept
1. Configure Shipit with two orgs, `orgA` and `orgB`, each with distinct `webhook_secret`s (as in `config/secrets.development.shopify.yml`).
2. As the legitimate owner of `orgA`, craft a `status` webhook JSON body:
```json
{
  "sha": "<sha of a commit that exists in orgB/victim-repo's stack>",
  "state": "success",
  "context": "required-ci-check",
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/victim-repo" }
}
```
3. Sign it with `orgA`'s real `webhook_secret` (HMAC-SHA1 per `GithubApp#verify_webhook_signature`) and send it as `X-Hub-Signature` to `POST /webhooks` with `X-Github-Event: status`.
4. `verify_signature` calls `Shipit.github(organization: 'orgA')` (from `repository.owner.login`) and the signature validates successfully.
5. `StatusHandler#process` looks up `Commit.where(sha: params.sha)` — which belongs to `orgB`'s stack — and calls `create_status_from_github!`, marking the CI check green on a commit the attacker does not control, in an organization the attacker has no access to. [8](#0-7) [9](#0-8)

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-27)
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
      end
    end
  end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** config/secrets.development.shopify.yml (L5-23)
```yaml
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
