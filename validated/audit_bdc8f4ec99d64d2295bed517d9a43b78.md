### Title
Webhook `status` event is authenticated per-organization but writes commit status without any repository binding, enabling cross-repository CI forgery and unauthorized continuous deployment - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` selects a `GitHubApp` (and thus a `webhook_secret`) using an organization derived from the payload's `repository.owner.login`/`organization.login`, and validates the raw HMAC signature against *that* organization's secret only. Once verification passes, the entire raw payload is handed to every registered handler for the event. `Shipit::Webhooks::Handlers::StatusHandler#process`, however, resolves the target purely by `sha` — `Commit.where(sha: params.sha)` — with no check that the commit's `stack`/repository belongs to the organization whose secret authenticated the request. [1](#0-0) [2](#0-1) 

### Finding Description
This is the same trust-binding break described in the audit report's `LoadVersion`/`ReadOnly` bug: one component authenticates against context A (the organization resolved from `repository_owner`, verified by `GitHubApp#verify_webhook_signature`) while a different component acts on context B (any commit anywhere in the Shipit instance matched only by `sha`), with no code path re-checking that A and B are the same trust boundary.

Concretely:
- `verify_signature` computes `repository_owner` from the payload and asks `Shipit.github(organization: repository_owner)` for that org's `GitHubApp`, then checks the signature solely against that org's `webhook_secret`. [3](#0-2) 
- Shipit explicitly supports multiple GitHub organizations, each configured independently with its own `webhook_secret` (which the setup docs and fixtures show as commonly left blank/`nil`). [4](#0-3) 
- `GitHubApp#verify_webhook_signature` trivially returns `true` when no `webhook_secret` is configured for that org: `return true unless webhook_secret`. [5](#0-4) 
- Once verification passes for *any* configured organization, `WebhooksController#create` dispatches the same payload to `StatusHandler.call`, which looks up commits **only by `sha`**, with zero reference to `repository_owner`/`full_name`/organization: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`. [6](#0-5) 
- Compare this with every other handler (`PushHandler`, `PullRequest::*Handler`), which do scope by `repository.full_name` before acting: [7](#0-6) [8](#0-7) 

Because commit SHAs are globally unique 40-character hashes but not secret (they are visible in Shipit's own UI/API for any stack, and in the source GitHub repo), an attacker who can produce one valid signature for *any single* organization served by the Shipit instance (including one with no `webhook_secret` configured, which `verify_webhook_signature` accepts unconditionally) can forge a `status` webhook naming an arbitrary `sha` belonging to a *completely different* organization/stack tracked by the same instance, and inject a forged commit status for it.

### Impact Explanation
A forged `success` status on a commit directly feeds `Commit#create_status_from_github!` → `Status#enable_ci_on_stack` / `schedule_continuous_delivery`, and `Commit#schedule_continuous_delivery` triggers `ContinuousDeliveryJob` once `deployable?` and `stack.continuous_deployment?` are true. [9](#0-8) [10](#0-9) 

This means an attacker who only controls the signing secret/authentication of one weakly-configured (or unconfigured) organization on a shared Shipit instance can forge CI-passing status on a commit belonging to an unrelated, more sensitive repository/stack and trigger an **unauthorized deploy** via continuous delivery — matching the report's Critical bar ("unauthorized deploy, rollback or merge").

### Likelihood Explanation
Multi-organization Shipit deployments are a documented, first-class configuration (`docs/setup.md`, "Using Multiple Github Applications"), and both the example config and the multi-org test fixture show `webhook_secret` as commonly left `nil`. [11](#0-10) [12](#0-11)  Any instance operator running such a shared, multi-tenant setup where at least one configured organization lacks a `webhook_secret` (or where the attacker has any legitimate ability to push a commit status to one org they control) exposes every other tracked stack to this cross-organization status forgery, since `WebhooksController` requires no session, token, or repository access — only a raw HTTP POST.

### Recommendation
`StatusHandler` (and any other handler that mutates state) must verify that the resolved `Commit`'s `stack.repository` actually matches the `repository`/`organization` that was used to select and validate the webhook signature, not merely match by `sha`. At minimum, scope the `Commit.where(sha: ...)` lookup by `stack.repository.owner`/`full_name` taken from the same payload field used in `verify_signature`, and reject/ignore statuses whose declared repository does not match the commit's actual stack repository. Additionally, do not allow organizations with a blank `webhook_secret` to implicitly authenticate write-triggering events for other, differently-configured organizations sharing the same instance.

### Proof of Concept
1. Shipit instance is configured with two organizations, e.g. `OrgWeak` (no `webhook_secret` set, as shown to be a supported/likely configuration) and `OrgTarget` (has a properly configured `webhook_secret`, tracks a stack with `continuous_deployment: true`).
2. Attacker (no session, no API token, no repo write access) sends:
   ```
   POST /webhooks
   X-Github-Event: status
   X-Hub-Signature: sha1=<anything>
   {
     "repository": { "owner": { "login": "OrgWeak" }, "full_name": "OrgWeak/whatever" },
     "sha": "<sha of latest commit on OrgTarget's tracked stack, obtained from the public Shipit UI/API>",
     "state": "success",
     "context": "ci/forged"
   }
   ```
3. `verify_signature` resolves `Shipit.github(organization: "OrgWeak")`; since `OrgWeak` has no `webhook_secret`, `verify_webhook_signature` returns `true` unconditionally, regardless of the (fake) `X-Hub-Signature` header. [5](#0-4) 
4. `Shipit::Webhooks.for_event('status')` dispatches to `StatusHandler`, which finds the commit purely by `sha` (belonging to `OrgTarget`'s stack) and creates a `success` status on it. [6](#0-5) 
5. If that commit is now `deployable?` and its stack has `continuous_deployment: true`, `ContinuousDeliveryJob` is scheduled and the commit is deployed to `OrgTarget`'s production stack without any legitimate CI signal or credential belonging to `OrgTarget`. [9](#0-8) 

Note: full exploitation depends on the specific `Shipit.github` configuration (multi-org with at least one unauthenticated org, or an attacker who can legitimately trigger a signed webhook for any one configured org) — I could not verify from the index whether any specific deployed instance actually runs in this configuration; the vulnerability is in the engine's own lack of a repository/organization binding check in `StatusHandler`, independent of that configuration detail.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-61)
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

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
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

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```

**File:** app/jobs/shipit/continuous_delivery_job.rb (L1-22)
```ruby
# frozen_string_literal: true

module Shipit
  class ContinuousDeliveryJob < BackgroundJob
    include BackgroundJob::Unique

    queue_as :deploys
    on_duplicate :drop

    def perform(stack)
      return unless stack.continuous_deployment?

      # If there is a schedule defined for this stack, make sure we are within a
      # deployment window before proceeding.
      return if stack.continuous_delivery_schedule && !stack.continuous_delivery_schedule.can_deploy?

      # checks if there are any tasks running, including concurrent tasks
      return if stack.occupied?

      stack.trigger_continuous_delivery
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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-20)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
      # Randomly generated
      private_key: |
        -----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQEA7iUQC2uUq/gtQg0gxtyaccuicYgmq1LUr1mOWbmwM1Cv63+S
        73qo8h87FX+YyclY5fZF6SMXIys02JOkImGgbnvEOLcHnImCYrWs03msOzEIO/pG
        M0YedAPtQ2MEiLIu4y8htosVxeqfEOPiq9kQgFxNKyETzjdIA9q1md8sofuJUmPv
        ibacW1PecuAMnn+P8qf0XIDp7uh6noB751KvhCaCNTAPtVE9NZ18OmNG9GOyX/pu
        pQHIrPgTpTG6KlAe3r6LWvemzwsMtuRGU+K+KhK9dFIlSE+v9rA32KScO8efOh6s
        Gu3rWorV4iDu14U62rzEfdzzc63YL94sUbZxbwIDAQABAoIBADLJ8r8MxZtbhYN1
        u0zOFZ45WL6v09dsBfITvnlCUeLPzYUDIzoxxcBFittN6C744x3ARS6wjimw+EdM
        TZALlCSb/sA9wMDQzt7wchhz9Zh2H5RzDu+2f54sjDh38KqancdT8PO2fAFGxX/b
        qicOVyeZB9gv6MJtJc20olBbuXAeBNfcDABF9oxF+0i+Ssg7B4VXiqgcjtGbr/Og
        qRll7AqyTArVx2xEcVfZxeZ4zGnigzcJq4te7yYpxzwk+RxblkPh54Yt4WxZ+8DI
```
