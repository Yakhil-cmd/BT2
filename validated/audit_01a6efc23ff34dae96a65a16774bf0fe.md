### Title
Cross-organization webhook authentication allows CI-status forgery on unrelated stacks - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects *which* GitHub App/organization's secret to validate a webhook's HMAC signature against using an attacker-controlled field (`repository.owner.login` or `organization.login`), while the handlers that actually mutate state (`Shipit::Webhooks::Handlers::StatusHandler`, `PushHandler`, etc.) act on a *different* attacker-controlled field (`repository.full_name`, or in `StatusHandler`'s case, no repository scoping at all — just `sha`). This breaks the binding: `organization whose signature was verified == repository/commit actually written to`.

### Finding Description
`Shipit.github(organization: repository_owner)` looks up the GitHub App config for the org named in the payload, and `verify_webhook_signature` is then evaluated against that org's `webhook_secret`: [1](#0-0) [2](#0-1) 

Critically, `GithubApp#verify_webhook_signature` treats an organization with no configured `webhook_secret` as **always verified**: [3](#0-2) 

Meanwhile, the handlers that consume the same JSON body select the target `Stack`/`Commit` using a *completely independent* field of the payload. `Handler#repository_name` reads `repository.full_name`, not `repository.owner.login`: [4](#0-3) 

`StatusHandler` is worse still — it does not consult the repository at all, it matches purely on commit `sha` across the entire `Commit` table: [5](#0-4) [6](#0-5) 

Because signature verification is keyed off `repository.owner.login`/`organization.login` while the actual mutation is keyed off `repository.full_name` (for push/pull_request/check_suite handlers) or `sha` alone (for status), an attacker who can produce a "verified" webhook for **one** organization (e.g. any org onboarded with `webhook_secret` left blank — a supported, documented configuration per `config/secrets.development.shopify.yml`) can freely set `repository.full_name` or `sha` to target a **different**, fully-secret-protected organization's stack/commit. The equality that should hold — `org(signature verified) == org(state written)` — does not, exactly mirroring the reported bug class where a value governing one side of a check (the fee/percentage) was unconstrained relative to what it is later applied to.

### Impact Explanation
Via `StatusHandler`, an attacker who controls (or can trivially guess/observe, since commit SHAs are public GitHub data) the SHA of a commit belonging to a protected, high-value stack can inject a forged `success` CI status for that commit by routing the webhook through an organization whose `webhook_secret` is unset. `Commit#create_status_from_github!` will accept it unconditionally, and `Commit#deployable?` / `Commit#blocked?` / merge-request gating (`StatusChecker`, `MergeRequest#reject_unless_mergeable!`) rely on these statuses to decide whether a commit may be **deployed or merged**: [7](#0-6) 

This can enable an unauthorized deploy or merge by satisfying required-status gates with forged data — squarely within the "unauthorized deploy, rollback, or merge" impact category, achieved without any Shipit session, `ApiClient` token, or knowledge of the target organization's actual `webhook_secret`.

### Likelihood Explanation
Exploitability depends entirely on at least one organization configured in `Shipit.secrets.github` having no `webhook_secret` set — a state the code explicitly tolerates (`return true unless webhook_secret`) rather than rejecting, and one that is shown as a normal example configuration. Given multi-tenant Shipit deployments onboarding many GitHub orgs over time, an under-configured org is a realistic, low-effort condition for an external attacker to find (a single POST to `/webhooks` with a bogus/no-secret org name reveals via the 422 vs 200 response whether that org requires a signature). No privileged credentials, sessions, or secrets are required — this is purely an unauthenticated HTTP POST to a public endpoint.

### Recommendation
Decouple state mutation from the org used for authentication, or better, remove the "no secret = accept" bypass entirely:
- Require every configured GitHub organization to have a non-blank `webhook_secret` before that org's app is usable to verify webhooks (fail closed rather than fail open).
- After verifying the signature for `repository_owner`, re-validate that every stack-mutating handler only operates on repositories/commits that belong to that same verified organization (e.g., `StatusHandler` should scope `Commit.where(sha:)` by the stack's `repository.owner`, not by SHA alone).

### Proof of Concept
1. Configure Shipit with two GitHub organizations in `secrets.yml`: `orgA` (no `webhook_secret` set) and `orgB` (properly configured with a secret, hosting a protected stack whose deploy/merge gates require CI status `ci/required`).
2. Observe (or already know) the SHA of a pending commit on an `orgB` stack awaiting a passing `ci/required` status.
3. POST to `/webhooks` with header `X-Github-Event: status` and no valid `X-Hub-Signature`, body:
   ```json
   {
     "sha": "<target orgB commit sha>",
     "state": "success",
     "context": "ci/required",
     "repository": { "owner": { "login": "orgA" } }
   }
   ```
4. `verify_signature` calls `Shipit.github(organization: "orgA").verify_webhook_signature(...)`, which returns `true` because `orgA`'s `webhook_secret` is blank — no valid signature is required.
5. `StatusHandler.process` runs `Commit.where(sha: params.sha)` and finds the `orgB` commit (no organization scoping), then calls `create_status_from_github!`, marking it as passing `ci/required` despite never having a real CI signal — enabling deploy/merge to proceed on `orgB`'s protected stack.

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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L227-237)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end

    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
    end
```
