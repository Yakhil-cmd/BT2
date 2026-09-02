### Title
Cross-organization forged commit-status injection via webhook signature/repository binding mismatch - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate a webhook's HMAC signature against using a value taken from the *same untrusted JSON payload* (`repository.owner.login` or `organization.login`). Once the signature check passes, event handlers such as `StatusHandler` and `CheckSuiteHandler` act on a *different, independently attacker-controlled* payload field (`repository.full_name`, or for `StatusHandler`, no repository scoping at all) to decide which `Stack`/`Commit` records to mutate. The org whose secret authenticated the request is never checked against the org/repo that is actually written to.

### Finding Description
`WebhooksController#verify_signature` picks the app config by `repository_owner`, itself parsed straight from the request body: [1](#0-0) [2](#0-1) 

```
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

The HMAC is verified with `Shipit.github(organization: repository_owner).verify_webhook_signature(...)` [3](#0-2) . The actual per-org secret used for the HMAC comparison lives in `GithubApp#verify_webhook_signature` [4](#0-3) .

Downstream, `Handler#repository_name`/`#stacks` resolve the target repository from a *separate* field of the same payload, `repository.full_name` [5](#0-4) , which is never cross-checked against `repository_owner`. `PushHandler`, `CheckSuiteHandler`, and the `PullRequest::*` handlers all key off `repository.full_name` this way [6](#0-5) [7](#0-6) .

`StatusHandler` is worse: it does not scope by repository at all — it matches purely by commit SHA across the **entire** Shipit instance: [8](#0-7) 

```
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```

On a multi-tenant Shipit deployment (which the engine explicitly supports — `config/secrets.development.shopify.yml` shows multiple orgs each with their own `webhook_secret`/`oauth` block [9](#0-8) ), an attacker who legitimately administers **any one** of the configured organizations (and therefore genuinely knows that org's real `webhook_secret`, without needing any Shipit credential, `ApiClient` token, or victim secret) can:

1. Craft a raw JSON body with `repository.owner.login` (or `organization.login`) = their own org (`attacker-org`), but `sha`/`state` referencing an arbitrary commit SHA that belongs to a *different* stack/org entirely (victim's repo).
2. Compute `X-Hub-Signature` over that body using `attacker-org`'s real webhook secret.
3. POST it to the shared `/webhooks` endpoint.

`verify_signature` passes because it validates the signature against `attacker-org`'s own secret — the only binding it checks. `StatusHandler#process` then writes a forged commit status (e.g., `state: "success"`) onto the victim's `Commit` record purely by SHA match, without any relation to `attacker-org`.

### Impact Explanation
`Commit#deployable?` gates deploy eligibility on `success? && !blocked?` unless `stack.ignore_ci?` [10](#0-9) , and `create_status_from_github!`/`add_status` also triggers `schedule_continuous_delivery`, which enqueues `ContinuousDeliveryJob` once a commit becomes `deployable?` and the stack has `continuous_deployment?` enabled [11](#0-10) . By forging a `state: "success"` status for a victim commit that has not actually passed CI, a tenant admin with no relationship to the victim's org/repo can:
- Flip a victim commit's deployability from "blocked/pending" to "deployable", causing an **unauthorized/automatic deploy** on a stack with continuous deployment enabled, or
- Enable a Shipit user of the victim's stack to manually trigger a deploy that CI would otherwise have blocked.

This is a cross-tenant, cross-repository write breaking the exact binding called out in scope: "an organization that authenticated versus the repository that is written." It maps to the High-impact category "escalation into authorization... unauthorized deploy" without requiring any Shipit session, `ApiClient` token, `webhook_secret` of the victim, or repository write access to the victim's repo.

### Likelihood Explanation
Requires only that the attacker administers (or has been granted a GitHub App/webhook_secret for) any single organization configured on the same shared Shipit instance — a realistic scenario for any multi-tenant Shipit deployment, which the engine's own config format (`config/secrets.*.yml` supporting multiple named orgs) is built to support. No knowledge of the victim's secret, no GitHub write access to the victim repo, and no Shipit login are needed; only knowledge that the victim's commit SHA exists (visible from the victim's public/private repo activity or from Shipit's own public UI if the stack/commit list is browsable).

### Recommendation
- In `WebhooksController#verify_signature`, after establishing which organization's secret validated the signature, re-derive `repository_owner`/organization identity independently from a source that cannot be renamed relative to `repository.full_name` and enforce equality (or better, have handlers filter by the *verified* organization, not raw payload fields).
- In every `Webhooks::Handlers::Handler` subclass (`StatusHandler` in particular), scope lookups (`Commit.where(sha:)`, etc.) to `Repository.from_github_repo_name(repository_name)` and additionally assert that the repository's owning organization matches the organization whose webhook secret authenticated the request.
- Reject/short-circuit webhook processing when `repository.owner.login` and the org implied by `repository.full_name` diverge.

### Proof of Concept
1. Configure Shipit with two orgs, e.g. `attacker-org` (attacker knows its `webhook_secret`) and `victim-org` (has a Stack tracking commit `abcdef123...`).
2. POST to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/some-repo" },
  "sha": "abcdef123...",
  "state": "success",
  "context": "ci/forged",
  "created_at": "2026-09-02T00:00:00Z"
}
```
3. Set `X-Hub-Signature: sha1=<HMAC-SHA1 of the raw body using attacker-org's real webhook_secret>`.
4. `verify_signature` succeeds (verified against `attacker-org`). `StatusHandler#process` matches `Commit.where(sha: "abcdef123...")`, which resolves to the victim's commit (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`), and calls `commit.create_status_from_github!`, injecting a forged "success" status onto `victim-org`'s commit — with no relationship checked between `attacker-org` and `victim-org`.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
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
```

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
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
