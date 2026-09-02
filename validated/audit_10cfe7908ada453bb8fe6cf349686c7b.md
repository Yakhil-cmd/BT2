This is a solid analog to the double-claim bug. The report's bug class is "no check that the state-changing action's target is bound to the actor performing the previous authorization step." I found the same pattern in Shipit's multi-organization webhook handling: the entity used to authenticate the webhook (a GitHub organization's secret) is never bound to the entity that is written (an arbitrary commit, resolved only by SHA, with no ownership check).

### Title
Cross-organization webhook forgery leads to unauthorized deploy via unscoped commit-status lookup - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` picks which GitHub App (and thus which HMAC `webhook_secret`) to validate a webhook against using an attacker-controlled field of the payload itself (`repository.owner.login`, falling back to `organization.login`), rather than any value tied to the actual target resource. Once the signature check passes, `StatusHandler#process` resolves the commit to update purely by `Commit.where(sha: params.sha)` — with no scoping to the repository/organization that produced the signature. Because creating a `Status` with `state: 'success'` can trigger `ContinuousDeliveryJob` for whichever stack owns that commit, an attacker who legitimately controls **any** GitHub organization configured in this Shipit instance can forge a `status` webhook, sign it with their own org's secret, and have it applied to a commit belonging to a **different** organization's stack — potentially triggering an unauthorized deploy.

### Finding Description
Signature verification: [1](#0-0) [2](#0-1) 

`repository_owner` is read straight from the untrusted JSON body (`params.dig('repository', 'owner', 'login')` or `params.dig('organization', 'login')`), and is used to select which configured GitHub App's `webhook_secret` verifies the HMAC. Shipit explicitly supports multiple independent GitHub organizations, each with its own app/secret: [3](#0-2) 

So a valid signature only proves "the sender knows *some* configured org's secret" — it says nothing about which repository/commit the payload's other fields describe.

The `status` handler then resolves its target with no relation at all to the authenticating organization: [4](#0-3) 

`Commit.where(sha: params.sha)` is a global, unscoped lookup across every stack/repository tracked by the Shipit instance — it doesn't even use `repository.full_name` like other handlers do (e.g. `Handler#repository_name`, `PushHandler`), let alone check it against `repository_owner`.

Creating that status is not inert — it feeds continuous deployment: [5](#0-4) [6](#0-5) 

This is the same class of flaw as the escrow bug: `revertEscrow` trusted that "intent not INACTIVE/RELEASED" was sufficient without checking it wasn't already CLAIMED by a *different* code path (`claimIntent`) that shared the same funds. Here, `verify_signature` trusts that "HMAC verified against *an* org's secret" is sufficient authorization without checking that the org matches the *actual* repository/commit the handler is about to mutate.

**Binding that should hold but doesn't:**
`organization whose secret authenticated the webhook == organization owning the repository/commit the handler writes to`

Before the attack: attacker only has legitimate control of their own configured org O_a; victim stack S_v (with `continuous_deployment: true`) belongs to unrelated org O_v and has an undeployed commit with SHA `X` (visible via GitHub's public commit history/API).

After the attack: attacker POSTs a `status` webhook with `X-Hub-Signature` computed using O_a's own `webhook_secret`, body `{"sha": "X", "state": "success", "context": "<required CI context>", "repository": {"owner": {"login": "O_a"}}}`. `verify_signature` passes (checked against O_a's secret, which the attacker legitimately knows). `StatusHandler` finds commit `X` under stack S_v regardless of the `repository.owner.login` used for verification, creates a success `Status`, and if that satisfies `stack.deployable?`, `ContinuousDeliveryJob` deploys commit `X` on S_v — without the attacker ever having deploy permission, an `ApiClient` token, or write access to O_v/S_v.

### Impact Explanation
This lets an attacker who only controls one tenant's GitHub App/organization within a shared Shipit instance trigger an unauthorized deploy on a completely unrelated organization's stack, by forging CI-status data for a commit they don't own. This matches the Critical bucket ("an unauthorized deploy, rollback or merge") since it results in code execution/deployment on infrastructure the attacker has no legitimate authorization over.

### Likelihood Explanation
Requires the deployment to run multiple GitHub organizations with distinct webhook secrets (explicitly documented/supported), a victim stack with `continuous_deployment: true`, and the attacker knowing the target commit SHA and required status context — both plausible from public GitHub data or from the shared `shipit.yml`/status page. No Shipit session, `ApiClient` token, or GitHub App private key of the victim org is needed — only legitimate control of the attacker's own configured org.

### Recommendation
Scope commit/stack resolution in `StatusHandler` (and ideally all handlers) to the same repository that produced the verified signature, e.g. require `Repository.from_github_repo_name(repository_name)` to match the org used in `verify_signature`, and restrict `Commit.where(sha:)` to `stack.commits` for that resolved repository/stack rather than a global lookup.

### Proof of Concept
1. Deploy Shipit configured with two GitHub orgs, `attacker-org` (attacker-controlled webhook secret) and `victim-org` (stack `victim-stack`, `continuous_deployment: true`).
2. Attacker learns SHA `X` of an undeployed commit on `victim-org/victim-repo` (public on GitHub) and the CI `context` required by `victim-stack`'s `shipit.yml`.
3. Attacker builds payload `{"sha": "X", "state": "success", "context": "<context>", "repository": {"owner": {"login": "attacker-org"}}}` and signs it with `attacker-org`'s `webhook_secret` per `Hook::DeliverySigner`/`OpenSSL::HMAC` scheme (see `verify_webhook_signature` in `lib/shipit/github_app.rb`).
4. POST to `/webhooks` with `X-Github-Event: status` and the computed `X-Hub-Signature`.
5. `verify_signature` passes (checked against `attacker-org`'s own secret). `StatusHandler#process` finds commit `X` (belonging to `victim-stack`) via the unscoped `Commit.where(sha:)` and creates a `success` `Status`, satisfying `schedule_continuous_delivery`, which enqueues `ContinuousDeliveryJob` and deploys `X` on `victim-stack` without any authorization from `victim-org`.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-63)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-25)
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
```

**File:** app/models/shipit/status.rb (L18-20)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

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
