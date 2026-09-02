Found it: `WebhooksController#verify_signature` selects which GitHub App/secret to validate the HMAC against using `repository_owner`, a value read from the parsed JSON body — but the actual repository/stack that event handlers act on (`repository.full_name`, used by `Handler#stacks`/`repository_name`, and `StatusHandler#process`) is a *separate* field in that same body that is never cross-checked against the owner used for verification.

### Title
Webhook signature is validated against the payload's declared organization, not the repository the event handler actually writes to - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks the GitHub App/secret to verify the HMAC with by reading `repository.owner.login` (falling back to `organization.login`) out of the untrusted, not-yet-verified JSON body, via `repository_owner`. [1](#0-0) [2](#0-1)  The event handlers that then act on the payload (e.g. `Handler#stacks`, `Handler#repository_name`, `StatusHandler#process`) look up the target `Stack`/`Repository` using the payload's `repository.full_name` field — a field that is completely independent from `repository.owner.login` and is never re-validated to belong to the organization whose secret authenticated the request. [3](#0-2) [4](#0-3) 

### Finding Description
The binding that should hold is: `organization whose webhook_secret authenticated the request == organization owning the repository the handler mutates`. In practice the code checks: `Shipit.github(organization: repository_owner)` where `repository_owner = params.dig('repository','owner','login') || params.dig('organization','login')` [2](#0-1) , then, if the HMAC matches for *that* organization's secret, hands the *entire* raw payload to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [5](#0-4) . Handlers such as the base `Handler#stacks` resolve which repository/stack to act on purely from `payload.dig('repository', 'full_name')` [3](#0-2) , and `StatusHandler#process` writes a commit status by SHA without any repository-ownership re-check at all [6](#0-5) .

Because `repository.owner.login` and `repository.full_name` are two unrelated JSON fields in the same request body, an org whose Shipit-configured `webhook_secret` is known/leaked to an attacker (e.g. an org admin at "OrgA" configured in the same Shipit instance as "OrgB") could construct a payload where `repository.owner.login = "OrgA"` (so the HMAC validates against OrgA's secret) but `repository.full_name = "OrgB/some-repo"` (so the handler acts on OrgB's stack). Signature verification covers the raw bytes and therefore "proves" the sender knows OrgA's secret, but it does not prove OrgA actually owns the repository field that the handler trusts to select the target stack.

### Impact Explanation
This crosses a repository-scoping boundary inside a single Shipit deployment that hosts multiple organizations/apps configured with different `webhook_secret`s: possessing valid webhook credentials for one org lets you drive `commit_status`/push/pull_request/membership handlers against a *different* org's stacks (e.g. forging CI green statuses on arbitrary commits via `StatusHandler`, which can unblock merges/deploys) — an unauthorized cross-repository write consistent with the "cross-repository writes" impact bucket.

### Likelihood Explanation
Requires the attacker to already control a legitimate `webhook_secret` for at least one organization configured on the instance (an org admin, or a leaked/rotated-late secret) and knowledge of another org's repository full name — a real但 non-trivial precondition given multi-tenant Shipit deployments configuring several `Shipit.github(organization: ...)` entries with distinct secrets. This is not exploitable by a fully unprivileged outsider with zero webhook credentials, which limits likelihood but the flaw is squarely a signature/binding-scope defect in the engine's own code, not a hosting misconfiguration.

### Recommendation
After computing `repository_owner` for signature verification, re-derive the same field from the verified payload and assert that `params.dig('repository','full_name')`'s owner segment matches `repository_owner` before dispatching to handlers; alternatively, resolve the target `Stack`/`Repository` via the organization whose secret validated the signature rather than trusting `repository.full_name` independently.

### Proof of Concept
1. Configure two organizations in `Shipit.github_configs`: `OrgA` (secret `SA` known to attacker, e.g., attacker is an OrgA GitHub App admin) and `OrgB` (secret `SB`, unknown to attacker), each with stacks tracked by the same Shipit instance.
2. Attacker crafts a `status` webhook JSON body: `{"sha": "<OrgB commit sha>", "state": "success", "repository": {"owner": {"login": "OrgA"}, "full_name": "OrgB/target-repo"}}`.
3. Attacker computes `X-Hub-Signature` using `SA` (known) over this exact raw body.
4. `WebhooksController#verify_signature` computes `repository_owner = "OrgA"`, fetches OrgA's app/secret, and the HMAC check passes. [1](#0-0) 
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` and creates a `success` status on OrgB's commit — a status the attacker had no legitimate right to set. [4](#0-3)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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
