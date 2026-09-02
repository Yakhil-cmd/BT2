### Title
Webhook signature is verified against the organization derived from `repository.owner.login`, but write actions are keyed on the independently-attacker-controlled `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate the HMAC signature against by reading `repository.owner.login` (or `organization.login`) straight out of the still-unverified JSON body, then checks the signature with that organization's secret. [1](#0-0)  Once the signature check passes, the actual event handlers (`Shipit::Webhooks::Handlers::Handler#repository_name` and all `PullRequest::*Handler#repository` methods) independently re-derive the target repository from a *different* field of the same payload, `repository.full_name`, and use it to look up the `Repository`/`Stack` records that get mutated. [2](#0-1) [3](#0-2) 

### Finding Description
This is the same bug class as the GMX report's double counting: two distinct values (in GMX, `feeReceiverAmount`/`borrowingFeeAmount`; here, `repository.owner.login` and `repository.full_name`) are drawn from a single computation/payload and are implicitly assumed to always agree, but nothing in the code enforces that equality. In `PositionPricingUtils.getPositionFees`, `totalNetCostAmount` re-included `borrowingFeeAmount` even though `feeAmountForPool`/`feeReceiverAmount` already accounted for it — a value used for one purpose (accounting split) leaked into another calculation (total cost) that assumed independence. Here, the equality the engine implicitly relies on is:

`organization used to select webhook_secret (repository.owner.login) == organization prefix of the repository actually written (repository.full_name)`

GitHub's own webhook payloads always keep these consistent, but the HMAC signature only proves the raw body was signed by *some* configured organization's secret — it says nothing about which fields of that body are "trusted" beyond "the whole body came from whoever holds that org's `webhook_secret`". Nothing in `verify_signature` or in the handler layer cross-checks that `repository.full_name.split('/').first == repository_owner`. An operator running Shipit with multiple configured GitHub orgs (as documented in `config/secrets.development.shopify.yml` and `TOP_LEVEL_GH_KEYS`) each has its own `webhook_secret`. [4](#0-3)  Anyone who legitimately controls the webhook for organization A (i.e., knows `secretA`, e.g., because they administer their own GitHub App installation pointed at this Shipit instance, or because `secretA` leaked for a lower-trust org) can craft a raw JSON body where `repository.owner.login` (or `organization.login`) is `"orgA"` — so `verify_signature` fetches `secretA` and the HMAC passes — while `repository.full_name` is set to `"orgB/some-other-tracked-repo"`. The dispatched handler (`PushHandler`, `PullRequest::OpenedHandler`, `ClosedHandler`, `LabelCapturingHandler`, `AssignedHandler`, etc.) resolves the acted-upon `Repository`/`Stack` purely via `Repository.from_github_repo_name(params.repository.full_name)`, with no re-verification that this repository belongs to the org whose secret authenticated the request. [5](#0-4) [6](#0-5) 

### Impact Explanation
This crosses exactly the boundary the rules call out as in-scope: "an organization that authenticated versus the repository that is written." A `push` event forged this way causes `PushHandler#process` to call `stack.sync_github(expected_head_sha: ...)` on a stack belonging to an unrelated, victim-controlled repository/org, which enqueues `GithubSyncJob` to re-fetch and append real commits for that stack from GitHub using the app's own credentials. [7](#0-6)  Pull-request handlers can similarly create/archive/unarchive review stacks, or (via `LabelCapturingHandler`, `AssignedHandler`) mutate `PullRequest` records for a target repo the attacker never authenticated for. Chained with review-stack provisioning (which runs the target repo's `shipit.yml` steps) or continuous deployment settings, this is a cross-repository write / unauthorized deploy trigger driven by credentials scoped to a different repository than the one being acted on — squarely an unauthorized-deploy-class impact.

### Likelihood Explanation
Requires an attacker to control (or have leaked) the `webhook_secret` for at least one GitHub App/org configured in this Shipit instance's multi-org config, and for the instance to track a second, unrelated org/repo as a Stack. This is plausible in shared/multi-tenant Shipit deployments (the documented multi-org secrets format exists specifically to support several orgs on one instance), where a lower-trust org's app credentials are compromised or intentionally granted to a less-trusted team, but the operator relies on Shipit's webhook validation to keep each org's write scope isolated.

### Recommendation
After `verify_signature` succeeds, re-derive `repository.full_name`'s owner and assert it matches the `repository_owner` (or `organization.login`) that was used to select the verifying secret, rejecting (422) any payload where they diverge, before dispatching to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` in `WebhooksController#create`.

### Proof of Concept
Conceptual request (cannot be executed without a live multi-org Shipit deployment and a valid `webhook_secret` for “orgA”):
```
POST /webhooks
X-Github-Event: push
X-Hub-Signature: sha1=<HMAC-SHA1(secretA, raw_body)>

{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "orgA" },
    "full_name": "orgB/victim-repo"
  }
}
```
`verify_signature` looks up `Shipit.github(organization: "orgA")` and validates the signature with `secretA` — success. [1](#0-0)  `PushHandler#process`/`Handler#repository_name` then resolves the target using `repository.full_name` = `"orgB/victim-repo"`, triggering `sync_github` on that stack even though the request was never signed by orgB's secret. [2](#0-1)

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
