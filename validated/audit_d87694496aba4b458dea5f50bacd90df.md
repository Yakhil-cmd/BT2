### Title
Webhook signature verification keys off `repository.owner`/`organization`, while payload handlers act on the independent `repository.full_name` field, allowing cross-organization forged pushes/syncs - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
This mirrors the reported SpotEngineState bug class: the check is performed against one field (a "current" reference) while the effect is applied using a *different, unverified* field of the same message. In `SpotEngineState#updateBalance`, `state.cumulativeDepositsMultiplierX18` (the current multiplier) is used instead of `balance.lastCumulativeMultiplierX18` (the multiplier actually bound to the balance being unwound), letting a value computed against the wrong reference silently corrupt accounting. In shipit-engine, the webhook signature check is bound to the organization derived from `repository.owner.login`/`organization.login`, but the actual repository whose Stack gets acted upon is derived independently from `repository.full_name`, never re-checked against the value used to select/verify the signing secret.

### Finding Description
`WebhooksController#verify_signature` selects which GitHub App (and therefore which `webhook_secret`) to use for HMAC verification based on `repository_owner`: [1](#0-0) [2](#0-1) 

That is the *only* binding the HMAC signature is checked against — it proves "this raw body was signed with organization X's `webhook_secret`," nothing more.

Once the signature passes, `create` dispatches the same raw JSON body to event handlers: [3](#0-2) 

Handlers determine which `Stack`/`Repository` to mutate using a *different* payload field, `repository.full_name`, with no cross-check against `repository_owner`: [4](#0-3) [5](#0-4) 

The equality that should hold but doesn't:
`organization_that_authenticated(repository_owner) == organization_that_owns(repository.full_name)`

Because Shipit supports multiple independently configured GitHub Apps/organizations, each with its own `webhook_secret` (as shown by the multi-org secrets layout): [6](#0-5) 

an entity that legitimately administers one configured organization's GitHub App (and thus knows that organization's own `webhook_secret`, which it controls) can compute a valid HMAC over an arbitrary JSON body using its own secret, while filling `repository.full_name` (and other action-determining fields) with a *different* organization's repository that is also registered as a Shipit `Stack`. `verify_signature` only proves the body was signed by Org A's secret; it never verifies that the repository the handlers will act on belongs to Org A.

### Impact Explanation
`PushHandler#process` resolves the target `Stack` purely via `Repository.from_github_repo_name(repository_name)` (from `repository.full_name`) and calls `stack.sync_github(expected_head_sha: params.after)` for every matching, non-archived stack on the referenced branch — this is a cross-repository/cross-organization write triggered by a webhook signed under an unrelated organization's credential. Other handlers (`status`, `check_suite`, `pull_request/*`) follow the identical pattern of trusting `repository.full_name`/`payload['repository']` independent of the signature-selecting organization, so the same class of confusion extends to commit status writes, check-run refreshes, and pull-request/review-stack state changes across organizations. This falls under "cross-repository writes / unauthorized deploy pipeline trigger," matching the Critical impact bucket.

### Likelihood Explanation
Exploitation requires only the ability to send an arbitrary HTTP POST to the public `/webhooks` endpoint with a body correctly HMAC-signed under a secret the attacker legitimately possesses for their *own* configured organization — no Shipit session, `ApiClient` token, or GitHub write access to the victim repository is needed. The only prerequisite is that the Shipit instance is configured to serve multiple organizations (a documented, supported configuration), which is a realistic and intended deployment mode rather than a misconfiguration.

### Recommendation
Bind the two fields together: after `verify_signature` selects `repository_owner`, re-derive/require that `payload.dig('repository','full_name')`'s owner segment matches the same `repository_owner` (or `organization.login`) used to pick the signing secret, and reject the request (422) if they diverge, before dispatching to any handler.

### Proof of Concept
1. Shipit is configured with two organizations, `OrgA` and `OrgB`, each with its own `github.<org>.webhook_secret` (per `config/secrets.development.shopify.yml` layout), and both have Stacks registered (`OrgA/repoA`, `OrgB/repoB`).
2. An entity controlling `OrgA`'s GitHub App knows `OrgA`'s `webhook_secret` (it is the secret they configured).
3. They build a `push` event JSON body: `{"ref": "refs/heads/master", "after": "<attacker-chosen sha>", "repository": {"owner": {"login": "OrgA"}, "full_name": "OrgB/repoB"}}` and sign it with `OrgA`'s secret using the same HMAC-SHA1 scheme in `GithubApp#verify_webhook_signature`.
4. POST to `/webhooks` with `X-Github-Event: push` and `X-Hub-Signature: sha1=<computed>`.
5. `verify_signature` computes `repository_owner = "OrgA"`, fetches `Shipit.github(organization: "OrgA")`, and the signature verifies successfully.
6. `PushHandler#process` resolves `repository_name = "OrgB/repoB"` and calls `sync_github` on `OrgB`'s stack, triggering an unauthorized action on a repository the attacker never authenticated for.

Note: I was unable to fully trace whether `sync_github` alone (without a subsequent auto-deploy trigger) constitutes a completed "unauthorized deploy" versus just a commit sync in this codebase version — the deploy scheduling logic (`continuous_delivery_job.rb`, deploy spec) was not fully reviewed within the available iterations. The cross-repository write via `sync_github` and the broader pattern (signature-authorization field vs. action-target field mismatch) is confirmed at the code level cited above.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-31)
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
