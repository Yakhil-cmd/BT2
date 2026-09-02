## Analog Analysis

The wasmtime report is a version-bump patch with no direct code analog. Applying the specified bug class (payload field acted on but never covered by binding verification — specifically "an organization that authenticated versus the repository that is written") to this engine's webhook trust boundary produces a concrete, reachable finding.

### Title
Webhook `status` event is applied by global commit SHA lookup with no binding to the authenticating organization/repository - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate the HMAC against using `repository_owner` (`params.dig('repository','owner','login')` or `params.dig('organization','login')`), scoping trust per-organization via `Shipit.github(organization: repository_owner)`. But `Webhooks::Handlers::StatusHandler#process` never re-checks that binding — it looks up commits purely by SHA across the *entire* instance (`Commit.where(sha: params.sha)`), with no repository/stack/organization filter at all.

### Finding Description
`app/controllers/shipit/webhooks_controller.rb` verifies the webhook signature against the secret configured for the organization named in the payload: [1](#0-0) [2](#0-1) 

Once verified, the raw JSON is dispatched to handlers registered for the event, with no repository scoping enforced by the controller itself: [3](#0-2) 

`StatusHandler`, which processes the `status` event, only requires `sha` and `state` from the payload and matches commits globally by SHA, with no `repository` field required or checked: [4](#0-3) 

This breaks the binding: `organization authenticated by verify_signature (repository.owner.login)` == `organization/repository whose commit is mutated (Commit#stack, resolved purely by sha)`. Nothing enforces that the commit matched by `sha` belongs to a stack/repository owned by the organization whose webhook secret validated the signature. In a multi-organization Shipit deployment (explicitly supported per `docs/setup.md`/`config/secrets.development.example.yml`, where each org has its own `github.<org>.webhook_secret`), a GitHub organization admin who controls their own org's Shipit-installed GitHub App — and therefore knows/sets that org's `webhook_secret` — can compute a valid `X-Hub-Signature` for an arbitrary payload of the form `{"sha": "<victim_sha>", "state": "success", ...}` and send it to `/webhooks` with `X-Github-Event: status`. `verify_signature` validates it (since the attacker's own org secret matches), but the resulting handler writes a fabricated `success` status onto a commit belonging to a completely different, victim organization's stack, because the SHA lookup is global and unscoped.

`Commit#create_status_from_github!` feeds directly into `Commit#deployable?` and continuous delivery gating: [5](#0-4) [6](#0-5) [7](#0-6) 

`deployable?` treats `success? && !blocked?` as sufficient, and `schedule_continuous_delivery` triggers `ContinuousDeliveryJob` once a commit becomes deployable — meaning a forged status can flip a previously CI-blocked victim commit into an auto-deployable state.

### Impact Explanation
This crosses a genuine authentication-to-target binding: the entity whose secret authenticated the request (their own onboarded org) is disjoint from the repository/stack whose commit-gating state is mutated (a victim org's stack). Concretely, this is an unauthorized write into another organization's deployment-gating state (fabricated CI `success` status), which can unlock/trigger an unauthorized deploy via `schedule_continuous_delivery` for a stack the attacker has no legitimate relationship with. This matches "cross-repository writes" / "an unauthorized deploy" impact criteria.

### Likelihood Explanation
Requires the attacker to control (or know) a `webhook_secret` for at least one organization actually onboarded to the target Shipit instance — i.e., they must be a legitimate org admin of *some* org integrated with that Shipit deployment, but with zero privileges over the *victim* org/repo/stack. This is realistic in any multi-tenant Shipit deployment (explicitly documented as a supported configuration), where trust is meant to be per-organization but the `status` handler enforces no such scoping.

### Recommendation
`StatusHandler` (and any other handler acting on payload fields not tied to `repository.full_name`) must resolve target commits/stacks strictly by joining through the `Repository` derived from `payload.dig('repository','full_name')` (as `Handler#stacks`/`#repository_name` already do for other handlers), and must additionally verify that `repository.full_name`'s owner segment matches the `repository_owner` used to select the verifying `webhook_secret`, rejecting the event otherwise.

### Proof of Concept
1. Attacker organization `A` has a GitHub App installed on the shared Shipit instance with its own `webhook_secret_A` (attacker controls this, e.g. as the GitHub App/org admin).
2. Attacker crafts payload: `{"sha": "<victim_commit_sha_from_org_B>", "state": "success", "repository": {"owner": {"login": "A"}}}` and computes `X-Hub-Signature: sha1=HMAC(webhook_secret_A, raw_body)`.
3. POST to `/webhooks` with `X-Github-Event: status`. `verify_signature` resolves `Shipit.github(organization: "A")` and validates successfully.
4. `StatusHandler#process` executes `Commit.where(sha: victim_sha).each { |c| c.create_status_from_github!(params) }`, writing a `success` status onto org B's commit regardless of org A having no relationship to org B's stack.

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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
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
