### Title
Cross-organization webhook confused deputy: signature verification org is unbound from the repository/commit actually mutated - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to use for HMAC verification based on `repository_owner`, a value read directly out of the untrusted JSON body (`repository.owner.login` or `organization.login`). Nothing enforces that this "authenticating organization" is the same organization/repository that the dispatched handler subsequently reads and mutates. `Shipit::Webhooks::Handlers::StatusHandler`, in particular, never even requires a `repository` field and updates `Commit` rows found purely by `sha`, globally across the whole Shipit instance. This mirrors the Astaria bug class: a value used for one purpose (authorization/trust binding) is disconnected from the value that actually drives the state-changing effect (the entity written), letting an attacker satisfy the "authenticated" side with data of their choosing while writing to a target that was never authenticated.

### Finding Description
`verify_signature` computes `repository_owner` from the attacker-supplied payload and uses it purely to pick the HMAC secret to check the signature against: [1](#0-0) [2](#0-1) 

If verification passes, the entire raw payload is forwarded unchanged to the event handlers: [3](#0-2) 

Shipit supports "Using Multiple Github Applications" where each organization owns its own GitHub App and, critically, its own `webhook_secret`, all configured independently: [4](#0-3) 

The organization that owns a given GitHub App (and therefore knows/controls that app's `webhook_secret`, since they set up their own app's webhook config) is treated by `verify_signature` as fully trusted for whatever payload arrives with that org's name in the `repository_owner` field. However, the field used to select the trust boundary (`repository.owner.login`) is never cross-checked against the field(s) the handler actually acts on.

The clearest exploitable instance is `StatusHandler`, whose params schema requires only `sha` and `state` — no `repository` at all — and which updates commits found by a **global** SHA lookup with no organization/stack scoping: [5](#0-4) 

`Commit#create_status_from_github!` then records the attacker-chosen `state` (e.g. `success`) on that commit, which directly feeds `Commit#deployable?` and `Commit#schedule_continuous_delivery`: [6](#0-5) [7](#0-6) [8](#0-7) 

`Status#after_create` callbacks additionally re-trigger continuous-delivery scheduling and enable CI on the target stack: [9](#0-8) [10](#0-9) 

**Binding broken (equality that should hold but doesn't):**
`organization_that_authenticated(payload.repository.owner.login) == organization_owning(entity_actually_mutated)`

Before the attack: an org admin of "Org A" (which has its own GitHub App / `webhook_secret` registered in Shipit for their own legitimate stacks) only has authority over Org A's repositories/stacks.

After the attack: by POSTing a body where `repository.owner.login` (or `organization.login`) is set to `"orgA"` (so `verify_signature` picks Org A's own known secret and passes) but the actual payload content (`sha`, `state`, etc.) targets a commit belonging to a completely unrelated Org B's stack, the request succeeds and mutates Org B's commit `Status` — something Org A's credentials should never authorize.

### Impact Explanation
This is a cross-organization authorization bypass: an org that legitimately owns (and therefore knows) its own webhook secret can forge state changes on any other organization's stacks/commits registered in the same Shipit instance, without ever possessing that other org's `webhook_secret`. Concretely via `StatusHandler`, an attacker can inject a fabricated `success` CI status for any known commit SHA anywhere in the instance. Since `Commit#deployable?` and `Commit#schedule_continuous_delivery` gate whether a commit is eligible for (continuous) deployment, this can bypass CI-status deploy safety gates and trigger an unauthorized deploy for a stack the attacker's organization has no legitimate access to — matching the "unauthorized deploy" / "escalation into authorization" impact bar. It also constitutes a cross-repository write (rows created under a `stack_id`/`commit_id` belonging to a different organization's repository than the one that authenticated the request).

### Likelihood Explanation
Requires only that: (1) the target Shipit instance uses the multi-GitHub-App configuration (documented, supported feature), and (2) the attacker is an admin/owner of at least one organization/GitHub App already registered in that Shipit instance (a low-privilege position relative to other tenants' stacks — no access to the victim org, no Shipit session, no other org's secret). The attacker only needs to know their own app's webhook secret, which they configured themselves, and craft an arbitrary JSON POST with a matching HMAC signature — well within an unprivileged external attacker's reach in a multi-tenant Shipit deployment.

### Recommendation
Do not let handler-side entity resolution be driven by unauthenticated-relative-to-the-selected-key fields. Concretely:
- Require and validate a `repository` (owner/full_name) field on every webhook payload, including `StatusHandler`, and verify it belongs to the same organization used to select the verification secret.
- Scope `Commit.where(sha: params.sha)` lookups to the resolved `Repository`/`Stack` set for the authenticated organization instead of a global, unscoped query.
- Optionally bind the verified organization into a signed/derived context (not re-read from the same untrusted body) that all downstream handlers must use for scoping their queries.

### Proof of Concept
1. Configure two organizations in `secrets.yml` per the multi-app setup (`orgA`, `orgB`), each with its own `github.<org>.webhook_secret`. `orgB` has a stack tracking commit `deadbeef...` with no passing status yet.
2. As the operator of `orgA`'s own GitHub App (attacker has full knowledge of `orgA`'s `webhook_secret` since they configured it), compute `X-Hub-Signature: sha1=<HMAC-SHA1(orgA_secret, body)>` for the body:
   ```json
   {
     "repository": { "owner": { "login": "orgA" } },
     "sha": "deadbeef...",
     "state": "success",
     "context": "ci/forged"
   }
   ```
3. POST to `/webhooks` with header `X-Github-Event: status` and the above body/signature.
4. `WebhooksController#verify_signature` resolves `repository_owner == "orgA"`, verifies successfully against `orgA`'s secret. `StatusHandler#process` runs `Commit.where(sha: "deadbeef...")` — matching `orgB`'s commit — and calls `create_status_from_github!`, creating a `success` `Status` on `orgB`'s commit, which can immediately flip `deployable?` to true and schedule continuous delivery for `orgB`'s stack, despite the attacker never possessing `orgB`'s webhook secret or any access to `orgB`.

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

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```

**File:** app/models/shipit/status.rb (L36-44)
```ruby
    private

    def enable_ci_on_stack
      commit.stack.enable_ci!
    end

    def schedule_continuous_delivery
      commit.schedule_continuous_delivery
    end
```
