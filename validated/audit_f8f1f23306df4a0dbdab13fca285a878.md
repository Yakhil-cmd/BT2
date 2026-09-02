### Title
Webhook signature verification is bound to `repository.owner.login`, while every event handler acts on `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` authenticates an inbound webhook against the GitHub App/org identified by `repository_owner`, parsed from the `repository.owner.login` field of the JSON body (falling back to `organization.login`). Once that check passes, `WebhooksController#create` dispatches the *entire raw payload* to every registered handler, and every handler (`Shipit::Webhooks::Handlers::Handler#stacks`, `StatusHandler`, `PushHandler`, all `PullRequest::*Handler`s, `ReviewStackAdapter`) resolves the target `Repository`/`Stack` from a completely different field: `repository.full_name`.

### Finding Description
The equality the code assumes but never enforces is:

`repository.owner.login` (used to select the webhook secret / GitHub App for HMAC verification) == owner segment of `repository.full_name` (used to look up the `Repository`/`Stack` that the event is applied to).

Signature check: [1](#0-0) [2](#0-1) 

Handler dispatch on the raw, already-parsed JSON: [3](#0-2) 

Resolution of the affected repository from an unrelated field of the same payload: [4](#0-3) [5](#0-4) 

This is analogous to the Sablier bug class: the code path that establishes trust (`unchecked` streamed-amount math / here, HMAC verification keyed on `repository.owner.login`) is disjoint from the code path that performs the state-changing action (`withdraw()` acting on `withdrawn` / here, handlers acting on `repository.full_name`). Because Shipit explicitly supports multiple GitHub organizations each with its own `webhook_secret` (see `Shipit.github_app_config`, `docs/setup.md` "Using Multiple Github Applications"), an attacker who legitimately controls (or has compromised) a repository in **OrgA** — and therefore can produce a validly-HMAC-signed delivery using OrgA's `webhook_secret` — can freely set `repository.full_name` to `"OrgB/target-repo"` while keeping `repository.owner.login` = `OrgA`. `verify_signature` will validate the signature against OrgA's secret and succeed; the handler will then look up and mutate **OrgB's** `Repository`/`Stack`/`Commit` records via `Repository.from_github_repo_name(params.repository.full_name)`: [6](#0-5) 

The most impactful instance is `StatusHandler`, which creates a `Status` record for any commit matching an attacker-supplied `sha`, with attacker-controlled `state`/`description`/`context`, without any repository binding at all (it looks up by `sha` alone, across the whole install): [7](#0-6) 

Forged `success` statuses feed directly into deployability and continuous-deployment gating: [8](#0-7) [9](#0-8) [10](#0-9) 

### Impact Explanation
An attacker who controls the webhook secret for *any one* organization configured in this Shipit instance (a normal, low-privilege capability for a legitimate customer/team of that org) can forge webhook deliveries whose `repository.owner.login` matches their own org (satisfying HMAC verification) but whose payload content (`repository.full_name`, or in the `status` event, just a raw `sha` with no repository scoping at all) targets a completely different, unrelated organization's stacks. This lets the attacker inject fabricated CI/commit statuses (`state: success`) for arbitrary commit SHAs across the whole Shipit install, which `Commit#schedule_continuous_delivery` and `Stack#deployable?` use to gate/trigger continuous deployment — i.e., it can cause an **unauthorized deploy** to be triggered for a repository the attacker has no legitimate access to. This satisfies the High-severity criterion "escalation ... or an unauthorized deploy."

### Likelihood Explanation
Likelihood is moderate-to-high in any deployment using the documented multi-organization webhook configuration (`docs/setup.md`, `config/secrets.development.shopify.yml`), which Shipit explicitly supports as a first-class feature. Any user capable of pushing to / triggering a webhook delivery from one onboarded org (not a privileged Shipit account) can attempt this; the `status` handler in particular requires no cross-field spoofing at all since it never checks `repository` against the matched `Commit`'s stack.

### Recommendation
Bind the entity used for signature verification to the entity acted upon: after verifying the HMAC using the org determined from `repository_owner`, re-derive and cross-check that the `Repository`/`Stack` resolved via `repository.full_name` (or via the matched `Commit`'s `stack.repository`) belongs to that same, already-authenticated organization before performing any write. For `StatusHandler` specifically, filter `Commit.where(sha: params.sha)` to commits whose `stack.repo_owner` equals the authenticated `repository_owner`, rather than trusting `full_name`/`sha` in isolation.

### Proof of Concept
1. Shipit is configured with two orgs, `OrgA` and `OrgB`, each with its own `webhook_secret` (per `docs/setup.md` multi-org config), both having stacks configured.
2. Attacker has legitimate delivery capability for `OrgA` (e.g., is able to trigger/replay a webhook for a repo in `OrgA`, computing a valid HMAC with `OrgA`'s `webhook_secret`).
3. Attacker sends a `status` event to `POST /webhooks` with header `X-Github-Event: status`, HMAC-signed with `OrgA`'s `webhook_secret`, and body:
```json
{
  "sha": "<sha of a real undeployed commit belonging to OrgB's stack>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgA/irrelevant-repo" }
}
```
4. `verify_signature` computes `repository_owner = "OrgA"`, fetches `Shipit.github(organization: "OrgA")`, and validates successfully against the attacker's known secret.
5. `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb`) matches `Commit.where(sha: params.sha)` — with no repository ownership check — and calls `commit.create_status_from_github!(params)`, creating a `success` `Status` on OrgB's commit.
6. If OrgB's stack has `continuous_deployment: true`, `Status#schedule_continuous_delivery` → `Commit#schedule_continuous_delivery` → `ContinuousDeliveryJob` will evaluate `stack.deployable?` and can trigger an unauthorized deploy of OrgB's stack, purely as a consequence of a signature that was only ever checked against OrgA's secret.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L6-24)
```ruby
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** app/models/shipit/stack.rb (L376-378)
```ruby
    def deployable?
      !locked? && !active_task? && !awaiting_provision? && deployment_checks_passed?
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
