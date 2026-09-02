### Title
Cross-repository forged CI status via `StatusHandler`, unbound from the org that authenticated the webhook - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`Shipit::Webhooks::Handlers::StatusHandler` writes a GitHub commit-status to **any** `Commit` in the entire Shipit instance that matches the payload's `sha`, without ever checking that the `sha` belongs to the repository/organization whose signature was verified. This breaks the binding between "the organization whose webhook_secret authenticated the request" and "the repository/stack that gets written to."

### Finding Description
`WebhooksController#verify_signature` selects the `GitHubApp`/secret used to validate `X-Hub-Signature` based on `repository_owner`, taken from `params.dig('repository', 'owner', 'login')`: [1](#0-0) 

That is the only binding enforced before dispatch: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` passes the *entire* raw JSON body to every handler: [2](#0-1) 

`StatusHandler`, however, never consults `repository` at all when deciding what to mutate — it looks up commits globally by `sha`: [3](#0-2) 

Compare this with the base `Handler` class, which *does* provide a `repository_name`/`stacks` helper scoped to `payload.dig('repository', 'full_name')`, used by `PushHandler` and `CheckSuiteHandler`: [4](#0-3) [5](#0-4) [6](#0-5) 

`StatusHandler` does not use this scoping mechanism at all, so the equality that should hold —
`organization that authenticated (repository.owner.login used to pick the webhook_secret)` == `repository that owns the commit being written`
— is never enforced. The field used for authentication (`repository.owner.login`) and the field that actually determines the write target (`sha`, matched with no repository filter) are completely disjoint.

Shipit explicitly supports multi-tenant deployments where multiple GitHub organizations share one Shipit instance, each with its own `webhook_secret` (`docs/setup.md`, "Using Multiple Github Applications"). A tenant/org that legitimately controls its own GitHub App/webhook_secret for its own tracked repository can therefore produce a validly-signed `status` webhook payload (signed with its own secret) whose `sha` field references a commit belonging to a completely different tenant's stack, and have Shipit apply a forged CI status to it via `Commit#create_status_from_github!`: [7](#0-6) 

### Impact Explanation
Writing a forged `Status` is not cosmetic: `Status#after_create` calls `enable_ci_on_stack` and `schedule_continuous_delivery`: [8](#0-7) 

and transitioning a commit to `success`/`pending` schedules `ProcessMergeRequestsJob` and, for stacks with `continuous_deployment` enabled, `ContinuousDeliveryJob`, which will deploy the commit once "CI" appears green and the stack is unoccupied: [9](#0-8) 

This lets an authenticated-but-unrelated tenant (org A) forge a passing CI status for a commit belonging to a different tenant's stack (org B), potentially triggering an unauthorized merge/deploy of that commit despite real CI never having passed — a cross-repository write with deploy/merge consequences, matching the Critical "cross-repository writes / unauthorized deploy" impact bucket.

### Likelihood Explanation
Any tenant configured on a shared multi-org Shipit instance already possesses a valid `webhook_secret` for their own org (by design — they configured their own GitHub App). No privileged access to the victim org, no `GITHUB_TOKEN`, and no repository write access on the victim repo are required; only knowledge of a target `sha` (frequently public/guessable from public repos or Shipit's own commit history/timeline pages) is needed. The webhook endpoint (`WebhooksController`) is fully unauthenticated aside from the per-organization HMAC check, so this is reachable by any tenant onboarded to the shared instance, satisfying the "unprivileged attacker breaking a deployment-trust binding" criterion.

### Recommendation
`StatusHandler#process` should scope the `Commit` lookup to `stacks` (i.e., repositories belonging to the organization that authenticated, via `repository_name`/`stacks` like `PushHandler`/`CheckSuiteHandler`), e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or equivalently `Commit.where(sha: params.sha, stack: Repository.from_github_repo_name(repository_name)&.stacks || Stack.none)`, ensuring the authenticated repository/organization matches the commit's owning stack before writing any status.

### Proof of Concept
1. Shipit is configured with two GitHub orgs, `org-a` and `org-b`, each with a distinct `webhook_secret` (per "Using Multiple Github Applications").
2. Org A's admin (an authenticated, but otherwise unprivileged w.r.t. org B, tenant) knows their own `webhook_secret_a`.
3. Attacker obtains the `sha` of a commit tracked by an `org-b` stack (e.g. via `org-b`'s public GitHub commit history or Shipit's own public commit/timeline views).
4. Attacker POSTs to `/webhooks` with header `X-Github-Event: status`, body:
```json
{
  "sha": "<org-b-commit-sha>",
  "state": "success",
  "description": "forged",
  "context": "ci/forged",
  "repository": { "owner": { "login": "org-a" } }
}
```
   signed with `HMAC-SHA1(webhook_secret_a, body)` in `X-Hub-Signature`.
5. `WebhooksController#verify_signature` resolves `Shipit.github(organization: 'org-a')` and successfully verifies the signature against `webhook_secret_a`.
6. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, finds the `org-b` commit (no repository check), and calls `create_status_from_github!`, creating a fabricated `success` status on org B's commit — potentially triggering `ProcessMergeRequestsJob`/`ContinuousDeliveryJob` for org B's stack.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/status.rb (L18-20)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

```

**File:** app/jobs/shipit/continuous_delivery_job.rb (L10-21)
```ruby
    def perform(stack)
      return unless stack.continuous_deployment?

      # If there is a schedule defined for this stack, make sure we are within a
      # deployment window before proceeding.
      return if stack.continuous_delivery_schedule && !stack.continuous_delivery_schedule.can_deploy?

      # checks if there are any tasks running, including concurrent tasks
      return if stack.occupied?

      stack.trigger_continuous_delivery
    end
```
