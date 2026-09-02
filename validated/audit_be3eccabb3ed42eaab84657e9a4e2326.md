### Title
Cross-stack `status` write via unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves the target `Commit` records solely by `sha`, with no scoping to the repository or GitHub App/organization that authenticated the webhook. Because the same physical commit SHA can exist as separate `Commit` rows in multiple `Stack`s (e.g. staging/production stacks tracking the same repository/branch history, or any stack that has imported the same commit), a single authenticated `status` webhook can write a `Status` into every stack sharing that SHA, including one whose `blocking_statuses` gate deploy eligibility via `Commit#blocked?`.

### Finding Description
The broken binding: the code assumes `{ commit updated by StatusHandler } == { commit belonging to the stack/repository that the webhook signature authenticated }`. In reality: [1](#0-0) 

`process` does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — there is no `stack_id`, `stack.repository`, or organization filter at all. Signature verification only picks *which* GitHub App/org secret to check against, based on `repository.owner.login` in the payload: [2](#0-1) 

but the `repository` field is never used again to scope which `Commit` rows get updated — `WebhooksController#create` just calls `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` with the raw parsed JSON, and `StatusHandler` throws away everything except `sha`/`state`/`context`/etc.

Every `Commit` row is `belongs_to :stack` (`app/models/shipit/commit.rb:11`), and `Commit#blocked?` walks `stack.commits.reachable.newer_than(...).older_than(self).any?(&:blocking?)` gated by `stack.blocking_statuses` (`app/models/shipit/commit.rb:231-237`), and `Status#context` is attacker-supplied via `accepts :context, String` in the handler's params schema. So if a `Commit` row with the same `sha` exists in a victim stack that has `blocking_statuses` configured to require `github-actions`, a `status` event that is validly signed for *any* repository/org whose commit history shares that SHA (same repo tracked by two stacks, e.g. staging+production, or a commit that legitimately propagates into multiple stacks before promotion) will create a `Status` row against the victim stack's `Commit` as well, flipping `blocking?`/`blocked?` and therefore `deployable?` (`app/models/shipit/commit.rb:227-229`) and `schedule_continuous_delivery` (`app/models/shipit/commit.rb:281-287`).

None of the existing guards stop this: `verify_signature` only checks that the payload came from *some* recognized GitHub organization/app — it never restricts which `Commit`/`Stack` rows the handler is allowed to mutate. `ExplicitParameters` (the `params do ... end` DSL in `StatusHandler`) only validates parameter *types/shapes*, not repository ownership. There is no `Stack`/`Repository` scoping anywhere in `StatusHandler#process`.

### Impact Explanation
A `status` webhook authenticated for one repository/org can write a `Status` record onto a `Commit` belonging to a different `Stack`, causing that other stack's `blocked?`/`deployable?`/continuous-delivery logic to change based on attacker-controlled `state`/`context` data they did not author for that stack. This is a "payload for one repository mutating another's stack/commit" scenario, matching the Critical impact category (cross-tenant/cross-stack state manipulation), provided a shared-SHA condition exists between the attacker-controlled repo/stack and the victim stack.

### Likelihood Explanation
Exploitability is conditioned on a real precondition: a `Commit` with an identical `sha` value must exist in both the attacker-reachable stack and the victim stack. This is not achievable by an attacker against an arbitrary unrelated repository (SHA-1 preimage/collision is not a realistic option), but it is realistic whenever the *same* GitHub repository is tracked by more than one `Stack` in the same Shipit instance (a common configuration pattern — e.g. separate stacks per environment/branch that share commit history), or whenever commits are shared/cherry-picked across tracked repos with identical SHAs. In those configurations, an attacker who can legitimately trigger a `status` event on the shared commit in one stack's context (e.g. via a GitHub Actions run on their own PR/branch in that shared repository) gets it forwarded, correctly signed, and it silently lands on every stack sharing that commit — no elevated privileges needed beyond what is required to trigger a CI status update in one of the stacks.

### Recommendation
Scope the `Commit` lookup in `StatusHandler#process` to the stack(s)/repository actually identified by the webhook payload (e.g. filter `Commit.joins(:stack).where(sha: params.sha, shipit_stacks: { repository_id: repository_from_payload.id })`), rather than a global `where(sha:)` across the entire `commits` table.

### Proof of Concept
1. Fixtures: create two stacks, `victim_stack` (with `blocking_statuses` requiring `github-actions`) and `attacker_stack`, both pointing at the same underlying repository (or manually insert two `Commit` rows with the identical `sha` value, one under each stack) — this models the shared-SHA precondition.
2. Assert baseline: `assert_equal false, victim_stack.commits.last.blocked?` (or whatever pre-status blocking state applies) given `victim_commit.blocking_statuses` unmet.
3. POST to `/webhooks` with `X-Github-Event: status`, a valid signature for `attacker_stack`'s repository/org, and body `{ sha: shared_sha, state: 'success', context: 'github-actions', repository: { ...attacker repo... } }`.
4. Assert `Status.where(commit_id: victim_commit.id, context: 'github-actions').exists?` is `true` even though the webhook only authenticated for the attacker's repository, and assert `victim_commit.reload.blocked?` / `deployable?` changed as a result — demonstrating the cross-stack write via the unscoped `Commit.where(sha:)` call in `StatusHandler#process`. [3](#0-2) [4](#0-3)

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-28)
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
end
```

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

**File:** app/models/shipit/commit.rb (L231-237)
```ruby
    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
    end
```
