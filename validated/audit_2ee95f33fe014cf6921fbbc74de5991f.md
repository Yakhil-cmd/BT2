### Title
`StatusHandler` writes CI status to any commit matching a SHA without verifying the payload's `repository` belongs to the organization whose webhook secret signed the request - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects the GitHub App/webhook secret to verify against based on `repository_owner` (the organization named in the payload) [1](#0-0) [2](#0-1) , but `Shipit::Webhooks::Handlers::StatusHandler#process` never checks that field, instead updating status on *every* `Commit` row across the entire installation whose `sha` matches the payload, regardless of which repository/stack owns it [3](#0-2) .

### Finding Description
Every other push/pull_request handler scopes its effect through `Handler#stacks`, which resolves `Repository.from_github_repo_name(payload.dig('repository','full_name'))` before touching any record [4](#0-3) , e.g. `PushHandler` and `CheckSuiteHandler` both filter through `stacks` [5](#0-4) [6](#0-5) .

`StatusHandler`'s `params` block only requires `sha` and `state` and never requires or reads `repository` [7](#0-6) , and its `process` method queries `Commit.where(sha: params.sha)` globally: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [8](#0-7) .

Meanwhile `WebhooksController#verify_signature` picks the GitHub App/secret to verify the HMAC using `repository_owner`, which is read straight from the same untrusted JSON payload (`params.dig('repository','owner','login')`), and only enforces that the signature is valid *for that named organization* — it never cross-checks that the commit being updated actually belongs to a stack under that organization [9](#0-8) [2](#0-1) .

This breaks the binding: **organization that authenticated (whose `webhook_secret` verified the request) == repository/stack that gets written**. Because git commit SHAs are content-addressed, any repository that shares history with a victim repository (a fork, a mirror, or a repo seeded with identical commits) will contain identical SHAs for the shared history. An attacker who controls a GitHub App/organization installed on such a repository (their own fork) can trigger a legitimately-signed `status` webhook (signed with *their own* organization's `webhook_secret`) naming a `sha` that also exists in a victim's Stack, and `StatusHandler` will apply the status to the victim's `Commit` record with no ownership check at all.

### Impact Explanation
`Commit#create_status_from_github!` → `add_status` recomputes `Commit#status`, which feeds `deployable?` (`!locked? && (stack.ignore_ci? || (success? && !blocked?))`) [10](#0-9)  and, on the create path, `Commit#schedule_continuous_delivery` will enqueue `ContinuousDeliveryJob` once `deployable? && stack.continuous_deployment? && stack.deployable?` are all true [11](#0-10) . An attacker forging a `success` status for a shared SHA can flip a victim stack's commit from failing/pending CI to "success," satisfying `ci.require`/blocking-status checks and causing an **unauthorized deploy** via continuous delivery, or unblocking a manual deploy that a legitimate user would otherwise be prevented from triggering. This matches the "unauthorized deploy" bucket under the High-impact criteria.

### Likelihood Explanation
Requires the attacker to control a GitHub organization/App installation that Shipit trusts (i.e., configured in `Shipit.github` with its own `webhook_secret`) and to control or fork a repository that shares commit history (and therefore SHAs) with a targeted stack's repository — a realistic scenario for open-source projects mirrored/forked across orgs, or multi-org monorepo setups sharing history. No compromise of the victim org's webhook secret, GitHub token, or Shipit session is needed; the attacker only needs the (unprivileged, self-controlled) organization's own valid signature, which is by design obtainable without any authorization from the victim.

### Recommendation
`StatusHandler` (and any other global-by-SHA handler) must scope commit lookup by the repository named in the payload, mirroring `Handler#stacks`, e.g. `stacks.joins(:commits).where(shipit_commits: { sha: params.sha })` or equivalently restrict to `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`, so a webhook signed by organization A can never mutate commit/status state belonging to a stack owned by a different repository/organization.

### Proof of Concept
1. Attacker forks (or otherwise obtains identical early history to) the victim's repository under their own GitHub organization, "attacker-org," which the attacker has separately registered as a Shipit GitHub App with its own `webhook_secret`.
2. Because the fork shares commit history, an old commit SHA `abc123...` exists both in the victim's Shipit-tracked stack and in the attacker's fork.
3. Attacker sends a `status` webhook to `/webhooks` with `X-Github-Event: status`, a valid `X-Hub-Signature` computed with attacker-org's own `webhook_secret`, and body `{"sha": "abc123...", "state": "success", "context": "ci/attacker", "repository": {"owner": {"login": "attacker-org"}, "full_name": "attacker-org/forked-repo"}}`.
4. `WebhooksController#verify_signature` resolves `Shipit.github(organization: "attacker-org")` and successfully verifies the signature (it is a legitimately signed request for that org) [1](#0-0) .
5. `StatusHandler#process` executes `Commit.where(sha: "abc123...")`, which returns the victim's `Commit` row (belonging to `victim-org/repo`'s Stack), and calls `create_status_from_github!`, writing a "success" status onto the victim's commit [8](#0-7) .
6. If this flips the commit's aggregate `state` to `success` and the victim stack has `continuous_deployment` enabled, `schedule_continuous_delivery` enqueues a deploy of that commit without any authorization from the victim organization [11](#0-10) .

Note: I could not find any additional cross-check (e.g., in `Status.replicate_from_github!` or `add_status`) that verifies repository ownership before this point, based on the available indexed files; a full runtime trace/exploit was not executed since this is a static code review.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
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
