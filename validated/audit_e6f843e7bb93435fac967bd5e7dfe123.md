### Title
`StatusHandler` writes commit statuses without scoping to the repository whose signature was verified, enabling cross-repository status forgery - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
The `status` webhook is authenticated in `WebhooksController#verify_signature` against the organization/repository derived from the payload's `repository.owner.login`, but the handler that actually applies the payload — `Shipit::Webhooks::Handlers::StatusHandler` — never checks that the commit(s) it mutates belong to that same, verified repository. It looks up commits **globally by SHA** across every stack/repository tracked by the Shipit instance.

### Finding Description
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to use for HMAC verification based on `repository_owner`, itself parsed from the same payload: [1](#0-0) [2](#0-1) 

This proves only that the payload was signed by *some* organization's registered webhook secret (i.e. by a GitHub App/organization that Shipit trusts for that `repository.owner.login`). It does not, and cannot by itself, guarantee that the commit SHAs referenced inside the body belong to that same repository.

The `status` event is dispatched to `StatusHandler`, whose `process` method resolves commits with a bare, unscoped `Commit.where(sha: params.sha)` — with no `repository`/`stack` constraint at all, unlike every other handler in the codebase (`PushHandler`, `CheckSuiteHandler`, all `PullRequest::*` handlers), which use the shared `Handler#stacks`/`#repository_name` helpers scoped by `payload.dig('repository', 'full_name')`: [3](#0-2) [4](#0-3) 

Compare with `PushHandler` and `CheckSuiteHandler`, which both scope their queries through `stacks` (repository-bound): [5](#0-4) [6](#0-5) 

Because `Commit` SHAs are only unique per stack (not globally), and `StatusHandler` never enforces `repository == verified_repository`, an unrelated repository's `status` webhook can create/update a `Status` record for a commit that lives in a completely different, unrelated stack — as long as the two repositories happen to share (or the attacker can predict/reuse) a commit SHA, e.g. via a merge/cherry-pick/rebase producing an identical SHA, or by pushing the exact same commit object to two different repos they don't fully control (a common scenario for shared base commits, vendored branches, or repos mirrored/forked across orgs tracked by the same Shipit instance).

This breaks the binding: **verified repository (organization whose webhook_secret authenticated the request) ≠ repository of the `Commit` actually written**.

Root cause: `app/models/shipit/webhooks/handlers/status_handler.rb:21` (`Commit.where(sha: params.sha)`), combined with `app/controllers/shipit/webhooks_controller.rb:24-31` and `:59-62` binding signature verification only to `repository.owner.login`.

### Impact Explanation
`Commit#status`/`Commit#deployable?` and `Stack#deployable?`/`#next_commit_to_deploy` gate automated and manual deploys directly on the aggregated `Status` records of a commit: [7](#0-6) [8](#0-7) 

An attacker who controls (or has push/CI access to) any single repository whose organization is configured in Shipit can trigger a `status` webhook (through their own CI or a crafted push) that references a commit SHA shared with a victim repository/stack, and mark it `success` for a required CI context. This can flip `deployable?` to true on the victim stack and trigger an unauthorized deploy (including via continuous delivery, `trigger_continuous_delivery`), satisfying the accepted "unauthorized deploy" Critical impact criteria.

### Likelihood Explanation
This requires the attacker to control a repository already registered in the same Shipit instance (which is the normal threat model these `Handler`s are built to defend against — cross-repository isolation) and to obtain a shared commit SHA with the victim repository, which is realistic in monorepo-splits, forks, vendoring, or shared submodule scenarios. No token, session, or GitHub App credential is required beyond the ability to make GitHub deliver (or a raw HTTP POST replicate) a validly-signed `status` payload for the attacker's own configured organization/repository.

### Recommendation
Scope `StatusHandler#process` the same way as `PushHandler`/`CheckSuiteHandler`: require `repository.full_name` in the handler's params and restrict the `Commit` lookup to `stacks` derived from `Repository.from_github_repo_name(params.repository.full_name)`, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` (or a joined query filtering by `stack: { repository_id: repository.id }`), instead of the current global `Commit.where(sha: params.sha)`.

### Proof of Concept
1. Attacker has push/CI access to `attacker-org/repoA`, which is tracked as a stack in the shared Shipit instance and has a valid, Shipit-configured `webhook_secret` for `attacker-org`.
2. Victim stack `victim-org/repoB` has an undeployed commit with SHA `deadbeef...` awaiting a required CI check `ci/tests` to reach `success` in order to be `deployable?`.
3. Attacker crafts/triggers (e.g. via their own CI reporting a commit status, or replaying a legitimately-signed webhook body from their own repo) a GitHub `status` event, correctly signed with `attacker-org`'s `webhook_secret`, whose JSON body contains `"sha": "deadbeef...", "state": "success", "context": "ci/tests"`, and `repository.owner.login == "attacker-org"` (so `verify_signature` passes for the attacker's own org).
4. `WebhooksController#create` dispatches to `StatusHandler`, which executes `Commit.where(sha: params.sha)` — this matches the victim commit in `victim-org/repoB` regardless of the fact the signature was only ever verified for `attacker-org`.
5. `commit.create_status_from_github!(params)` creates a `success` status on the victim's commit, potentially unblocking `Stack#deployable?` in `victim-org/repoB` for continuous delivery / manual deploy — an unauthorized deploy trigger the attacker never had permission to influence.

### Citations

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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/stack.rb (L376-378)
```ruby
    def deployable?
      !locked? && !active_task? && !awaiting_provision? && deployment_checks_passed?
    end
```
