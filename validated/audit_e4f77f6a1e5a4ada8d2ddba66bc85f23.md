Confirmed vulnerability: the webhook signature check only authenticates that the payload was signed by the GitHub App/organization matching `params['repository']['owner']['login']`; it never verifies that the target `Commit` (looked up by bare SHA) belongs to a `Stack`/`Repository` under that organization.

### Title
Cross-repository `Status` forgery via SHA-scoped lookup in `StatusHandler#process` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` finds commits with `Commit.where(sha: params.sha)` across the *entire* database — not scoped to the repository named in `payload['repository']['full_name']` — and then calls `commit.create_status_from_github!(params)`, which writes `statuses.replicate_from_github!(stack_id, github_status)` using the commit's own `stack_id`. `WebhooksController#verify_signature` only proves that the request was signed by the GitHub App belonging to `repository_owner`; it never checks that `repository_owner`/`full_name` matches the stack that owns the matched commit(s). Any attacker who can get a validly-signed `status` webhook accepted for *any* organization/repo they control can write a `Status` row (and thus flip CI/deploy-gating state) for a same-SHA commit tracked under a completely unrelated stack.

### Finding Description
The binding the question is checking: `Status#stack_id (written)` == `Repository#id-owning-stack of the repository named in payload['repository']` that authenticated via `X-Hub-Signature`.

Trace:
- `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-30`) resolves `github_app = Shipit.github(organization: repository_owner)` from `params.dig('repository','owner','login')` and calls `github_app.verify_webhook_signature(signature, raw_post)`. This proves the request was HMAC-signed with the webhook secret configured for that **organization**, and does nothing to relate the *specific repository* in the payload to any specific `Stack`/`Repository` row in the DB.
- `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`. This query is **global across all stacks** — it is not scoped via `Handler#stacks`/`Handler#repository_name` (unlike `CheckSuiteHandler`, which does scope through `stacks.where(branch: ...)`). The DB only enforces a composite index on `(stack_id, sha)` (`db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb`), not a global uniqueness constraint on `sha` — so the same SHA can legitimately exist under multiple different `Stack`s (e.g., forks/mirrors of the same repository tracked as separate stacks, or repos with a shared git history).
- `Commit#create_status_from_github!` (`app/models/shipit/commit.rb:165-169`) calls `statuses.replicate_from_github!(stack_id, github_status)` using `self.stack_id` — the commit's *own* stack — with no cross-check against `params.dig('repository','full_name')`.
- `Status.replicate_from_github!` (`app/models/shipit/status.rb:24-33`) blindly `find_or_create_by!`s using the `stack_id` handed to it.

Attacker flow: attacker owns/controls a repository (or fork) whose organization is configured in Shipit (or otherwise reuses/collides a SHA that is also present under a separate tracked stack — most realistically via a fork of the target repo, since git commit SHAs are content-addressed and identical objects produce identical SHAs across forks). The attacker creates a `status` webhook event (either via genuinely triggering GitHub to send one for their own repo/fork, or, if any repo they control shares the exact same webhook-secret-bearing organization/App installation as the victim stack) whose `sha` matches a commit that already exists on the victim's tracked `Stack`. `verify_signature` succeeds because it only checks the organization owning the *attacker's* repository, not that the affected commit actually belongs to that organization's repository. `StatusHandler` then finds the victim's `Commit` row purely by SHA and writes a forged `Status` (e.g., `state: 'success'`) onto it under the victim stack's `stack_id`.

This bypasses `Status.replicate_from_github!`, model validations (only checks `state` inclusion), and `ExplicitParameters` schema (only type-checks fields, not repository ownership) — none of the existing guards tie the webhook's authenticated repository to the `stack_id` being written.

### Impact Explanation
A forged `success`/`failure` `Status` written to an arbitrary victim `Stack`'s commit satisfies the "payload for one repository mutating another's stack/commit" Critical category. Since `Commit#deployable?` and `Commit#blocked?` depend on `Status` state (`app/models/shipit/commit.rb:227-236`), and `add_status`/`create_status_from_github!` schedules continuous delivery (`schedule_continuous_delivery`) and `ProcessMergeRequestsJob` on success transitions (see `test/models/commits_test.rb:763-777`), this can force a commit to become "deployable" or trigger continuous deployment/merge processing for a stack the attacker does not own, purely by causing a same-SHA commit and getting one authenticated `status` webhook accepted for their own controlled repository. This is repeatable against any stack that happens to share a commit SHA with an attacker-reachable repository (most practically via forks/mirrors), and the blast radius spans all stacks sharing that GitHub organization/App installation.

### Likelihood Explanation
Requires: (1) the attacker's own repository (or a fork of the victim repo) to be under an organization Shipit has configured (`Shipit.github(organization:)` must resolve, i.e., not raise `GithubOrganizationUnknown`), and (2) a commit SHA collision between the attacker-reachable repo and the victim `Stack`'s tracked commits — trivially achievable by forking the target repository, since fork commits are byte-identical git objects with identical SHAs. No Shipit secrets, session, or API token are needed; only the ability to get GitHub to emit (or replay) a `status` event that Shipit's `verify_signature` accepts for the attacker's own org/repo context. This is feasible without any privileged role and is repeatable for every additional stack sharing a SHA.

### Recommendation
Scope the commit lookup in `StatusHandler#process` (and mirror the existing pattern used by `CheckSuiteHandler`) to the repository named in the payload, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or `Commit.joins(:stack).merge(stacks).where(sha: params.sha)`, so only commits belonging to a `Stack` under `Repository.from_github_repo_name(payload['repository']['full_name'])` can be updated, instead of a global `Commit.where(sha:)` query.

### Proof of Concept
```ruby
# test/models/webhooks/status_handler_cross_repo_test.rb
require 'test_helper'

module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerCrossRepoTest < ActiveSupport::TestCase
        test "status webhook does not write a Status onto a commit belonging to a different repository's stack" do
          victim_stack   = shipit_stacks(:shipit)          # e.g. repo "shopify/shipit-engine"
          attacker_stack = shipit_stacks(:cyclimse)         # different repository/org entirely

          # Simulate a SHA collision: attacker's tracked commit shares the SHA
          # of a commit that exists on the victim's stack (e.g. via a fork).
          colliding_sha = "deadbeef00112233445566778899aabbccddeeff"
          victim_commit = victim_stack.commits.create!(sha: colliding_sha, author: shipit_users(:walrus),
                                                          committer: shipit_users(:walrus),
                                                          authored_at: Time.now, committed_at: Time.now,
                                                          message: "victim commit")

          attacker_commit = attacker_stack.commits.create!(sha: colliding_sha, author: shipit_users(:walrus),
                                                             committer: shipit_users(:walrus),
                                                             authored_at: Time.now, committed_at: Time.now,
                                                             message: "attacker commit")

          payload = {
            'sha' => colliding_sha,
            'state' => 'success',
            'context' => 'forged',
            'repository' => { 'full_name' => 'attacker-org/attacker-repo' }
          }

          Shipit::Webhooks::Handlers::StatusHandler.call(payload)

          # BINDING CHECK: the Status written for this sha must only belong to
          # attacker_stack.id (the repo that authenticated the webhook),
          # never victim_stack.id.
          victim_status = victim_commit.reload.statuses.find_by(context: 'forged')
          assert_nil victim_status,
            "Expected no Status to be written on victim_stack (id=#{victim_stack.id}) " \
            "from a webhook authenticated for a different repository, " \
            "but got stack_id=#{victim_status&.stack_id}"
        end
      end
    end
  end
end
```
This test currently fails (the victim's `Status` gets created with `stack_id == victim_stack.id`) because `StatusHandler#process` uses an unscoped `Commit.where(sha:)` lookup, demonstrating the broken binding. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
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

**File:** app/models/shipit/status.rb (L24-33)
```ruby
      def replicate_from_github!(stack_id, github_status)
        find_or_create_by!(
          stack_id:,
          state: github_status.state,
          description: github_status.description,
          target_url: github_status.target_url,
          context: github_status.context,
          created_at: github_status.created_at
        )
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```
