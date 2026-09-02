This confirms the pattern: `PushHandler` scopes via `stacks.not_archived.where(branch:)` where `stacks` is `Repository.from_github_repo_name(repository_name)&.stacks` [1](#0-0) [2](#0-1) , and `CheckSuiteHandler` scopes via `stacks.where(branch:)` before touching commits by sha [3](#0-2) . `StatusHandler`, by contrast, queries `Commit.where(sha: params.sha)` globally across the entire `commits` table with no reference to `payload['repository']['full_name']` at all, and its `params` schema doesn't even declare `repository` [4](#0-3) .

### Title
Cross-tenant commit-status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` — ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` writes a `Status` to every `Commit` row in the entire database that shares the SHA in the webhook payload, without ever checking `payload['repository']['full_name']` against the commit's own stack/repository. Any GitHub-originated `status` webhook — legitimately signed by GitHub for a repository the attacker owns or can push to — can therefore mutate the CI status of a commit belonging to a completely different tenant's `Stack`, as long as that other stack happens to contain a commit with the same SHA (e.g. via a fork sharing history, or a repo tracked under two Shipit `Repository`/`Stack` records).

### Finding Description
The broken binding: `commit.stack.repository.full_name == payload['repository']['full_name']` should hold for every `Status` created by a webhook, but `StatusHandler#process` never checks it.

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [5](#0-4) 

This is inconsistent with every other handler that mutates commit/stack state from webhook payloads. `Handler#stacks` resolves `Repository.from_github_repo_name(repository_name)&.stacks`, i.e. the set of stacks belonging to the repository named in the payload [2](#0-1) , and both `PushHandler#process` and `CheckSuiteHandler#process` restrict their commit/branch mutations to `stacks` before doing anything else [1](#0-0) [3](#0-2) . `StatusHandler` never calls `stacks` and its `ExplicitParameters` schema doesn't even declare a `repository` field [6](#0-5) .

`WebhooksController#verify_signature` verifies the HMAC over the whole payload against the webhook secret configured for `Shipit.github(organization: repository_owner)`, where `repository_owner` is read straight out of the attacker-controlled JSON payload (`params.dig('repository', 'owner', 'login')`) [7](#0-6) [8](#0-7) . This check confirms the request was signed for *some* organization Shipit is configured to receive events from — it does not, and cannot, confirm that the SHA referenced in the `status` payload doesn't also exist in a different stack's commit history. A GitHub App/webhook installed at the organization level delivers real, correctly-signed `status` events for *any* repository in that org, including forks. If an attacker forks (or otherwise controls a repository sharing commit history/SHAs with) a tracked repository within that same org, and sets a commit status via the normal GitHub Statuses API on their own repo for a SHA that is also present in the victim stack's `commits` table, GitHub delivers a legitimately signed webhook whose payload references the attacker's own `repository.full_name` — but Shipit's `StatusHandler` ignores that field entirely and applies the status to **every** `Commit` row sharing that SHA, including the victim's.

`Status.replicate_from_github!` further has no way to distinguish or dedupe based on origin — it does a bare `find_or_create_by!` keyed on `stack_id`/state/description/etc, with no reference to which repository/webhook produced it [9](#0-8) , so a forged status persists in `commit.statuses` and drives `deployable?`/blocking-status/CD logic on the victim stack until a differing real GitHub status supersedes it via `refresh_statuses!` (which is correctly scoped: `stack.github_api.statuses(github_repo_name, sha, ...)` per `stack`) [10](#0-9) .

### Impact Explanation
A forged/attacker-influenced `Status` write lands on a commit belonging to a `Stack`/repository the attacker does not control, without ever needing Shipit secrets — this is a payload for one repository mutating another's commit/stack state, matching the Critical impact category. Because commit statuses feed `deployable?`, `blocked?`, and continuous-delivery/merge-request logic (`create_status_from_github!` → `add_status` → CD/merge-request scheduling), a malicious or misleading status (e.g. a fake `success` on a security-relevant check, or a fake `failure` to block deploys) can enable an unauthorized deploy or block a legitimate one on a tenant's stack the attacker doesn't own. The blast radius is every stack whose tracked repository shares commit history (forks, mirrors, or repos migrated/re-added under a new `Repository` record) with any repository the attacker can push to or set statuses on within the same GitHub organization Shipit is configured for.

### Likelihood Explanation
Preconditions: Shipit's GitHub App/webhook must be configured to receive `status` events for the attacker's repository (typically true for org-wide App installations, which is the documented normal setup) [11](#0-10) ; a colliding SHA must exist between attacker-controlled repo and victim stack (straightforward via forking before divergence, or any scenario where the same commit content is tracked under two `Repository`/`Stack` records). No Shipit secret, session, or elevated GitHub permission is required — only ordinary push/fork/status-setting rights on a repository the attacker owns, which matches the stated unprivileged attacker capabilities. The attack is repeatable at will against any SHA the attacker can arrange to share with a victim stack.

### Recommendation
Scope `StatusHandler#process` the same way as `PushHandler`/`CheckSuiteHandler`: require `repository.full_name` in the params schema, resolve `stacks` via `Handler#stacks`, and restrict the commit lookup to `stacks.flat_map(&:commits).where(sha: params.sha)` (or equivalently join through `stack_id`) instead of the global `Commit.where(sha: params.sha)`.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`):
1. Create two stacks/repositories, `victim/repo` (Stack V) and `attacker/fork` (Stack A), each with a `Commit` row sharing the identical `sha` value (simulating shared fork history).
2. Call `Shipit::Webhooks::Handlers::StatusHandler.call(payload_for_attacker_repo_with_shared_sha)` where the payload's `repository.full_name` is `attacker/fork` only.
3. Assert `commit_v.statuses.reload.count` changed (it should NOT, if properly scoped) — currently it *does* change, proving the victim stack's commit received a status derived from a webhook for a repository it doesn't belong to:
```ruby
assert_no_difference -> { commit_victim.statuses.count } do
  StatusHandler.call(status_payload.merge('repository' => { 'full_name' => 'attacker/fork' }))
end
```
This assertion currently fails against the existing implementation, demonstrating the cross-tenant write.

### Citations

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
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

**File:** app/models/shipit/status.rb (L23-34)
```ruby
    class << self
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
    end
```

**File:** app/models/shipit/commit.rb (L156-163)
```ruby
    def refresh_statuses!
      github_statuses = stack.handle_github_redirections do
        stack.github_api.statuses(github_repo_name, sha, per_page: 100)
      end
      github_statuses.each do |status|
        create_status_from_github!(status)
      end
    end
```

**File:** docs/setup.md (L43-49)
```markdown
  - Events:
    - Check run
    - Check suite
    - Membership
    - Pull request
    - Push
    - Status
```
