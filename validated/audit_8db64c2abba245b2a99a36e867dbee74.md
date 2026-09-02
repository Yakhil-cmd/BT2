### Title
Cross-tenant commit-status mutation via unscoped `Commit.where(sha: ...)` in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits to update purely `Commit.where(sha: params.sha)` [1](#0-0)  without ever consulting the webhook's `repository.full_name`, even though the params schema for this handler doesn't require `repository` at all [2](#0-1) . Since `Commit.sha` is only unique per-`stack` (`[sha, stack_id]` unique index), not globally, [3](#0-2)  a legitimately signed status event for repository A's commit can mutate a Commit row belonging to an entirely different tracked repository/stack B, if both stacks happen to contain a `Commit` record for the same sha (trivially true for forks sharing upstream git history).

### Finding Description
The broken binding: StatusHandler assumes **sha == unique repository-scoped identifier** (one sha maps to exactly one repository's commit), while the actual DB invariant is **sha is unique only per `stack_id`** — confirmed by `t.index ["sha", "stack_id"], unique: true` in the schema [4](#0-3)  and by `Commit` model, which `belongs_to :stack` with no cross-stack uniqueness constraint on `sha` alone [5](#0-4) .

Every other webhook handler that touches commits/stacks correctly scopes its query through `Handler#stacks`, which is derived from `Repository.from_github_repo_name(repository_name)` where `repository_name` comes from `payload.dig('repository', 'full_name')`:
- `PushHandler#process` uses `stacks.not_archived.where(branch:)` [6](#0-5) 
- `CheckSuiteHandler#process` uses `stacks.where(branch: ...)` before touching commits [7](#0-6) 
- The base `Handler#stacks` helper is exactly what performs this repository scoping [8](#0-7) 

`StatusHandler` is the outlier: it never calls `stacks`, never requires `repository` in its `params` block, and queries `Commit` unscoped by any repository/stack filter [9](#0-8) .

`WebhooksController#verify_signature` only authenticates that the payload was signed by GitHub for the organization named in `repository.owner.login` [10](#0-9) . This proves the request genuinely came from GitHub for *some* repository under that org, but it does nothing to constrain which `Commit` rows `StatusHandler#process` is allowed to touch — the handler itself discards the repository context entirely.

Exploit flow: a Shipit instance tracks two separate `Repository`/`Stack` pairs whose git histories intersect (e.g., an internal fork and the upstream project, or two related forks under the same GitHub App installation/org — a common real-world topology). Both stacks import overlapping ancestor commits into their own `commits` table (same `sha`, different `stack_id`, allowed by the per-stack-unique index). A legitimate, properly-signed `status` webhook for repository A, referencing a shared historical `sha`, is processed by `Commit.where(sha: params.sha)`, which returns Commit rows from **both** stack A and stack B, and `create_status_from_github!` is invoked on all of them — mutating status data for a repository/stack that never authenticated or was even named in this webhook payload.

### Impact Explanation
Any tracked repository whose commit history overlaps with another tracked repository/stack in the same Shipit deployment can have its `Status` records (used to gate deploy readiness/CI-required-status checks) fabricated or altered by activity happening on the *other* repository. Because required/blocking statuses drive whether a stack is considered deployable, this can flip perceived CI status across tenant boundaries, matching the "payload for one repository mutating another's stack, commit... " Critical impact category. The blast radius spans every stack in the instance that shares any historical commit sha with the reporting repository — repeatable on every subsequent legitimate status delivery for a shared sha.

### Likelihood Explanation
Requires two Shipit-tracked stacks whose `commits` tables contain rows for a common `sha` — a very common precondition given how often organizations track both an upstream and an internal fork, or multiple related forks, under one Shipit instance and one GitHub App/webhook signing key. No signature forgery, no privileged Shipit access, and no crafted payload are needed — an ordinary, correctly-signed status event triggers the mismatch automatically once the precondition holds. This makes it highly likely wherever this common OSS/fork topology exists.

### Recommendation
Scope `StatusHandler#process` the same way as `PushHandler`/`CheckSuiteHandler`: require `repository.full_name` in the params schema, resolve the reporting `Repository`, and restrict the commit lookup to `stacks.commits` (or `Repository.from_github_repo_name(params.repository.full_name)&.stacks&.commits`) instead of the global `Commit.where(sha: ...)`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb (conceptual)
test "status for a shared sha does not mutate commits in unrelated stacks" do
  repo_a = shipit_repositories(:shipit) # e.g. owner/app
  stack_a = repo_a.stacks.first
  repo_b = Shipit::Repository.create!(owner: 'attacker', name: 'app-fork')
  stack_b = Shipit::Stack.create!(repository: repo_b, environment: 'production')

  shared_sha = 'a' * 40
  commit_a = stack_a.commits.create!(sha: shared_sha, author: shipit_users(:walrus),
                                      committer: shipit_users(:walrus), authored_at: Time.now,
                                      committed_at: Time.now, message: 'shared ancestor')
  commit_b = stack_b.commits.create!(sha: shared_sha, author: shipit_users(:walrus),
                                      committer: shipit_users(:walrus), authored_at: Time.now,
                                      committed_at: Time.now, message: 'shared ancestor')

  payload = {
    'sha' => shared_sha, 'state' => 'success',
    'repository' => { 'full_name' => repo_a.github_repo_name, 'owner' => { 'login' => repo_a.owner } }
  }

  # binding under test:
  # BEFORE: Commit.sha uniqueness is per stack_id (commit_a.stack_id != commit_b.stack_id)
  # StatusHandler assumes sha alone identifies a single repository's commit
  assert_difference -> { commit_a.reload.statuses.count }, 1 do
    assert_difference -> { commit_b.reload.statuses.count }, 1 do
      Shipit::Webhooks::Handlers::StatusHandler.call(payload)
    end
  end
  # AFTER: both commit_a (intended target) AND commit_b (unrelated repo/tenant)
  # received the status mutation, proving the cross-tenant write.
end
```

### Citations

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

**File:** db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb (L1-5)
```ruby
class IndexCommitsOnStackIdAndSha < ActiveRecord::Migration[5.1]
  def change
    add_index :commits, %i(sha stack_id), unique: true
  end
end
```

**File:** test/dummy/db/schema.rb (L79-86)
```ruby
    t.string "sha", limit: 40, null: false
    t.integer "stack_id", limit: 4, null: false
    t.datetime "updated_at"
    t.index ["author_id"], name: "index_commits_on_author_id"
    t.index ["committer_id"], name: "index_commits_on_committer_id"
    t.index ["created_at"], name: "index_commits_on_created_at"
    t.index ["sha", "stack_id"], name: "index_commits_on_sha_and_stack_id", unique: true
    t.index ["stack_id"], name: "index_commits_on_stack_id"
```

**File:** app/models/shipit/commit.rb (L11-11)
```ruby
    belongs_to :stack
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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
