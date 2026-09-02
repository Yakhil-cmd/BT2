This is a real, confirmed vulnerability. The `Handler` base class already provides a `stacks` helper that scopes to `Repository.from_github_repo_name(repository_name)&.stacks`, and `PushHandler` and `CheckSuiteHandler` correctly use it to restrict effects to the authenticating repository's own stacks. `StatusHandler`, however, does not use `stacks` at all — it queries `Commit.where(sha: params.sha)` globally, across every stack in the database, ignoring `payload.dig('repository', 'full_name')` entirely.

### Title
Cross-repository status forgery via unscoped `Commit.where(sha:)` in `StatusHandler` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits by bare `sha` with no repository/stack scoping, unlike `PushHandler`/`CheckSuiteHandler` which use the `stacks` helper (`Repository.from_github_repo_name(repository_name)&.stacks`). Any commit SHA that coincidentally or genuinely exists in more than one stack's `commits` table (e.g. shared history between a fork and its upstream, or multiple stacks/environments tracking overlapping history) will have its status/CI state mutated for **every** stack containing that SHA, not just the repository whose webhook signature authenticated the request.

### Finding Description
The broken binding: the code assumes `sha` is a repository-unique identifier, i.e. it implicitly treats `{sha authenticated by repository_owner's signature} == {sha column value in Commit table}` as sufficient to authorize a write, when the actual invariant that must hold is `commit.stack.repository.full_name == payload.dig('repository', 'full_name')`.

Trace:
- `WebhooksController#verify_signature` only proves the raw POST body was HMAC-signed with the webhook secret for `repository_owner` (`params.dig('repository', 'owner', 'login')`), per [1](#0-0) . It does not verify that the `repository.full_name`/`sha` combination genuinely belongs together beyond what GitHub itself signed for that org's app installation.
- `Shipit::Webhooks.for_event('status')` dispatches to `StatusHandler` [2](#0-1) .
- `StatusHandler#process` does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` with no repository filter [3](#0-2) .
- Contrast with `PushHandler#process`, which correctly scopes via `stacks.not_archived.where(branch:)`, where `stacks` is defined in the base `Handler` as `Repository.from_github_repo_name(repository_name)&.stacks` [4](#0-3) [5](#0-4) . `CheckSuiteHandler` similarly scopes via `stacks.where(branch: ...)` [6](#0-5) . `StatusHandler` is the outlier that never calls `stacks`.
- `Commit` has a unique index on `(sha, stack_id)`, not on `sha` alone [7](#0-6) , confirming the schema itself expects the same SHA to legitimately exist under multiple stacks (e.g. multiple environments/stacks tracking the same repository, or forks/mirrors sharing history) — yet `StatusHandler` doesn't respect stack boundaries when applying the write.
- Once a matching `Commit` is found in an unrelated stack, `create_status_from_github!` → `add_status` recomputes `commit.state`/`deployable?`/`blocked?` on that foreign stack [8](#0-7) [9](#0-8) , which can flip `deployable?` to `false` (blocking a legitimate deploy) or, if `state` transitions to `success`, trigger `ProcessMergeRequestsJob` (as demonstrated in existing tests) [10](#0-9) .

Why existing guards don't catch this: `verify_signature` authenticates the org/app that sent the webhook, not that the `sha` inside the payload belongs to that org's repository; `ExplicitParameters` in `StatusHandler` only validates types (`sha: String`, `state: String`), not repository ownership [11](#0-10) ; there is no `Repository.from_github_repo_name` check anywhere in the handler.

### Impact Explanation
A `status` webhook whose SHA collides with a commit in an unrelated (or related-but-different-owner) stack causes that foreign stack's `Commit#state`/`deployable?`/`blocked?` to change, and can enqueue `ProcessMergeRequestsJob` or affect deploy blocking on that stack — a write to a repository/stack that did not authenticate the request. Where the affected stack is a production environment, this can flip `deployable?` from true to false (denial of a legitimate deploy) or, on a `success`-directed transition, unblock a deploy/merge that CI hadn't actually approved. This matches "a payload for one repository mutating another's stack, commit ... or an unauthorized deploy, rollback or merge" (Critical), constrained specifically to cases where the attacker can produce/control a commit sharing a SHA with the victim's tracked history (e.g., shared upstream/fork history, or multiple stacks tracking the same GitHub repository under different environments) — it is not a general SHA-1 preimage attack against arbitrary unrelated content.

### Likelihood Explanation
Preconditions: (1) the attacker's own repository, or a repository whose webhook the attacker can trigger genuinely through GitHub (their own fork/org with a Shipit-integrated GitHub App), must produce a `status` event whose `sha` also exists as a `Commit` row for the victim's stack — realistic when stacks/forks share git history (e.g. multiple environment-stacks on the same underlying GitHub repository, or forks that haven't diverged past the shared commit). (2) The attacker still needs a validly signed webhook for the org resolved from `repository.owner.login` in their payload — they cannot forge an arbitrary payload for an org whose `webhook_secret` they don't hold. This substantially reduces attacker freedom compared to the idealized "attacker sends any SHA" framing, but the core code defect (missing repository scoping in `StatusHandler`, unlike its sibling handlers) is real and directly inconsistent with the codebase's own established pattern.

### Recommendation
Scope `StatusHandler#process` the same way as `PushHandler`/`CheckSuiteHandler`: restrict the `Commit` lookup to `stacks` derived from `Repository.from_github_repo_name(payload.dig('repository','full_name'))`, e.g. `Commit.where(sha: params.sha, stack: stacks).each { |commit| commit.create_status_from_github!(params) }`, so a status can only ever affect commits belonging to the repository that authenticated the webhook.

### Proof of Concept
minitest plan (`test/models/webhooks/handlers/status_handler_test.rb`):
```ruby
test "status for a SHA shared across two different stacks/repos only updates the authenticating repository's stack" do
  victim_stack = shipit_stacks(:shipit) # e.g. repository "shopify/shipit-engine"
  attacker_stack = shipit_stacks(:cyclimse) # different repository, e.g. "cyclimse/shipit-engine"

  shared_sha = "deadbeef" * 5
  victim_commit = victim_stack.commits.create!(sha: shared_sha, ...)
  attacker_commit = attacker_stack.commits.create!(sha: shared_sha, ...)

  before_victim_state = victim_commit.reload.state          # e.g. "pending"

  payload = {
    "sha" => shared_sha,
    "state" => "failure",
    "context" => "shipit/checks",
    "repository" => { "full_name" => attacker_stack.repository.full_name, "owner" => { "login" => attacker_stack.repository.owner } }
  }

  Shipit::Webhooks::Handlers::StatusHandler.call(payload)

  # Assert the binding: only the authenticating repo's commit should change
  assert_equal "failure", attacker_commit.reload.state   # expected, legitimate
  assert_equal before_victim_state, victim_commit.reload.state # currently FAILS: victim_commit.state becomes "failure" too
end
```
This test currently fails because `StatusHandler` mutates `victim_commit` despite the webhook only authenticating `attacker_stack`'s repository, proving the missing scoping.

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

**File:** app/models/shipit/webhooks.rb (L19-19)
```ruby
          'status' => [Handlers::StatusHandler],
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L7-18)
```ruby
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
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb (L1-5)
```ruby
class IndexCommitsOnStackIdAndSha < ActiveRecord::Migration[5.1]
  def change
    add_index :commits, %i(sha stack_id), unique: true
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

**File:** app/models/shipit/commit.rb (L227-237)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end

    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
    end
```

**File:** test/models/commits_test.rb (L763-777)
```ruby
    test "#add_status schedule a MergeMergeRequests job if the commit transition to `pending` or `success`" do
      commit = shipit_commits(:second)
      github_status = OpenStruct.new(
        state: 'success',
        description: 'Cool',
        context: 'metrics/coveralls',
        created_at: 1.day.ago.to_formatted_s(:db)
      )

      assert_equal 'failure', commit.state
      assert_enqueued_with(job: ProcessMergeRequestsJob, args: [@commit.stack]) do
        commit.create_status_from_github!(github_status)
        assert_equal 'success', commit.state
      end
    end
```
