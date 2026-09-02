### Title
`StatusHandler#process` mutates `Commit` records without verifying repository/stack ownership - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` looks up commits by raw SHA alone (`Commit.where(sha: params.sha)`) and never scopes the query to the stack(s) owned by `params.repository.full_name`, unlike every other handler in the same module. Any GitHub "status" webhook that passes signature verification for *some* onboarded organization can therefore write an attacker-controlled `Status` (state, description, target_url, context) onto a commit belonging to an unrelated stack, as long as that commit's SHA also exists in a repository the attacker controls (trivially true for a fork, since forks share commit SHAs with their upstream).

### Finding Description
The broken binding is: the set of stacks derivable from the webhook payload's `repository.full_name` via `Handler#stacks` (`Repository.from_github_repo_name(repository_name)&.stacks || Stack.none`) should equal the set of `Commit` rows mutated by the handler. It does not.

- `Handler#stacks` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`) is the standard, repository-scoped access pattern used by every sibling handler:
 - `PushHandler#process` restricts to `stacks.not_archived.where(branch:)` [1](#0-0) 
 - `CheckSuiteHandler#process` restricts to `stacks.where(branch:)` and then `stack.commits.where(sha:)` (still stack-scoped) [2](#0-1) 
 - All `PullRequest::*Handler`s resolve `repository = Repository.from_github_repo_name(...)` and operate only on `repository.review_stacks` [3](#0-2) 

- `StatusHandler#process`, by contrast, ignores `stacks`/`repository_name` entirely and queries the global `Commit` table by SHA only: [4](#0-3) , then calls `commit.create_status_from_github!(params)` for every match, which persists a `Status` row via `Status.replicate_from_github!` [5](#0-4) [6](#0-5) .

- `WebhooksController#verify_signature` only proves the request came from a real GitHub delivery for the organization named in `params.dig('repository','owner','login')` — it never checks that this organization/repository actually owns the target commit: [7](#0-6) .

**Exploit flow:** attacker forks (or otherwise controls a repository sharing commit history with) a repository tracked by Shipit, inside an org that is legitimately onboarded (has a real `webhook_secret`/GitHub App installation covering that repo). The attacker sets a commit status on a SHA that is also a real, tracked commit of the victim stack (identical SHA because of shared git history via fork). GitHub computes a correctly signed webhook using the org's real `webhook_secret` and delivers it to Shipit — `verify_signature` legitimately succeeds because it is a genuine GitHub delivery, not a forged signature. `StatusHandler#process` then finds the victim's `Commit` row purely by SHA (with no repository check) and writes the attacker's status onto it.

Existing guards do not stop this: `ExplicitParameters` only validates types/presence of `sha`/`state`/etc., not repository ownership; `verify_signature` authenticates the *sender org*, not the *target commit's owner*; and no model validation ties a `Status` write to the `repository.full_name` in the payload.

### Impact Explanation
A successful `Status` write on a victim commit can flip `commit.state`/`deployable?` (`success? && !blocked?`) and triggers `schedule_continuous_delivery`/`ProcessMergeRequestsJob` via `Status#after_commit` callbacks [8](#0-7)  and `Commit#create_status_from_github!` add_status flow. On a stack with continuous deployment enabled, this can trigger an unauthorized deploy of a victim's stack — matching the Critical category "a payload for one repository mutating another's stack, commit, task" and "an unauthorized deploy." The blast radius spans every stack/repository whose commit history happens to share a SHA with an attacker-controlled repository (most straightforwardly, any fork of a tracked repo), i.e., cross-tenant, database-wide.

### Likelihood Explanation
Requires the attacker to control a repository (e.g., a fork) whose commit SHAs overlap with a tracked victim commit, and for that repository to be covered by a real, already-configured GitHub App/webhook installation that Shipit trusts (an "onboarded" org). No secret material, session, or privileged Shipit role is needed — GitHub itself computes the valid signature for the attacker's own repo/webhook delivery. Forking a public repository and using GitHub's Status API on it is a zero-privilege action available to any GitHub user. This is repeatable against any tracked commit whose SHA is reachable via a controllable fork.

### Recommendation
Scope `StatusHandler#process` to the stacks derived from `payload['repository']['full_name']` (analogous to `PushHandler`/`CheckSuiteHandler`), e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or `stacks.joins(:commits).where(commits: { sha: params.sha })`, instead of an unscoped `Commit.where(sha:)`.

### Proof of Concept
Minitest plan (controller-level, mirrors existing `test/controllers/webhooks_controller_test.rb` patterns):
```ruby
test ":state from an unrelated/unknown repository must not mutate a victim stack's commit" do
  request.headers['X-Github-Event'] = 'status'
  victim_commit = shipit_commits(:first)

  Shipit::Repository.stubs(:from_github_repo_name).with('attacker/evil').returns(nil)

  body = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'context' => 'attacker/forged',
    'repository' => { 'full_name' => 'attacker/evil', 'owner' => { 'login' => 'shopify' } }
  }.to_json

  # Binding under test:
  # LHS: Handler#stacks for 'attacker/evil' => Stack.none (empty)
  # RHS: commits actually mutated by StatusHandler#process for this sha
  assert_no_difference -> { victim_commit.reload; victim_commit.statuses.count } do
    post :create, body:, as: :json
  end
  # Currently FAILS: victim_commit.statuses.count increases by 1 despite
  # Repository.from_github_repo_name('attacker/evil') == nil / Stack.none,
  # proving StatusHandler ignores repository identity entirely.
end
```

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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```

**File:** app/models/shipit/status.rb (L23-33)
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
