This confirms the vulnerability with concrete evidence. Note the fixtures already demonstrate the pattern: `shipit_commits(:third)` (sha `367578b362bf2b4df5903e1c7960929361c39074`, stack `shipit`) and `shipit_commits(:canaries_third)` (same sha, stack `shipit_canaries`) are two entirely different `Commit` rows in two different stacks sharing an identical `sha`. `StatusHandler#process` does not scope by repository/stack at all - it iterates every DB row with that sha and writes a status onto each, using that row's own `stack_id`.### Title
Cross-repository CI status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler` enables unauthorized merge - (`app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits to attach a status to purely `Commit.where(sha: params.sha)`, with no scoping to the repository/organization that the webhook signature actually authenticated. Any commit row that happens to share a `sha` value across two independent stacks receives the forged status, letting an attacker who controls a webhook-emitting repository B poison the CI state of an unrelated stack A and get its merge queue to merge a PR using stack A's own `GITHUB_TOKEN`.

### Finding Description
The binding that must hold is: `verified_webhook.repository.full_name (B) == commit.stack.repository.full_name (A's stack's repo)`. Tracing the code shows this equality is never checked.

- `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) only verifies the HMAC using `Shipit.github(organization: repository_owner)` — i.e. the webhook secret bound to the **organization** in the payload, not to any specific repository row in Shipit's DB. `repository_owner` is read straight from the attacker-controlled/GitHub-emitted `payload['repository']['owner']['login']` [1](#0-0) .
- `StatusHandler#process` then does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [2](#0-1) 
This query is global across the entire `commits` table and is not filtered by `commit.stack.repository` or by `params['repository']['full_name']` at all.
- `create_status_from_github!` calls `statuses.replicate_from_github!(stack_id, github_status)` where `stack_id` is `commit.stack_id` of the matched row [3](#0-2) [4](#0-3) . So the forged `Status` is correctly persisted with stack A's own `stack_id`, not repo B's.
- `Commit` rows are per-stack (`commits` table has a unique index on `(sha, stack_id)`, not a global unique index on `sha`) [5](#0-4) , so identical SHAs legitimately coexist for independent stacks — the fixtures themselves demonstrate this pattern (`shipit_commits(:third)` and `shipit_commits(:canaries_third)` share sha `367578b3...` across two different stacks) [6](#0-5) [7](#0-6) . Any workflow that produces identical commit content (forks, mirrored/imported history, cherry-picks preserving metadata, shared upstream monorepo mirrors) reproduces this in the wild — the attacker doesn't need a SHA1 collision, only a commit with byte-identical git object content (same tree, parents, author/committer identities and timestamps, message) to a commit that already exists in stack A's table.
- On the consumer side, `MergeRequest#all_status_checks_passed?` calls `StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?` [8](#0-7) , using exactly the `statuses` association poisoned above. Once `all_status_checks_passed?` and `reject_unless_mergeable!` pass, the merge-queue machinery invokes `merge!`, which calls `stack.github_api.merge_pull_request(stack.github_repo_name, ...)` — i.e. stack A's own GitHub App/organization credentials — with no re-verification of which repository actually produced the passing status [9](#0-8) .

None of the documented guards apply here: `verify_signature` validates only organization-level HMAC, not repository identity; `drop_unhandled_event` only filters unknown event types; there is no `ExplicitParameters` check on `repository.full_name` inside `StatusHandler`'s `params do...end` block (it only requires `sha`/`state`, and does not even declare/consume the `repository` key) [10](#0-9) ; `EnvironmentVariables#permit`, `require_permission!`, and `subset`/`url` validators are unrelated to this data path.

### Impact Explanation
An attacker who owns/administers repository B (any repo webhook-enabled in Shipit, even under a different organization if a matching GitHub org secret happens to be configured, or more directly under the **same** organization as stack A if multiple stacks share one org) can cause a real `success` `Status` row to be written against stack A's `Commit`/`MergeRequest` head, without stack A's own CI ever running. This flips `all_status_checks_passed?` to `true` for a pending merge request on stack A, which the merge-queue job will act on and call `merge_pull_request`/`delete_branch` using stack A's `github_api` (its own `GITHUB_TOKEN`-equivalent installation credentials). This is an unauthorized merge triggered by a payload authenticated for one repository mutating another repository's stack/commit/merge-request — matching the Critical category ("a payload for one repository mutating another's stack, commit, task or team, or an unauthorized... merge"). The blast radius scales to every pair of stacks in the installation that can ever share an identical commit SHA (forks, mirrors, monorepo splits, template repos, shared vendored commits, etc.), and is repeatable per PR/commit.

### Likelihood Explanation
Preconditions: (1) the attacker needs legitimate ability to make GitHub emit a real, correctly-signed `status` webhook for a repository B that Shipit has configured (i.e., they own/admin repo B, or have CI/push access sufficient to post a commit status on it — well within the stated unprivileged attacker capabilities, since they "can push to a fork ... and emit webhooks from a repository they own"); (2) a commit with byte-identical content (hence identical SHA) must exist as a row in stack A's `commits` table — realistic in fork-based/mirrored/shared-history setups, which are common in monorepo-adjacent or multi-stack Shipit deployments. No Shipit secrets, sessions, or API tokens are needed; GitHub itself computes and signs the webhook for repo B. This is fully repeatable and requires no interaction from stack A's maintainers.

### Recommendation
In `StatusHandler#process` (and analogously in `CheckSuiteHandler`/`RefreshCheckRunsJob` style handlers), scope the commit lookup by the verified webhook's repository, not merely by SHA: join through `stack.repository.full_name == params.repository.full_name` (or `github_repo_name`) before calling `create_status_from_github!`, e.g. `Commit.joins(:stack => :repository).where(sha: params.sha, shipit_repositories: { name: repo_name, owner: repo_owner })`. Require and validate `repository` in the handler's `params` schema so it can't silently apply a status without a repository context.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`, new):
1. Create `stack_a` bound to `repository_a` (`owner/repo-a`) and `stack_b` bound to `repository_b` (`attacker/repo-b`).
2. Create `Commit` `commit_a` with `sha: SHARED_SHA, stack: stack_a` and `Commit` `commit_b` with `sha: SHARED_SHA, stack: stack_b` (duplicate SHA across two unrelated stacks, mirroring the existing `third`/`canaries_third` fixture pattern).
3. Create `merge_request` on `stack_a` whose `head` is `commit_a`; assert `merge_request.all_status_checks_passed? == false` beforehand (binding side "before": commit_a has no success status from A's own CI).
4. Stub `Shipit.github(organization: 'attacker').verify_webhook_signature` to return `true` (simulating a validly-signed webhook from repo B, no Shipit secret needed by the attacker — GitHub signs it).
5. POST a `status` webhook payload with `sha: SHARED_SHA, state: 'success'` and `repository.full_name: 'attacker/repo-b'` to `/webhooks`.
6. Assert `commit_a.statuses.reload.last.stack_id == stack_a.id` and `merge_request.reload.all_status_checks_passed? == true` — proving the equality `repo B (verified) == repo A (owns stack)` was broken.
7. Assert that `stack_a.github_api.expects(:merge_pull_request).with(stack_a.github_repo_name, merge_request.number, ...)` is invoked when the merge-queue processes `merge_request`, using `stack_a`'s credentials, despite no status ever originating from `repository_a`'s CI.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-61)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
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

**File:** db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb (L1-5)
```ruby
class IndexCommitsOnStackIdAndSha < ActiveRecord::Migration[5.1]
  def change
    add_index :commits, %i(sha stack_id), unique: true
  end
end
```

**File:** test/fixtures/shipit/commits.yml (L29-41)
```yaml
third:
  id: 3
  sha: 367578b362bf2b4df5903e1c7960929361c39074
  message: "fix it!"
  stack: shipit
  author: walrus
  committer: walrus
  authored_at: <%= 6.days.ago.to_formatted_s(:db) %>
  committed_at: <%= 5.days.ago.to_formatted_s(:db) %>
  additions: 12
  deletions: 64
  updated_at: <%= 8.days.ago.to_formatted_s(:db) %>
  created_at: <%= 1.day.ago.to_formatted_s(:db) %>
```

**File:** test/fixtures/shipit/commits.yml (L219-231)
```yaml
canaries_third:
  id: 303
  sha: 367578b362bf2b4df5903e1c7960929361c39074
  message: "fix it!"
  stack: shipit_canaries
  author: walrus
  committer: walrus
  authored_at: <%= 6.days.ago.to_formatted_s(:db) %>
  committed_at: <%= 5.days.ago.to_formatted_s(:db) %>
  additions: 12
  deletions: 64
  updated_at: <%= 8.days.ago.to_formatted_s(:db) %>
  created_at: <%= 1.day.ago.to_formatted_s(:db) %>
```

**File:** app/models/shipit/merge_request.rb (L164-191)
```ruby
    def merge!
      raise InvalidTransition unless pending?

      raise NotReady if not_mergeable_yet?

      stack.github_api.merge_pull_request(
        stack.github_repo_name,
        number,
        merge_message,
        sha: head.sha,
        commit_message: 'Merged by Shipit',
        merge_method: stack.merge_method
      )
      begin
        if stack.github_api.pull_requests(stack.github_repo_name, base: branch).empty?
          stack.github_api.delete_branch(stack.github_repo_name, branch)
        end
      rescue Octokit::UnprocessableEntity
        # branch was already deleted somehow
      end
      complete!
      true
    rescue Octokit::MethodNotAllowed # merge conflict
      reject!('merge_conflict')
      false
    rescue Octokit::Conflict # shas didn't match, PR was updated.
      raise NotReady
    end
```

**File:** app/models/shipit/merge_request.rb (L193-197)
```ruby
    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end
```
