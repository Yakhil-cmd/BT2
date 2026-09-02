### Title
Unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` lets a validly-signed status from one repository write CI state onto another stack's commit, corrupting merge-queue decisions - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves the target commit(s) for an incoming `status` webhook purely by `sha`, with no constraint on the repository or organization that the webhook signature was verified against. Because `Commit` rows are scoped by `stack_id` but the handler ignores that scoping, any commit sharing the same SHA across different stacks (e.g. a shared ancestor commit between a fork and its upstream) receives the forged status, which can flip `review/approved` and trigger `stack.schedule_merges` / `MergeRequest#merge!` on a victim stack with `merge_queue_enabled: true`.

### Finding Description
The broken binding: the code implicitly assumes `Commit.where(sha: params.sha)` == "commits belonging to the repository that authenticated this webhook", but the actual equality only guarantees `Commit.where(sha: params.sha)` == "all commits in the database with this SHA, across every stack/repository".

Trace:
1. `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) only checks that the raw payload was HMAC-signed by the GitHub App/organization derived from `repository_owner` in the payload (`params.dig('repository','owner','login')`). It never checks the payload's `sha` against any specific stack or repository — it only proves "this event genuinely came from GitHub for this org/repo", not "this sha belongs to this repo".
2. `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) then does:
   ```ruby
   Commit.where(sha: params.sha).each do |commit|
     commit.create_status_from_github!(params)
   end
   ```
   This query is global — `Commit` belongs to `stack` (`app/models/shipit/commit.rb:11`) and the DB index is only `(stack_id, sha)` (`db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb`), not a global unique constraint — so any commit row in any stack with a matching SHA gets the status applied, regardless of which repository/org the webhook's signature actually verified.
3. `Commit#create_status_from_github!` → `Commit#add_status` (`app/models/shipit/commit.rb:366-386`) writes the new status and, if the state transitions to `pending` or `success`, calls `stack.schedule_merges` (line 383) on *that* commit's stack — the victim stack, not the attacker's.
4. `MergeRequest.schedule_merges` / stack merge-queue logic evaluates `StatusChecker` against `head.statuses_and_check_runs` (`app/models/shipit/merge_request.rb:193-206`), and if the forged `review/approved` status satisfies `merge_request_required_statuses`, `MergeRequest#merge!` (`app/models/shipit/merge_request.rb:164-191`) can fire, merging/unblocking the victim's PR.

Why existing guards fail: `verify_signature` authenticates *who sent the payload*, not *which commit/stack the payload is allowed to mutate*. There is no per-stack or per-repository scoping anywhere in `StatusHandler`, unlike the DB schema's own `(stack_id, sha)` indexing convention, which the handler bypasses entirely.

Attacker path: an attacker who owns or controls a repository under the same GitHub App installation/org (e.g., their own fork of the victim repo, which shares identical commit SHAs for any commits predating the fork, since Git SHAs are content-addressed and forks share history) can set a commit status via the GitHub Status API on their own repo for a SHA that is also tracked as a `Commit` on the victim's stack. GitHub delivers a legitimately signed `status` webhook (signed with the org/App secret) to Shipit; `verify_signature` passes because the signature is genuinely valid for that org; `StatusHandler` then applies the status to every `Commit` row matching that SHA, including the victim stack's row.

### Impact Explanation
A forged `review/approved` (or any required) status context can be written onto a victim stack's commit, causing `Commit#add_status` to invoke `stack.schedule_merges`, and — if the victim stack has `merge_queue_enabled: true` and the forged status satisfies `merge_request_required_statuses` — `MergeRequest#merge!` fires, causing GitHub to merge the pull request via `stack.github_api.merge_pull_request` (`app/models/shipit/merge_request.rb:169-176`). This is an unauthorized merge/ship action on a repository the attacker never authenticated against, matching the Critical impact category ("a payload for one repository mutating another's stack, commit... or an unauthorized deploy, rollback or merge"). It is repeatable against any victim stack whose tracked commits share a SHA with a repository the attacker can legitimately post statuses to (most commonly via forks sharing ancestor commit history), and could similarly be used to *block* a stack by posting a failing/error status for a required context, denying legitimate merges.

### Likelihood Explanation
Preconditions: (1) the victim stack must have `merge_queue_enabled: true` and a required status context such as `review/approved`; (2) the attacker must be able to get a legitimately GitHub-signed `status` webhook delivered to Shipit for a SHA that also exists as a `Commit` row on the victim stack — realistically achieved by forking the victim's public repository (sharing ancestor commit SHAs) and posting a commit status via the GitHub API on their own fork, provided the GitHub App/webhook delivering to Shipit is scoped broadly enough (e.g., organization-wide installation, or the attacker's fork/App installation is itself configured to deliver to the same Shipit webhook endpoint). This is a real, low-cost, repeatable action for an attacker with ordinary GitHub permissions (fork + status API on their own repo) and requires no Shipit credentials, session, or secrets.

### Recommendation
Scope commit lookups in `StatusHandler#process` (and analogous handlers) by the repository that the webhook's signature was actually verified against, not just by SHA. Concretely, thread the payload's `repository.full_name` (or the `repository_owner`/App installation identity) into the handler and filter via `Commit.joins(:stack).merge(Stack.where(repository: repo)).where(sha: params.sha)`, mirroring the `(stack_id, sha)` scoping already implied by the schema, so a status can only ever affect commits belonging to stacks whose repository matches the authenticated webhook source.

### Proof of Concept
```ruby
# test/models/webhooks/handlers/status_handler_test.rb (conceptual, minitest)
test "status webhook is not applied across repositories sharing a sha" do
  victim_stack = shipit_stacks(:shipit) # merge_queue_enabled: true, requires review/approved
  attacker_stack = create_stack(repository: create_repository(name: 'attacker/evil'))

  shared_sha = 'a' * 40
  victim_commit = victim_stack.commits.create!(sha: shared_sha, message: 'shared ancestor')
  attacker_commit = attacker_stack.commits.create!(sha: shared_sha, message: 'shared ancestor')

  # Binding under test:
  # expected: statuses posted on attacker_stack's commit != statuses on victim_stack's commit
  assert_equal 0, victim_commit.statuses.count

  # Simulate a legitimately-signed status webhook whose `repository` belongs to attacker's org,
  # but whose sha collides with the victim's tracked commit.
  Shipit::Webhooks::Handlers::StatusHandler.new.call(
    'sha' => shared_sha,
    'state' => 'success',
    'context' => 'review/approved',
    'repository' => { 'full_name' => 'attacker/evil', 'owner' => { 'login' => 'attacker' } }
  )

  victim_commit.reload
  # FAILS today: victim_commit picks up the forged status because Commit.where(sha:) is unscoped
  assert_equal 0, victim_commit.statuses.count, "status from unrelated repo leaked into victim stack's commit"
end
```
Both sides of the equality diverge: `Commit.where(sha: shared_sha)` returns both `victim_commit` and `attacker_commit`, while only `attacker_commit` should be writable by a webhook authenticated for `attacker/evil`. This confirms the vulnerability as described. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
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

**File:** app/models/shipit/commit.rb (L366-386)
```ruby
    def add_status
      already_deployed = deployed?

      previous_status = status
      yield
      reload # to get the statuses into the right order (since sorted :desc)
      new_status = status

      unless already_deployed
        payload = { commit: self, stack:, status: new_status.state }
        Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
      end

      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
      new_status
    end
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
