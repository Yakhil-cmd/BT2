This confirms the divergence: `PushHandler#process` and `CheckSuiteHandler#process` both scope their queries through `stacks` (which resolves `Repository.from_github_repo_name(repository_name)` where `repository_name = payload.dig('repository', 'full_name')`) [1](#0-0) , but `StatusHandler#process` does not use `stacks` at all — it queries `Commit.where(sha: params.sha)` globally across every stack in the database [2](#0-1) .

### Title
Cross-repository sha-collision triggers `deployable_status`/`commit_status` `Hook.emit` on a victim stack via `StatusHandler#process` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits by `sha` alone across the entire `commits` table, ignoring the `repository.full_name` in the authenticated payload, then calls `commit.create_status_from_github!` which fires `Hook.emit(:commit_status, ...)` and `Hook.emit(:deployable_status, ...)` scoped to `commit.stack` [3](#0-2) . Any attacker who controls a GitHub organization/repo that Shipit trusts (i.e., has a valid `GithubApp`/webhook secret configured for their own org) can send a legitimately-signed `status` webhook naming an arbitrary commit SHA, and if that SHA happens to also exist as a commit belonging to an unrelated victim stack, the victim stack's status/hooks fire.

### Finding Description
The broken binding: `payload.dig('repository', 'full_name')` (the repo the webhook is authenticated for) should equal the `full_name` of the `Repository` backing every `Stack` whose `Hook`s get triggered by this request, but it does not for the `status` event.

Trace:
1. `WebhooksController#verify_signature` verifies the signature using `Shipit.github(organization: repository_owner)`, where `repository_owner` is read directly from the JSON payload's `repository.owner.login` [4](#0-3) [5](#0-4) . This only proves the request was signed with the secret belonging to whatever organization is named in the payload — it says nothing about which *stacks* should be affected, and an attacker who legitimately owns/administers a GitHub org/repo with Shipit's app installed can produce a validly-signed payload for any `sha` value they choose (SHAs are attacker-controlled strings in JSON, not verified against the named repo's actual git history).
2. `Shipit::Webhooks.for_event('status')` dispatches to `StatusHandler`, whose `process` method does:
   ```ruby
   Commit.where(sha: params.sha).each do |commit|
     commit.create_status_from_github!(params)
   end
   ``` [2](#0-1) 
   This is a global, unscoped `Commit` lookup — unlike `PushHandler` and `CheckSuiteHandler`, which both restrict to `stacks` derived from the payload's `repository.full_name` via `Handler#stacks`/`Handler#repository_name` [6](#0-5) [7](#0-6) [1](#0-0) , `StatusHandler` has no such scoping.
3. `commit.create_status_from_github!` calls `add_status`, creating a `Status` row for `commit.stack_id` (the victim stack) and, if the state transition qualifies, emits `Hook.emit(:commit_status, stack, ...)` and `Hook.emit(:deployable_status, stack, ...)` against the victim `stack`'s configured outbound hooks [8](#0-7) [3](#0-2) .

Exploit flow: attacker registers/owns a GitHub org+repo for which they can configure (or already have) a Shipit `GithubApp`/webhook secret recognized by the target Shipit instance (any org onboarded in `Shipit.github_teams`/app config, not necessarily the victim's). They send a `status` event payload with `repository.full_name` = their own repo, but `sha` equal to a real commit SHA that also exists in the victim's `commits` table (this can happen via a genuine sha collision, a forked/duplicated commit history, or — more practically — any commit whose SHA the attacker can discover, e.g. from a public victim repo, since `git` commit SHAs are content hashes and are not secret; two repositories can easily share an identical commit if one is a fork of, or has cherry-picked/rebased content from, the other). Because `StatusHandler` never checks that the commit's stack corresponds to the authenticated `repository.full_name`, the victim's `Status` record and `Hook.emit` fire.

### Impact Explanation
The impact is a payload authenticated for one repository mutating another stack's data and triggering outbound webhook notifications for a repository that never authenticated the request — this matches the "Critical" category ("a payload for one repository mutating another's stack, commit, task or team"). Concretely: a bogus `Status` row is written against the victim's commit/stack [9](#0-8) , `commit.state`/`deployable?` can flip, `ProcessMergeRequestsJob`/`ContinuousDeliveryJob` can be scheduled (`add_status` calls `stack.schedule_merges` and `Commit#schedule_continuous_delivery`), and the victim's external Slack/webhook integrations receive spoofed status data (target_url/description supplied entirely by the attacker) [10](#0-9) . This is repeatable against any stack whose commits share a SHA that the attacker can supply, and is not limited to a single victim — any stack containing a commit with a guessable/known SHA is exposed.

### Likelihood Explanation
Preconditions: the attacker must control a GitHub org/repo already trusted by this Shipit instance's `Shipit.github(organization:)` configuration (i.e., some org has the app installed / webhook secret configured) — this does not need to be the victim org. The attacker must also know or guess a SHA that exists in the victim's `commits` table; this is feasible whenever the victim's repository is public (SHAs are visible), the victim stack tracks a fork/mirror of a public codebase, or via common shared base commits between forks. Given the low cost (a single unauthenticated-content but validly-signed HTTP POST) and full repeatability, likelihood is moderate-to-high wherever multiple stacks in the same Shipit instance can plausibly share commit SHAs (e.g., forks, mirrors, monorepo splits).

### Recommendation
Scope `StatusHandler#process` to the payload's repository the same way `PushHandler` and `CheckSuiteHandler` do: resolve `stacks` via `Handler#repository_name`/`Repository.from_github_repo_name`, and restrict the `Commit` lookup to `stacks.flat_map(&:commits)` (or a joined scope) matching `params.sha`, e.g. `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`, instead of the current unscoped `Commit.where(sha: params.sha)`.

### Proof of Concept
minitest plan (in `test/controllers/webhooks_controller_test.rb`-style, using existing fixtures):
```ruby
test ":status webhook for repo A fires hooks on stack B's commit sharing the same sha" do
  request.headers['X-Github-Event'] = 'status'
  victim_commit = shipit_commits(:first) # belongs to shipit_stacks(:shipit)
  attacker_repository_payload = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'context' => 'ci/travis',
    'branches' => [{ 'name' => 'master' }],
    'repository' => { 'full_name' => 'attacker/unrelated-repo', 'owner' => { 'login' => 'attacker-org' } }
  }.to_json

  Shipit.github(organization: 'attacker-org').stubs(:verify_webhook_signature).returns(true)

  Hook.expects(:emit).with(:deployable_status, victim_commit.stack, has_entries(commit: victim_commit)).at_least_once

  post :create, body: attacker_repository_payload, as: :json
end
```
Assert both sides of the binding before/after: before the fix, `payload['repository']['full_name']` (`attacker/unrelated-repo`) != `victim_commit.stack.repository.full_name` (`shipit/shipit`), yet `Hook.emit` fires for `victim_commit.stack`. After applying the fix (scoping via `stacks`), the same request should result in no `Status` created and no `Hook.emit` call, since `attacker/unrelated-repo` resolves to no `Repository`/`Stack` in `stacks`.

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/commit.rb (L366-384)
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
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
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
