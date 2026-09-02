This confirms the pattern: `PushHandler` and `CheckSuiteHandler` both scope through `stacks` (derived from `repository_name` = `payload.dig('repository', 'full_name')`) before touching any `Commit`/`Status` record. `StatusHandler`, however, resolves target commits purely by SHA with no repository scoping: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` in [1](#0-0) , and `create_status_from_github!` writes using `self.stack_id`, the found commit's own foreign key, not anything derived from the webhook payload's repository [2](#0-1) .

### Title
Cross-tenant `Status` write via repository-unscoped SHA lookup in status webhook - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` looks up `Commit` records by `sha` alone, with no constraint tying the lookup to the repository named in the webhook payload. Because `verify_signature` only proves the requester controls the org named in `payload['repository']['owner']['login']`, an attacker who owns a repository can produce a commit with byte-identical content (thus identical SHA-1) to a commit already tracked under a victim's stack, then send a signed `status` webhook from their own repo to have a `Status` row written against the victim's `stack_id`.

### Finding Description
The security invariant that should hold is: `Status.stack_id` written by a status webhook == the stack owned by the organization identified in `payload['repository']['owner']['login']`, whose `webhook_secret` was used in `verify_webhook_signature`. In `WebhooksController#verify_signature`, `github_app = Shipit.github(organization: repository_owner)` and `repository_owner` is read straight from the untrusted payload [3](#0-2) [4](#0-3) . This only proves the attacker controls that org's secret for their own claimed repository — it says nothing about which `Commit`/`Stack` should be touched.

`StatusHandler#process` never uses `repository_name`/`stacks` (the scoping helpers defined on `Handler`, and used correctly by `PushHandler` and `CheckSuiteHandler`) to constrain which commits are affected [5](#0-4) . Instead it does a bare, global lookup:
```
Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }
``` [1](#0-0) 

`Commit#create_status_from_github!` then calls `statuses.replicate_from_github!(stack_id, github_status)`, using the found commit's own `stack_id`, i.e., whichever stack that SHA happens to belong to in the database — completely independent of which org's webhook_secret verified the inbound request [2](#0-1) , and `Status.replicate_from_github!` writes `stack_id` directly into the row [6](#0-5) .

Exploit flow: (1) attacker registers/owns a GitHub organization/repo with a valid Shipit webhook (so `verify_signature` will pass for their own org). (2) Attacker crafts a git commit object with tree/parent/author/committer/message/timestamps byte-identical to a public commit already tracked by a victim stack (git commit SHA-1s are content-addressed, so duplicating known public commit metadata trivially reproduces the same SHA — no cryptographic collision needed). (3) Attacker POSTs a `status` event to `/webhooks` with `repository.full_name`/`owner.login` set to their own repo/org and `sha` set to the duplicated SHA, signed with their own `webhook_secret`. (4) `verify_signature` passes because it validates against the attacker's own org. (5) `StatusHandler` finds the victim's pre-existing `Commit` row (matching `sha` globally) and writes a `Status` under the victim's `stack_id`.

None of the existing guards prevent this: `verify_signature` only authenticates the claimed org, not the affected records; `drop_unhandled_event` and the `ExplicitParameters` schema only validate shape, not tenancy; `stacks`/`repository_name` scoping exists on the base `Handler` class but is simply not used by `StatusHandler`.

### Impact Explanation
An attacker who owns any repository with a Shipit-configured webhook can inject arbitrary CI `Status` rows (`state`, `description`, `target_url`, `context`, `created_at`) into any victim stack whose tracked commit SHA the attacker can reproduce. Since `Status` state influences `Commit#state`/`deployable_status` and can trigger `ProcessMergeRequestsJob`/`schedule_continuous_delivery` (per `test/models/commits_test.rb` transitions around `create_status_from_github!`), a forged "success" status can push a commit toward deployability without the victim's CI or org authorizing it — this is a payload for one repository mutating another stack's/commit's data, matching the Critical category ("payload for one repository mutating another's stack, commit, task or team").

### Likelihood Explanation
Preconditions: attacker needs any Shipit-connected GitHub org/repo (to obtain a valid signature) and needs to reproduce a target commit's exact SHA. Because git commit SHAs are deterministic content hashes and commit metadata is often public (tree, parent, author, committer, message, timestamps are visible via `git log`/GitHub API), reproducing an identical commit object in another repository is straightforward (not a hash-collision attack, just content duplication) — this is repeatable against any publicly-known commit SHA tracked by any Shipit stack, at low cost to the attacker.

### Recommendation
In `StatusHandler#process`, scope the commit lookup through the payload's own repository, mirroring `PushHandler`/`CheckSuiteHandler`: e.g. `stacks.find_each { |stack| stack.commits.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) } }`, so a status webhook can only affect commits/stacks belonging to the repository named (and authenticated) in that same request.

### Proof of Concept
minitest (model/controller level, no live GitHub):
```ruby
test "status webhook from a different repo cannot write Status to a victim stack via SHA collision" do
  attacker_stack = shipit_stacks(:cyclimse) # different repository than @stack
  victim_commit = shipit_commits(:first)    # belongs to @stack (different repo/org)
  duplicated_sha = victim_commit.sha

  request.headers['X-Github-Event'] = 'status'
  GithubHook.any_instance.stubs(:verify_signature).returns(true)

  body = {
    'sha' => duplicated_sha,
    'state' => 'success',
    'context' => 'attacker/injected',
    'repository' => { 'full_name' => attacker_stack.github_repo_name, 'owner' => { 'login' => attacker_stack.repository.owner } }
  }.to_json

  assert_difference -> { victim_commit.statuses.count }, 0 do
    post :create, body:, as: :json
  end
  # Currently FAILS: Status.last.stack_id == @stack.id (victim's stack),
  # even though the request was authenticated as attacker_stack's organization.
end
```
Assertion on both sides of the binding: expected `Status.last.stack_id == attacker_stack.id` (or no row created at all, since attacker's org has no such SHA), actual (pre-fix) `Status.last.stack_id == @stack.id` — the victim's stack — proving the broken binding.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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
