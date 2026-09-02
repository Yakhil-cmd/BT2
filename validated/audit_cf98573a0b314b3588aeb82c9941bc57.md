Confirmed: `PushHandler#process` scopes lookups via `stacks` (repository-derived) at [1](#0-0) , and `CheckSuiteHandler#process` similarly scopes via `stacks.where(branch: ...)` before touching commits at [2](#0-1) . `StatusHandler#process`, by contrast, does a completely unscoped, global lookup by sha with no repository filter at all.

### Title
StatusHandler#process resolves commits by global SHA lookup, ignoring the webhook's verified repository - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` queries `Commit.where(sha: params.sha)` across the entire `commits` table with no scoping to the repository whose org signed the webhook. Any attacker who owns a GitHub repository wired to Shipit (and can therefore produce a validly-signed `status` webhook for their own org) can name an arbitrary SHA — such as the public head SHA of a victim's queued `MergeRequest` in a completely unrelated stack — and drive that victim commit to `success`, triggering `stack.schedule_merges` for the victim stack.

### Finding Description
The broken binding is: the webhook is only proven to originate from `repository_owner` (the org named in `payload['repository']['owner']['login']`), i.e. `verified_org == payload.repository.owner`, per `WebhooksController#verify_signature` at [3](#0-2) . This should imply that any commit/stack mutated by the handler belongs to a repository under that same verified org: `commit.stack.repository.owner == repository_owner`. Instead, `StatusHandler#process` enforces no such constraint:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [4](#0-3) 

This is unlike sibling handlers, which correctly scope to the verified repository via the `stacks` helper (`Repository.from_github_repo_name(repository_name)&.stacks`) defined on the base `Handler` class at [5](#0-4) . `PushHandler` and `CheckSuiteHandler` both filter through `stacks` before acting on commits/branches [1](#0-0) [2](#0-1) . `StatusHandler` never calls `stacks` or filters by `repository_name` at all.

Once a matching `Commit` row is found (an existing commit already tracked in the victim stack because it's the head of a queued `MergeRequest`), `Commit#create_status_from_github!` calls `add_status`, which creates/finds a `Status` for that commit and, if the transition reaches `pending`/`success`, unconditionally calls `stack.schedule_merges` on `commit.stack` — the victim stack — regardless of which org's signature was verified: [6](#0-5) . `Stack#schedule_merges` enqueues `ProcessMergeRequestsJob.perform_later(self)` keyed off `commit.stack`, not off the webhook's payload repository: [7](#0-6) .

Exploit flow: attacker owns (or controls) some GitHub repository/org onboarded to Shipit (only needs their own repo, no privilege on the victim). They observe the public head SHA of a victim `MergeRequest` (any git object is discoverable via the PR itself, which they could even open themselves). They send `POST /webhooks` with `X-Github-Event: status`, `repository.owner.login` = their own org, and body `{"sha": "<victim-pr-head-sha>", "state": "success", ...}`, signed with their own org's legitimate webhook secret. `verify_signature` passes because it only checks that the attacker's own org's secret matches (correctly proving control of the attacker's own repo, but proving nothing about the victim's repo). `StatusHandler#process` then finds the victim's `Commit` row purely by SHA match and applies the attacker-supplied `success` state to it, which is existing project code that then re-evaluates CI checks and can unblock the queued merge.

Existing guards do not catch this: `verify_signature` is scoped correctly to the attacker's own org (that part of the binding holds), but nothing downstream re-checks that the resolved `Commit`'s stack/repository matches `repository_name` from the payload — the gap is entirely inside `StatusHandler#process`.

### Impact Explanation
A payload signed for one repository/organization can flip the CI status — and thereby progress the merge queue — of a commit belonging to a completely different, unrelated repository/stack. This is a cross-tenant integrity violation: "a payload for one repository mutating another's stack, commit ... or an unauthorized merge," which matches the Critical impact category. It is repeatable against any victim stack whose queued `MergeRequest` head SHA the attacker can observe (which is always true, since PR heads are public), as long as the attacker controls webhook signing for at least one repo/org connected to Shipit.

### Likelihood Explanation
Preconditions: the victim stack must have `merge_queue_enabled` and a queued `MergeRequest` blocked only on CI status (`ci_missing`/`ci_failing`), and the attacker needs a Shipit-connected repository/org of their own to legitimately sign a `status` webhook. No Shipit session, API token, GitHub App key, or `webhook_secret` of the victim organization is required — only knowledge of the victim's own org's webhook secret for the attacker's own repo, which they legitimately have. Attacker cost is a single unauthenticated-from-victim's-perspective HTTP POST; fully repeatable, and does not require live GitHub access to test (it's exercised purely on the `Commit.where(sha:)`/`add_status`/`schedule_merges` chain in this engine).

### Recommendation
Scope `StatusHandler#process` to the verified repository, mirroring `PushHandler`/`CheckSuiteHandler`: resolve commits only through `stacks.joins(...).where(sha: params.sha)` (i.e., restrict to `Commit` rows whose `stack_id` is in `stacks` derived from `repository_name`/`repository_owner`), rather than a global `Commit.where(sha: params.sha)`.

### Proof of Concept
```ruby
# test/models/webhooks/handlers/status_handler_test.rb (conceptual)
test "status webhook signed for org A cannot progress org B's stack merge queue" do
  victim_stack = shipit_stacks(:shipit) # belongs to org "shopify"
  victim_commit = shipit_commits(:second) # sha belongs to victim_stack, currently 'failure'/pending
  attacker_repo_full_name = "attacker-org/attacker-repo" # unrelated repo, different org

  payload = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'repository' => { 'full_name' => attacker_repo_full_name, 'owner' => { 'login' => 'attacker-org' } }
  }

  # verify_signature succeeds because it's checked against attacker-org's own secret,
  # not against victim_stack's org.
  Shipit.github(organization: 'attacker-org').stubs(:verify_webhook_signature).returns(true)

  handler = Shipit::Webhooks::Handlers::StatusHandler
  assert_enqueued_with(job: Shipit::ProcessMergeRequestsJob, args: [victim_stack]) do
    handler.call(payload)
  end

  assert_equal 'success', victim_commit.reload.state
  # Assert the binding: commit.stack (victim_stack) must NOT be reachable
  # from a webhook whose verified owner is 'attacker-org' != victim_stack.repository.owner
  refute_equal victim_stack.repository.owner, 'attacker-org'
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

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
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

**File:** app/models/shipit/stack.rb (L231-233)
```ruby
    def schedule_merges
      ProcessMergeRequestsJob.perform_later(self)
    end
```
