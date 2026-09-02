### Title
Cross-repository commit-status forgery via SHA-only matching in `StatusHandler#process` bypasses merge-queue CI gating - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves the target `Commit` for an incoming GitHub `status` webhook using only `Commit.where(sha: params.sha)`, with no check that the webhook's originating repository matches the repository/stack that owns the matched commit. Because the `commits` table is indexed as `(stack_id, sha)` — not a global unique index on `sha` — the schema itself anticipates the same SHA existing in multiple stacks (forks/mirrors), and a validly-signed webhook from an attacker-controlled repository sharing a commit object with a victim repository will write a status onto the victim's `MergeRequest#head` commit, letting `MergeRequest#all_status_checks_passed?` return true and letting `ProcessMergeRequestsJob` merge that PR out of its intended CI-gated order.

### Finding Description
The intended binding is: `status.commit.stack.repository.full_name == webhook.payload.dig('repository','full_name')` — i.e., a status should only ever be recorded against a commit that belongs to the stack whose repository actually emitted the webhook.

The code never enforces this. The flow is:

1. `WebhooksController#verify_signature` validates the HMAC signature using the secret for `Shipit.github(organization: repository_owner)`, where `repository_owner` is read straight from the attacker-supplied `payload['repository']['owner']['login']`. [1](#0-0) 
This only proves the request came from *some* organization Shipit trusts (which can be the attacker's own org/repo that Shipit already tracks as an unrelated stack) — it proves nothing about which commit the payload's `sha` is allowed to touch.

2. `StatusHandler#process` looks up commits purely by SHA, with no scoping to the repository that signed the request: [2](#0-1) 

3. `Commit#create_status_from_github!` writes the status using the *matched commit's own* `stack_id`: [3](#0-2) 

4. The schema confirms SHAs are not globally unique — the composite index is `(stack_id, sha)`, meaning the same commit object is expected to legitimately exist across multiple stacks (e.g., mirrors/forks tracked as separate Shipit stacks): [4](#0-3) 

5. `MergeRequest#all_status_checks_passed?` evaluates readiness purely from `head.statuses_and_check_runs`, with no origin check: [5](#0-4) 

6. `ProcessMergeRequestsJob#perform` iterates `to_be_merged` (oldest `merge_requested_at` first) and merges the first PR whose `all_status_checks_passed?` returns true: [6](#0-5) 

**Exploit flow:** An attacker who controls (or forks) a repository that Shipit already tracks as *some* stack pushes/creates a commit whose SHA is identical to the victim PR's head commit — trivially achievable by forking the victim's public repository (fork objects are byte-identical git objects, so the SHA of the shared ancestor/head commit is literally the same) — then sets a `success` GitHub status on that SHA in their own repository via the GitHub API (which they legitimately control) with a `context` matching the victim stack's required CI check name (obtainable from the victim's public `.shipit.yml`). GitHub delivers a validly-signed `status` webhook to Shipit for the attacker's repository. `verify_signature` passes because it validates against the attacker's own org's secret. `StatusHandler#process` then matches `Commit.where(sha: ...)`, which includes the victim's `Commit` row (same SHA, different `stack_id`), and writes a `Status` under the victim's `stack_id`. The next `ProcessMergeRequestsJob` run (triggered by `Status#schedule_continuous_delivery` after_commit) sees `all_status_checks_passed?` true for that PR and merges it — regardless of its real, unrelated CI state, and out of the legitimate merge-queue order.

None of the existing guards prevent this: `verify_signature` checks org-secret matching but is keyed off attacker-controlled `repository_owner` field, not the commit's actual stack; the `StatusHandler` params schema (`requires :sha`, etc.) validates types only, not repository binding; there is no `require_permission!` or stack-scoped lookup anywhere in this path.

### Impact Explanation
An attacker who legitimately controls one Shipit-tracked repository can inject a forged, always-"success" CI status onto a *different, victim* stack's pull request, causing `Shipit::ProcessMergeRequestsJob` to merge that PR — an unauthorized merge that bypasses real CI gating and jumps the queue ahead of legitimately-ready PRs. This is a payload from one repository mutating another repository's stack state and triggering an unauthorized merge, matching the Critical category explicitly listed in scope ("a payload for one repository mutating another's stack... or an unauthorized deploy, rollback or merge"). The attack is repeatable against any victim stack whose repository shares a git object (via fork ancestry, mirrored history, or a colliding commit) with any repository the attacker controls, and is not limited to one PR — it can be repeated for every commit SHA the attacker's repo shares with the target.

### Likelihood Explanation
Preconditions: the victim stack must have `merge_queue_enabled?` with `allows_merges?` true, the attacker must control (own or fork) a separate GitHub repository already tracked as a Shipit stack (or one Shipit's GitHub App is installed on), and the shared commit SHA must actually exist in both repos' object graphs (trivial via forking a public repo, since fork history shares identical commit objects with the upstream by construction). No Shipit secrets, sessions, or maintainer privileges are required — only ordinary GitHub push/API access to a repository the attacker owns. This is a low-cost, fully repeatable attack against any multi-tenant Shipit deployment tracking more than one repository that share commit history (very common with forks and mirrors).

### Recommendation
In `Shipit::Webhooks::Handlers::StatusHandler#process`, scope the commit lookup by the webhook's own repository, not by SHA alone — e.g., resolve the `Stack`(s) whose `repository.full_name` matches `params.dig('repository','full_name')` (or `repository_owner`) and restrict `Commit.where(sha: params.sha, stack_id: ...)` to those stacks only, rather than updating every `Commit` row across every stack that happens to share that SHA.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb (conceptual addition)
test "#process does not attach a status to a commit belonging to an unrelated stack sharing the same sha" do
  victim_stack = shipit_stacks(:shipit)
  attacker_stack = shipit_stacks(:cyclimse) # a different, unrelated stack/repo
  shared_sha = "deadbeef" * 5

  victim_commit = victim_stack.commits.create!(sha: shared_sha, ...)
  attacker_commit = attacker_stack.commits.create!(sha: shared_sha, ...)

  payload = {
    'sha' => shared_sha,
    'state' => 'success',
    'context' => 'ci/required',
    'repository' => { 'full_name' => attacker_stack.repository.full_name, 'owner' => { 'login' => attacker_stack.repository.owner } }
  }

  Shipit::Webhooks::Handlers::StatusHandler.new(payload).call

  # equality that should hold: only attacker_commit gets the status
  assert_equal 1, attacker_commit.reload.statuses.count
  assert_equal 0, victim_commit.reload.statuses.count  # currently FAILS: also gets the status
end
```
A second, end-to-end test would set up two pending `MergeRequest`s on `victim_stack` (one legitimately CI-passing, one attacker-targeted with only the forged cross-stack status), run `ProcessMergeRequestsJob.new.perform(victim_stack)`, and assert `Shipit.github.api.expects(:merge_pull_request)` is invoked with the attacker-targeted PR's `number` while the legitimately-ready PR is left untouched — demonstrating the queue-jump/CI-bypass impact.

### Citations

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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb (L1-1)
```ruby
class IndexCommitsOnStackIdAndSha < ActiveRecord::Migration[5.1]
```

**File:** app/models/shipit/merge_request.rb (L193-197)
```ruby
    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end
```

**File:** app/jobs/shipit/process_merge_requests_job.rb (L10-32)
```ruby
    def perform(stack)
      merge_requests = stack.merge_requests.to_be_merged.to_a
      merge_requests.each do |merge_request|
        merge_request.refresh!
        merge_request.reject_unless_mergeable!
        merge_request.cancel! if merge_request.closed?
        merge_request.revalidate! if merge_request.need_revalidation?
      end

      return false unless stack.allows_merges?

      merge_requests.select(&:pending?).each do |merge_request|
        merge_request.refresh!
        next unless merge_request.all_status_checks_passed?

        begin
          merge_request.merge!
        rescue MergeRequest::NotReady
          ProcessMergeRequestsJob.set(wait: 10.seconds).perform_later(stack)
          return false
        end
      end
    end
```
