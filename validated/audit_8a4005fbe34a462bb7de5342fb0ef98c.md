### Title
Cross-repository CI status forgery via unscoped commit SHA lookup in `StatusHandler` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
The `status` webhook handler resolves the commit to update purely by SHA, with no verification that the SHA belongs to the repository the inbound webhook was authenticated for. Because Shipit's GitHub App verifies webhook authenticity keyed off the payload's `repository.owner.login`/`organization.login` [1](#0-0)  but the actual database write in `StatusHandler#process` is scoped only by `sha` and not by repository [2](#0-1) , a legitimately-signed `status` event from one GitHub organization/repository can update the CI status of a `Commit` record that actually belongs to a stack tracked for a completely different, unrelated repository — as long as both repositories happen to share a commit with the same SHA (the common case for forks, which share git object history with their upstream until histories diverge).

### Finding Description
`WebhooksController#verify_signature` binds the authenticated identity to the organization/repository owner found in the payload [3](#0-2) . This establishes an equality the rest of the pipeline is implicitly expected to respect: `organization authenticated == repository written`.

Other handlers respect this binding by scoping their side effects through `Handler#stacks`, which resolves stacks strictly via `repository.full_name` from the same payload [4](#0-3) , e.g. `PushHandler` [5](#0-4) .

`StatusHandler`, however, breaks this binding: it never calls `stacks`/`repository_name` at all. It loads every `Commit` row across the entire Shipit installation whose `sha` matches the payload, regardless of which repository/stack it belongs to, and writes a new status onto each of them:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [2](#0-1) 

Since Shipit's `Commit` model is keyed by `sha` (a content-addressed git hash) without any composite uniqueness against repository, and forked repositories share git object history (and therefore SHAs) with their upstream until they diverge, an attacker who owns/controls their own fork (tracked as its own Shipit stack, which requires no privileged Shipit permission — only that the fork exists and Shipit's GitHub App is installed on it) can trigger a real, correctly-signed `status` webhook for a commit SHA that is also present in an unrelated organization's/repository's stack. Because the write path ignores which repository authenticated the event, the forged/attacker-controlled status (e.g., `state: success` for a required CI context) is applied to the `Commit` row belonging to the victim stack as well.

### Impact Explanation
Commit statuses feed directly into deploy and merge-queue gating: `MergeRequest#all_status_checks_passed?`/`any_status_checks_failed?`/`any_status_checks_missing?` are computed from `head.statuses_and_check_runs` via `StatusChecker` [6](#0-5) , and `ProcessMergeRequestsJob` merges pull requests once `all_status_checks_passed?` is true [7](#0-6) . Similarly, deploy gating uses the same commit statuses. If an attacker can force a shared commit's status to "success" for a required CI context from an unrelated repository they control, they can cause an unrelated stack's merge queue to merge a pull request, or a deploy to proceed, despite failing/missing real CI — an unauthorized merge/deploy. This satisfies the "Critical" impact bar (unauthorized deploy/merge) defined in scope.

### Likelihood Explanation
Exploitability depends on finding/engineering a shared commit SHA between the attacker's own repository (tracked as a Shipit stack) and the victim's repository (also tracked as a Shipit stack). This is realistic in fork-based workflows, which are extremely common on GitHub (forks share full git history/SHAs with upstream by construction), and organizations frequently onboard many repos, including forks, into the same Shipit instance. The attacker needs no privileged Shipit credential — only the ability to fire a real, correctly-signed webhook from a repository they legitimately control (e.g., by pushing/creating a status on their own fork), which is an unprivileged action relative to the victim stack.

### Recommendation
Scope `StatusHandler#process` (and any other handler that resolves records purely by `sha`) to only the stacks that belong to the repository identified in the webhook payload, mirroring the pattern already used by `PushHandler`/`CheckSuiteHandler` via `Handler#stacks`/`repository_name`. For example, filter `Commit.where(sha: params.sha)` down to commits whose `stack` belongs to `stacks` (repository-scoped), instead of operating globally across all Shipit-tracked repositories.

### Proof of Concept
1. Attacker forks `victim-org/app` into `attacker-org/app` (or any independent repo that happens to share a commit `C` with `victim-org/app`, e.g., prior to divergence).
2. Both `attacker-org/app` and `victim-org/app` are tracked as separate Shipit stacks (each with its own installed GitHub App / webhook secret).
3. Victim's stack requires CI context `ci/required` to pass before merge (`merge.require` in `shipit.yml`) and currently has that status missing/failing on commit `C` for an open PR queued in the merge queue.
4. Attacker sets (or has CI set) a `success` status for context `ci/required` on commit `C` in their own fork `attacker-org/app`. GitHub sends a correctly-signed `status` webhook to Shipit for `attacker-org/app`.
5. `WebhooksController#verify_signature` authenticates the request using `attacker-org`'s webhook secret and passes.
6. `StatusHandler#process` runs `Commit.where(sha: 'C')`, which returns the `Commit` row tracked under `victim-org/app`'s stack as well, and writes the forged `success` status onto it via `commit.create_status_from_github!`.
7. `ProcessMergeRequestsJob` re-evaluates the victim's pending PR, sees `all_status_checks_passed?` now true, and merges it — an unauthorized merge triggered entirely from the attacker's own, unrelated repository.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/merge_request.rb (L193-206)
```ruby
    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end

    def any_status_checks_failed?
      status = StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec)
      status.failure? || status.error?
    end

    def any_status_checks_missing?
      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).missing?
    end
```

**File:** app/jobs/shipit/process_merge_requests_job.rb (L21-30)
```ruby
      merge_requests.select(&:pending?).each do |merge_request|
        merge_request.refresh!
        next unless merge_request.all_status_checks_passed?

        begin
          merge_request.merge!
        rescue MergeRequest::NotReady
          ProcessMergeRequestsJob.set(wait: 10.seconds).perform_later(stack)
          return false
        end
```
