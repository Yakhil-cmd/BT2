This confirms the mechanism. `StatusHandler#process` matches commits purely by `sha` across the entire `commits` table with no repository/stack scoping check against the webhook payload's `repository.full_name`, then calls `commit.create_status_from_github!(params)` which persists a `Status` row keyed to that commit's own `stack_id`/`commit_id` [1](#0-0) [2](#0-1) [3](#0-2) .

### Title
Cross-repo forged `status` webhook persists a fake `Status` row for `victim/repo`, corrupting CI history read by `MergeRequest` checks even when `ignore_ci?` is true - ([File: app/models/shipit/webhooks/handlers/status_handler.rb](app/models/shipit/webhooks/handlers/status_handler.rb))

### Summary
`Commit#deployable?` short-circuiting to `!locked?` for `ignore_ci?` stacks only neutralizes the *deploy-trigger* consequence of a forged status; it does not prevent the write. `StatusHandler#process` still persists the forged `Status` row scoped to the victim commit/stack, which is later read by `MergeRequest#any_status_checks_missing?`/`#any_status_checks_failed?` for merge-queue decisions on that same stack, and is displayed in the UI as if GitHub reported it.

### Finding Description
The binding claimed is: `Status` row for `victim/repo`'s commit == a status GitHub actually reported for `victim/repo`. This binding is broken independent of `ignore_ci?`.

`StatusHandler#process` does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [1](#0-0) 
This lookup is global across all stacks/repositories in the Shipit instance and never cross-checks `params.dig('repository','full_name')` against the matched commit's `stack.github_repo_name`. `create_status_from_github!` calls `statuses.replicate_from_github!(stack_id, github_status)` [2](#0-1) , and `Status.replicate_from_github!` persists a row with the commit's own `stack_id` [3](#0-2) . So the persisted `state`, unrelated to which repository actually sent it, is attributed to whichever commit row matches the sha — including a `victim/repo` commit that shares its sha with an identical commit an attacker replicated in their own (attacker-owned, Shipit-registered) repository/fork.

`Commit#deployable?` is:
```ruby
def deployable?
  !locked? && (stack.ignore_ci? || (success? && !blocked?))
end
``` [4](#0-3) 
For `ignore_ci?` stacks this indeed ignores `success?`, so the forged `success` status does not by itself unlock a deploy trigger through this path. That is a separate, narrower question than whether the row is written and read elsewhere.

Independently, `MergeRequest`'s merge-queue logic uses a completely separate status evaluation path that does not consult `ignore_ci?` at all:
```ruby
def any_status_checks_failed?
  status = StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec)
  status.failure? || status.error?
end

def any_status_checks_missing?
  StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).missing?
end
``` [5](#0-4) 
These are consumed by `reject_unless_mergeable!`, run from `ProcessMergeRequestsJob` for merge-queue evaluation on the victim's own stack: [6](#0-5) [7](#0-6) 
`head.statuses_and_check_runs` simply concatenates `statuses + check_runs` for that commit [8](#0-7) , so the forged row is indistinguishable from a genuine GitHub status once written, and directly participates in whether a victim PR is rejected for `ci_failing`/`ci_missing` or allowed to proceed toward `merge!`.

Existing guards do not stop this: `verify_signature` only proves the payload was signed for whichever `repository_owner`/organization is present in the payload — it never checks that the matched `Commit`'s `stack.repository` equals that organization/repo [9](#0-8) . `StatusHandler`'s `ExplicitParameters` schema only validates `sha`/`state`/etc. types, not repository ownership [10](#0-9) .

### Impact Explanation
A forged `Status` row is written into the `statuses` table attributed to `victim/repo`'s commit/stack, without any authentication tying it to `victim/repo`. This corrupts the CI history displayed in Shipit's UI for `victim/repo` and, more materially, can flip `MergeRequest#any_status_checks_failed?`/`#any_status_checks_missing?` from true to false (by injecting a fabricated `success` for a required context) on `victim/repo`'s own merge queue, letting a PR bypass `reject_unless_mergeable!`'s `ci_failing`/`ci_missing` checks and proceed to `merge!`. This is a payload for one repository (the attacker's) mutating another repository's stack/commit data and can enable an unauthorized merge for `victim/repo` — matching the Critical category ("a payload for one repository mutating another's stack, commit, task or team" / "unauthorized... merge"). It is repeatable against any stack whose tracked commit shas can be reproduced by an attacker (e.g. via a public fork with identical commit objects) and does not depend on the `ignore_ci?` setting of the affected stack at all — `ignore_ci?` only changes whether `Commit#deployable?` reacts to it, not whether the row is persisted or read by the merge queue.

### Likelihood Explanation
Preconditions: the attacker must own/control a repository that is itself registered as a Shipit stack (a legitimate, unprivileged action for their own repo) so that GitHub signs real `status` webhook events for it with a secret Shipit already trusts; and the attacker must produce a commit with the exact same SHA as a commit in `victim/repo` (trivial via forking a public repo, which reproduces identical commit objects/shas). No Shipit secrets, sessions, or GitHub App keys are needed — the webhook signature is genuinely computed by GitHub for the attacker's own repository. Given a public target repo, this is cheap and repeatable against any commit sha shared between the attacker's fork and the tracked stack.

### Recommendation
In `StatusHandler#process` (and analogously in any other sha-keyed webhook handler), restrict the `Commit.where(sha: ...)` lookup to commits whose `stack.repository` matches `params.dig('repository','full_name')` (or the equivalent `repository_owner`/`repo_name` from the payload), rejecting/ignoring matches for stacks belonging to a different repository.

### Proof of Concept
Minitest plan (`test/models/shipit/status_handler_test.rb` or extending `webhooks_controller_test.rb`):
1. Create `victim_stack` for `victim/repo` with `ignore_ci: true`, and a `victim_commit` with a known `sha` (e.g. `"deadbeef"*5`) that already has no statuses, so `victim_commit.deployable?` is already `true` (`!locked? && ignore_ci?`).
2. Create `attacker_stack` for `attacker/repo`, and an `attacker_commit` with the identical `sha`.
3. Simulate the webhook handler directly (bypassing signature since it's proven separately elsewhere): `Shipit::Webhooks::Handlers::StatusHandler.new.call({'sha' => sha, 'state' => 'success', 'repository' => {'full_name' => 'attacker/repo'}})`.
4. Assert: `victim_commit.reload.status.success?` is `true` — binding broken: `assert victim_commit.statuses.exists?` even though no GitHub event was ever sent for `victim/repo`.
5. Assert `victim_commit.deployable?` was already `true` before/after (showing `ignore_ci?` masked nothing about the write).
6. Build a `MergeRequest` on `victim_stack` whose `head == victim_commit` requiring context matching the forged status; assert `merge_request.any_status_checks_failed?` is now `false` (previously `true`/missing) purely due to the forged row, i.e. `assert_not merge_request.reject_unless_mergeable!` where it should have rejected as `ci_missing`/`ci_failing` absent the forgery.

### Citations

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

**File:** app/models/shipit/commit.rb (L144-146)
```ruby
    def statuses_and_check_runs
      statuses + check_runs
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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
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

**File:** app/models/shipit/merge_request.rb (L155-162)
```ruby
    def reject_unless_mergeable!
      return reject!('merge_conflict') if merge_conflict?
      return reject!('ci_missing') if any_status_checks_missing?
      return reject!('ci_failing') if any_status_checks_failed?
      return reject!('requires_rebase') if stale?

      false
    end
```

**File:** app/models/shipit/merge_request.rb (L199-206)
```ruby
    def any_status_checks_failed?
      status = StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec)
      status.failure? || status.error?
    end

    def any_status_checks_missing?
      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).missing?
    end
```

**File:** app/jobs/shipit/process_merge_requests_job.rb (L10-23)
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
