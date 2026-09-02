### Title
Cross-repository status forgery unblocks victim stack's commits via SHA-only matching in `StatusHandler#process` — ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` resolves target commits purely by `sha` across the entire `commits` table, without checking that the webhook's `repository.full_name` matches the `stack` that owns the matched `Commit` row. Because Git commit SHAs are content-addressed and identical across forks/clones, an attacker who owns any repository sharing a commit object with a public victim stack B (e.g., via forking B) can send a legitimately GitHub-signed status webhook from their own repository that gets applied to B's commit, satisfying `stack.blocking_statuses`, flipping `Commit#blocked?` to `false`, and triggering `ContinuousDeliveryJob` for B.

### Finding Description
The broken binding: the set of `Status` rows used to compute `blocking_statuses` for stack B's commit must satisfy `status.commit.sha's owning repository == B`. In fact, `StatusHandler#process` performs: [1](#0-0) 

`Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` matches every `Commit` record in the database sharing that SHA, regardless of which stack/repository it belongs to. Unlike other handlers, it never uses the `Handler#stacks` helper (`Repository.from_github_repo_name(repository_name)&.stacks`), which scopes lookups to the repository named in the payload: [2](#0-1) 

`verify_signature` in `WebhooksController` only proves the webhook truly originated from GitHub for the organization owning the payload's `repository.owner.login` — it does not, and cannot, prove anything about which SHAs are legitimately "owned" by that repository: [3](#0-2) 

Since Git SHA1 commit hashes are computed from tree/parent/metadata content, a commit forked from a public repository B into attacker-controlled repository A retains the *exact same SHA*. The attacker can then call GitHub's real Statuses API against their own fork A for that shared SHA (a fully legitimate action for a repo they own), causing GitHub to deliver a correctly-signed `status` webhook for repository A. `StatusHandler#process` ignores the repository context in that payload and applies the status to *every* `Commit` row with that SHA — including B's row — via `create_status_from_github!`: [4](#0-3) 

`Commit#blocked?` computes blocking purely from `Status`/`CheckRun` rows attached to commits between last-deployed and this commit: [5](#0-4) 

Once the forged status satisfies every context in `stack.blocking_statuses`, `deployable?` and `schedule_continuous_delivery` can flip true and enqueue `ContinuousDeliveryJob` for B: [6](#0-5) 

None of the listed guards (`verify_signature`, `drop_unhandled_event`, `ExplicitParameters` schema, `force_github_authentication`, `require_permission!`) prevent this, because they authenticate *that a webhook came from GitHub for repository A*, not *that the SHA inside it belongs to A*. The `Handler#stacks`/`Repository.from_github_repo_name` scoping mechanism exists precisely to make this binding hold, but `StatusHandler` is the one handler that bypasses it entirely.

### Impact Explanation
A forged/mismatched status write on stack B's commit can unblock deploy gating (`blocking_statuses`) and cause `ContinuousDeliveryJob` to be enqueued and execute an unauthorized deploy for a stack the attacker has no relationship to, no membership in `Shipit.github_teams` for, and no GitHub write access to. This is a "payload for one repository mutating another's stack/commit" and can lead to an unauthorized deploy — matching the Critical severity bucket. The attack is repeatable against any public repository whose history the attacker can fork/clone (trivial on GitHub), and scales across all stacks in the Shipit instance that happen to track any commit reachable by an attacker-owned fork.

### Likelihood Explanation
Preconditions: attacker needs (a) a GitHub repository they control that is registered as a Shipit-managed stack (any user who can administer a repo can typically add it as a stack — no elevated Shipit privilege needed), and (b) that repository shares at least one commit object (same SHA) with the victim stack, trivially achieved by forking the victim's public repository. The attacker needs to discover `stack.blocking_statuses` context names, which the prompt notes are visible in the victim's public `shipit.yml`. No secrets, tokens, or privileged roles are required — only a standard GitHub account and the ability to call the real Statuses API on their own repository, which GitHub will sign legitimately. This is low-cost and fully repeatable.

### Recommendation
Scope `StatusHandler#process` (and any other handler resolving records purely by SHA) to only the commits belonging to stacks of the repository named in the webhook payload, e.g., using the existing `Handler#stacks` helper: resolve `stacks` from `Repository.from_github_repo_name(repository_name)` and restrict `Commit.where(sha: params.sha, stack_id: stacks.select(:id))` (or iterate `stacks.flat_map { |s| s.commits.where(sha: params.sha) }`) before calling `create_status_from_github!`.

### Proof of Concept
Minitest plan (webhook/model level, no live GitHub):
1. Create `stack_b` with `stack.blocking_statuses = ['ci/blocking']`.
2. Create an older `Commit` (`older_commit`) on `stack_b` with a `Status` for context `ci/blocking` in `pending`/`error` state (blocking), and a newer undeployed `victim_commit` sharing the same SHA `S` as a commit that also exists (or is faked) on an unrelated `stack_a` (attacker's repo).
3. Assert precondition: `victim_commit.blocked?` is `true`.
4. POST to `/webhooks` with `X-Github-Event: status`, correctly signed for `stack_a`'s owning organization, payload `{ sha: S, state: 'success', context: 'ci/blocking', repository: { full_name: stack_a.github_repo_name, owner: { login: stack_a_org } } }`.
5. Assert `older_commit.reload.blocking?` becomes `false` and `victim_commit.reload.blocked?` becomes `false`, even though the webhook's `repository.full_name` equals `stack_a.github_repo_name`, not `stack_b.github_repo_name` — proving the binding `status.reported_repository == commit.stack.github_repo_name` is violated.
6. Assert `ContinuousDeliveryJob` was enqueued with `stack_b` as argument, confirming the unauthorized-deploy trigger fired for a stack the webhook's repository does not own.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L227-287)
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

    def children
      self.class.where(stack_id:).newer_than(self)
    end

    def detach_children!
      children.detach!
    end

    def pull_request?
      pull_request_number.present?
    end

    # TODO: remove in a few versions when it is assumed the commits table was backfilled
    def pull_request_number
      super || message_parser.pull_request_number
    end

    def title
      pull_request_title || message_header
    end

    def message_header
      message.lines.first.to_s.strip
    end

    # TODO: remove in a few versions when it is assumed the commits table was backfilled
    def pull_request_title
      super || message_parser.pull_request_title
    end

    def revert?
      title.start_with?('Revert "') && title.end_with?('"')
    end

    def revert_of?(commit)
      title == %(Revert "#{commit.title}") || title == %(Revert "#{commit.message_header}")
    end

    def short_sha
      sha[0..9]
    end

    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```
