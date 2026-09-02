### Title
Cross-repository Status forgery via unscoped `sha` lookup in `StatusHandler#process` merges commits from unrelated repos - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` resolves target commits by `Commit.where(sha: params.sha)` with no repository/stack scoping, unlike every other handler (`PushHandler`, the `PullRequest::*Handlers`) which resolve `stacks`/`repository` via `Repository.from_github_repo_name(payload.dig('repository','full_name'))`. Any legitimately signed "status" webhook whose `sha` collides with a commit already known to an unrelated stack will write a `Status` onto that unrelated stack's commit, letting `MergeRequest#all_status_checks_passed?` return true for a PR the attacker never had access to.

### Finding Description
The binding that must hold before a CI status is trusted for stack A's merge decision is:

`payload.dig('repository', 'full_name') == stack_a.repository.full_name`

i.e., the GitHub repository that produced the "status" event must be the same repository that owns the commit being merged.

Tracing the code:
- `WebhooksController#verify_signature` only checks that the payload is signed with the secret configured for `repository_owner` (`params.dig('repository','owner','login')` or `organization.login`) [1](#0-0) . This proves the payload came from a GitHub App/organization that Shipit trusts, but it never ties the payload to the *specific repository* that owns any particular stack.
- `StatusHandler` declares no `repository` field in its `params` schema at all, and `process` is:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [2](#0-1) 
This is a global, cross-repository lookup by `sha` only. Contrast with `PushHandler`, which scopes via `stacks` (`Repository.from_github_repo_name(repository_name)&.stacks`) [3](#0-2)  and `Handler#stacks`/`#repository_name` [4](#0-3) , and every `PullRequest::*Handler`, which resolves `repository` from `params.repository.full_name` before touching any stack [5](#0-4) .
- `create_status_from_github!` -> `add_status` -> `statuses.replicate_from_github!` creates a `Status` row and, if the resulting simple state is `pending`/`success`, schedules `ProcessMergeRequestsJob` for `commit.stack` [6](#0-5) .
- `ProcessMergeRequestsJob#perform` then calls `merge_request.all_status_checks_passed?` and, if true, `merge_request.merge!` [7](#0-6) .
- `MergeRequest#all_status_checks_passed?` is computed purely from `head.statuses_and_check_runs` on the commit row matched by `sha`, with no reference back to which GitHub repository actually emitted the status [8](#0-7) .

Exploit flow: git commit SHA-1 is a hash of tree+parent+author/committer+timestamp+message, so it is trivially reproducible across repositories (e.g., a fork sharing history up to a point, or an attacker who copies the exact tree/parents/metadata of stack A's PR head into their own unrelated repository). The attacker pushes/creates that identical commit in their own repository (which they legitimately own and control CI for), gets a genuine GitHub-signed "status" webhook fired for **their own repo** (verified against `repository_owner` = attacker's own org/user, a check that only proves "this org's app secret signed it," not "this repository owns the commit"), and Shipit's `StatusHandler` blindly attaches that status to *every* `Commit` row across the install that shares the `sha`, including stack A's queued `MergeRequest#head`. `ProcessMergeRequestsJob` then merges stack A's PR.

Existing guards analyzed:
- `verify_signature`/`GithubApp#verify_webhook_signature` only authenticate "this event came from an org Shipit trusts"; they never assert "this event is about the repository that owns this commit," so they do not close the gap.
- `drop_unhandled_event`, `ExplicitParameters` schema, `force_github_authentication`, `User#authorized?`, `require_permission!`, the `stacks` scope on the controller side, and model validations are all irrelevant here — none of them are invoked in the "status" webhook path, which bypasses `current_user`/`ApiClient` entirely by design (webhooks are unauthenticated app-to-app calls, authorized only at the org level).

### Impact Explanation
A commit belonging to stack A can be pushed to its terminal `merged` state and actually merged on GitHub (`MergeRequest#merge!` calls `stack.github_api.merge_pull_request`) as a direct result of a status event that originated from a completely unrelated repository. This is an unauthorized merge/deploy trigger — the "GitHub identity/org that authorized the merge decision" (stack A's own repository/CI) is not the "GitHub identity/org that produced the passing status" (attacker's unrelated repository). This matches the Critical impact category "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy, rollback or merge." It is repeatable against any stack whose merge queue is enabled, as long as the attacker can produce/replicate a commit sha that also exists as a pending `MergeRequest#head` (or any queued commit) elsewhere in the same Shipit installation, and can get one genuinely-signed "status" webhook delivered for it from any repository under an org Shipit trusts.

### Likelihood Explanation
Preconditions: (1) the attacker needs a repository under an organization whose GitHub App/webhook secret Shipit already trusts (this can be an unrelated repo in the *same* org as stack A — very common in a shared-org, multi-repo Shipit deployment — no special privilege on stack A's repo is required); (2) the attacker needs to produce a commit whose SHA matches a commit currently queued in stack A's merge queue, which is feasible via shared git history (forks, cherry-picks, identical squash commits) or by directly crafting matching tree/parent/timestamp/message; (3) merge_queue must be enabled on stack A (`stack.allows_merges?`), which is the normal state for stacks using this feature. No secrets, sessions, or `ApiClient` tokens are required — GitHub itself signs the webhook when the attacker's own CI reports a status on their own repository. This is feasible without live GitHub access to prove: the vulnerable code path (`Commit.where(sha:)` unscoped by repository) can be demonstrated deterministically in a minitest by seeding two commits with the same `sha` in two different stacks and posting a status webhook that only carries a `repository` field matching the second stack.

### Recommendation
Scope `StatusHandler#process` (and any other sha-keyed handler) to the reporting repository, mirroring `PushHandler`/`PullRequest::*Handler`: require `repository.full_name` in the params schema, resolve `Repository.from_github_repo_name(params.repository.full_name)`, and restrict the `Commit.where(sha: params.sha)` lookup to `commits` belonging to that repository's stacks (e.g., `repository.stacks.flat_map(&:commits)

### Citations

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L6-24)
```ruby
      class StatusHandler < Handler
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

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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

**File:** app/models/shipit/merge_request.rb (L193-197)
```ruby
    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end
```
