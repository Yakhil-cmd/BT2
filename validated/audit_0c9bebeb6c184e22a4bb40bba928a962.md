### Title
Cross-repository status forgery via unscoped `Commit.where(sha:)` lookup enables unauthorized merge - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`Webhooks::Handlers::StatusHandler#process` resolves the commit to update purely by SHA, with no scoping to the repository that emitted the webhook [1](#0-0) . Because GitHub's commit-status API lets any writer of *any* repository attach a status to an arbitrary SHA string (it need not belong to that repository's own history), and Shipit's `Stack` model is keyed by repository but `Commit`/`Status` records are looked up globally by SHA, a status genuinely emitted from an unrelated repository can be attributed to a commit that belongs to a completely different stack, which can flip a pending `MergeRequest` to "checks passed" and trigger an unauthorized `merge!` against the victim stack's own GitHub repository.

### Finding Description
The binding this breaks: "the CI/reporting repository authorized to set a status for stack S's commit == the repository whose webhook actually produced that status record for stack S's commit" should hold, i.e. `status.commit.stack.repository == webhook.payload.repository`. It does not.

- `StatusHandler#process` does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [1](#0-0) . Unlike `PushHandler`, which scopes to `stacks.not_archived.where(branch:)` derived from the payload's own repository [2](#0-1) , `StatusHandler` never joins/filters on `repository`. `Commit` is a global table shared by all stacks/repositories, so any commit anywhere in the database whose `sha` matches the incoming payload's `sha` gets a new `Status` row applied, `commit.create_status_from_github!` re-evaluates commit state, and (via `add_status`) schedules `ProcessMergeRequestsJob` for that commit's *actual* stack when the new status is pending/success [3](#0-2) .
- `WebhooksController#verify_signature` selects the HMAC secret via `Shipit.github(organization: repository_owner)` [4](#0-3) . In the common single-GitHub-App deployment (the primary documented setup), `Shipit#github` ignores the `organization` argument entirely and always returns the one global `secrets.github` config [5](#0-4) . That means signature verification does not bind the checked secret to the claimed `repository_owner`; it only proves the request was genuinely signed by GitHub for *some* repository covered by that single App installation — not necessarily the victim's tracked stack repository.
- `MergeRequest#all_status_checks_passed?` and `ProcessMergeRequestsJob#perform` only consult the locally stored `head.statuses_and_check_runs` [6](#0-5) [7](#0-6) ; nothing re-derives these statuses from GitHub scoped to the stack's own repository before calling `merge!`, which then uses `stack.github_api.merge_pull_request` with the victim stack's own credentials [8](#0-7) .

Exploit flow: an attacker who has write access to *any* repository covered by the same GitHub App installation as the victim's Shipit instance (their own repo, or any unrelated/sandbox repo in the same org — not the victim's tracked repository, and not requiring Shipit access/team membership) reads the victim's public PR head commit SHA, then calls GitHub's commit-status API against their own unrelated repository with `sha=<victim head sha>&state=success`. GitHub emits a genuinely-signed `status` webhook for that unrelated repository. Shipit's `verify_signature` accepts it (valid signature for a covered installation), `StatusHandler` finds the `Commit` row with that SHA irrespective of which repository reported it, appends a `success`/`pending` status to it, and schedules `ProcessMergeRequestsJob` for the victim's stack. If that satisfies `StatusChecker.new(head, ...).success?` (e.g. it supplies a missing required context, or the deploy spec doesn't require anything else), `all_status_checks_passed?` returns true and `merge!` executes against the victim's repository using the victim stack's own `GITHUB_TOKEN`.

Existing guards do not stop this: `verify_signature` proves the request is real GitHub traffic for the shared App installation, not that it originated from the specific repository referenced by the SHA; there is no `Repository`/`Stack` scoping check anywhere in `StatusHandler`.

### Impact Explanation
A commit/status write and a subsequent GitHub `merge_pull_request` API call are executed for repository/stack S using S's own credentials, triggered entirely by activity on an unrelated repository the attacker controls. This is an unauthorized-merge / cross-tenant-mutation finding matching "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized merge" (Critical). It is repeatable against any stack whose head commit SHA the attacker can learn (trivial for public repos) as long as the attacker can set a status on some repository within the same GitHub App installation scope.

### Likelihood Explanation
Preconditions: Shipit must have a pending `MergeRequest` whose head commit is otherwise close to passing checks (attacker only needs to supply the missing/pending context, not fabricate every required check), and the attacker needs write access to at least one repository covered by the same GitHub App installation as the victim (their own repo if the App installation is broad/organization-wide, or another repo in the org). No Shipit credentials, session, API token, or webhook secret are required — only ordinary GitHub repository write access, which is a low-cost, realistic precondition in many organizations that install a GitHub App org-wide while restricting actual Shipit UI/team access more tightly.

### Recommendation
Scope `StatusHandler#process` (and `CheckSuiteHandler`, which has the same weakness) to the repository named in the webhook payload, mirroring `PushHandler`: resolve `stacks.where(repository: repository_from_payload)` first, then only update commits/statuses belonging to those stacks' repositories, e.g. join through `Stack`/`Repository` instead of a bare `Commit.where(sha:)`. Additionally, `MergeRequest#all_status_checks_passed?`/`ProcessMergeRequestsJob` should not treat locally cached `Status` rows as trustworthy across stacks without this repository binding.

### Proof of Concept
```ruby
# test/jobs/process_merge_requests_job_test.rb (new test)
test "a status forged from an unrelated repository's webhook cannot trigger a merge" do
  stack = shipit_stacks(:shipit)
  merge_request = shipit_merge_requests(:pending_merge_request) # fixture: pending, head commit missing one required status
  head = merge_request.head

  # Attacker only owns/writes to a completely unrelated repo; the payload's sha
  # matches the victim's head commit sha, but the payload's own repository is unrelated.
  forged_payload = OpenStruct.new(
    sha: head.sha,
    state: 'success',
    context: 'ci/required-context',
    description: nil,
    target_url: nil,
    created_at: Time.now.to_s,
    branches: []
  )

  stack.github_api.expects(:merge_pull_request).never

  assert_difference '-> { head.statuses.count }', 1 do
    Shipit::Webhooks::Handlers::StatusHandler.call(forged_payload.to_h.stringify_keys)
  end

  ProcessMergeRequestsJob.new.perform(stack)

  merge_request.reload
  assert_predicate merge_request, :pending? # should remain pending; must NOT have merged
end
```
Binding assertions: `status.commit.stack.repository == "unrelated/other-repo"` (payload origin) vs `merge_request.stack.repository == "victim/repo"` — the test should fail today (status is created and, depending on `StatusChecker` config, `merge_pull_request` gets called) because `StatusHandler` never checks that the two repositories match, demonstrating the broken binding.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
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

**File:** lib/shipit.rb (L170-181)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
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

**File:** app/models/shipit/merge_request.rb (L193-197)
```ruby
    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
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
