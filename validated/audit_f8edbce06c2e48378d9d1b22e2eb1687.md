### Title
Cross-tenant status webhook forgery merges pull requests on victim stacks via unscoped `Commit.where(sha:)` lookup - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` resolves target commits purely by `sha`, with no scoping to the repository/organization that authenticated the webhook. Because Git commit SHA1s are content-addressed (identical tree + parents + author/committer + message + timestamps yield identical SHA1), an attacker who owns any repository registered as a Shipit stack can produce a commit whose SHA matches the `head` commit of a *victim's* pending `MergeRequest`, then have GitHub deliver a legitimately-signed `status` webhook for their own repo that writes a `success` `Status` row onto the victim's shared `Commit` record, unblocking and ultimately triggering `MergeRequest#merge!` on the victim's repository.

### Finding Description
The claimed binding should be: `webhook.repository_owner (used in verify_signature) == commit.stack.repository.owner (the record being mutated)`. Tracing the code shows this equality is never enforced past signature verification.

- `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-30`) derives the signing organization from the **attacker's own payload** (`repository_owner`, `app/controllers/shipit/webhooks_controller.rb:59-62`) and verifies the signature against that organization's GitHub App secret via `Shipit.github(organization: repository_owner)`. This check is legitimately satisfiable by the attacker because GitHub will sign a `status` event for a repository the attacker owns/controls with that org's real webhook secret. [1](#0-0) [2](#0-1) 

- After that check passes, `StatusHandler#process` does:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
This query is **global across all stacks/tenants** — it is not scoped by `stack_id`, `repository`, or anything derived from `repository_owner`. Any `Commit` row anywhere in the Shipit instance whose `sha` matches the attacker-controlled `params.sha` will be updated. [3](#0-2) 

- `Commit#create_status_from_github!` → `#add_status` creates the `Status` using the commit's own `stack_id` (the victim stack's id, not the attacker's), and when the resulting state is `pending` or `success`, calls `stack.schedule_merges`, enqueuing `ProcessMergeRequestsJob` for the **victim's stack**. [4](#0-3) 

- `ProcessMergeRequestsJob#perform` then calls `merge_request.all_status_checks_passed?`, which delegates to `MergeRequest::StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?` — purely a function of the `Status`/`CheckRun` rows attached to `head`, with no notion of which organization created them. [5](#0-4) [6](#0-5) 

- If this flips a previously-blocked (`any_status_checks_missing?`) pending `MergeRequest` to passing, `merge_request.merge!` calls `stack.github_api.merge_pull_request(...)`, performing a real merge on the victim repository, driven entirely by a webhook the victim's organization never authenticated. [7](#0-6) 

None of the existing guards close this gap: `verify_signature` only proves the payload's *own* `repository`/`organization` field is authentic for *that* org — it says nothing about which `Commit` rows the handler is permitted to touch, and `StatusHandler`'s `ExplicitParameters` schema only validates `sha`/`state` types, not repository ownership. `drop_unhandled_event` and `check_if_ping` are irrelevant here.

### Impact Explanation
A single forged/legitimate-but-attacker-controlled `status` webhook from a repository the attacker owns can write a `Status` record onto, and ultimately trigger `Shipit::MergeRequest#merge!` for, a completely different organization's `MergeRequest`/`Stack`, as long as a SHA collision (achievable via content-identical commits, e.g. cherry-picks/rebases reproducing tree+parents+message+timestamps) exists between the attacker's commit and the victim's PR head. This is a cross-tenant write and an unauthorized merge triggered on a victim's repository by an unprivileged external party — matching the Critical category "a payload for one repository mutating another's stack, commit ... or an unauthorized ... merge." The attack is repeatable against any stack/commit whose SHA the attacker can reproduce, and is not limited to a single victim.

### Likelihood Explanation
Preconditions: the victim `MergeRequest` must be `pending` with `merge_queue_enabled`, and the attacker must control a repository registered as a Shipit stack (or any repo GitHub will deliver signed webhooks for) so their own status webhook passes `verify_signature`. The attacker additionally needs to produce a commit with the same SHA1 as the victim's PR head — feasible without any cryptographic collision attack when the attacker can reproduce identical commit content/metadata (tree, parents, author, committer, message, timestamps), e.g. by forking a shared base and performing a rebase-preserving cherry-pick as described. No secrets, sessions, or privileged roles are needed; the attacker only needs an account and a repo they can push to.

### Recommendation
Scope `StatusHandler#process` (and analogous handlers like `check_suite`) by the repository that authenticated the webhook, not by `sha` alone — e.g. join through `Stack`/`Repository` matching `params.dig('repository','full_name')` (or `repository_owner`/`repository_id`) before touching any `Commit`, so a status can only ever mutate commits belonging to stacks under the same GitHub repository/organization that signed the webhook.

### Proof of Concept
```ruby
# test/jobs/process_merge_requests_job_test.rb (new test)
test "#perform does not merge a PR whose status was set via a status webhook from a different repository" do
  victim_stack = shipit_stacks(:shipit)
  victim_pr = shipit_merge_requests(:shipit_mergeable_pending_ci) # currently blocked by any_status_checks_missing?
  shared_sha = victim_pr.head.sha

  # Attacker owns a different repo (different stack/org) but crafts a commit with the same sha
  # and gets GitHub to deliver a legitimately-signed status webhook for THEIR repo.
  attacker_payload = {
    'sha' => shared_sha,
    'state' => 'success',
    'context' => 'ci/circle',
    'repository' => { 'full_name' => 'attacker-org/attacker-repo', 'owner' => { 'login' => 'attacker-org' } }
  }

  # verify_signature passes because it's checked against attacker-org's own webhook secret, not victim's.
  Shipit::Webhooks::Handlers::StatusHandler.new(attacker_payload).call

  refute victim_pr.reload.all_status_checks_passed?, "victim MR should not be marked passing from a foreign webhook"

  Shipit.github.api.expects(:merge_pull_request).never
  ProcessMergeRequestsJob.new.perform(victim_stack)
  refute_predicate victim_pr.reload, :merged?
end
```
Both sides of the binding to assert explicitly: `webhook_signing_org = 'attacker-org'` vs `commit.stack.repository.owner = victim org owning shipit_stacks(:shipit)` — they differ, yet current code lets the write through; the test should fail today (status gets created, `all_status_checks_passed?` flips true, `merge_pull_request` gets invoked) confirming the vulnerability, and should pass once the handler is scoped to the authenticated repository.

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

**File:** app/jobs/shipit/process_merge_requests_job.rb (L21-26)
```ruby
      merge_requests.select(&:pending?).each do |merge_request|
        merge_request.refresh!
        next unless merge_request.all_status_checks_passed?

        begin
          merge_request.merge!
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
