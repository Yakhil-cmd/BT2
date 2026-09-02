### Title
Cross-repository/cross-tenant CI status forgery via `StatusHandler` unscoped `Commit.where(sha:)` lookup enables victim `GITHUB_TOKEN` to auto-merge a PR based on attacker-forged status - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves target commits by `Commit.where(sha: params.sha)` across the entire commits table, with no check that the webhook's `repository.full_name` matches the stack that owns the matched commit(s), unlike the base `Handler#stacks` helper. Since GitHub SHAs are content-addressed and shared across forks/mirrors, and Shipit installations commonly onboard multiple independent GitHub orgs (`Shipit.github(organization:)` supports a per-org webhook secret/app, as documented and tested in `secrets_double_github_app.yml`), a legitimately-webhook-signed event from one onboarded org can create a `Shipit::Status` row attributed to a *different* org/stack's commit that happens to share the same SHA. That forged status then flows into `MergeRequest#all_status_checks_passed?` via `Status::Group.compact`, and `ProcessMergeRequestsJob` calls `merge_request.merge!`, which uses the victim stack's own `stack.github_api` (the victim org's GitHub App token) to merge the victim's pull request.

### Finding Description
Broken binding: the credential used, `stack.github_api` (victim's `Shipit.github(organization: repository.owner).api`, backed by the victim org's GitHub App installation token), should only be authorized to act based on Status data that was authenticated as originating from that same victim org/repository. Instead:

`credential_scope(stack.github_api) == org(repository.owner of the matched Commit's Stack)`, but `data_scope(Status created)` is only bound to `sha` (content hash), not to `payload['repository']['full_name']`.

Code path:
1. `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) picks the GitHub App/secret to verify against using `repository_owner`, i.e. `payload.dig('repository','owner','login')` — this is the *sender's own* org field, and is correctly signed by GitHub for whatever org the webhook actually came from. It does **not** establish that the sha in the payload belongs to that org's repository.
2. `Shipit::Webhooks.for_event('status')` dispatches to `StatusHandler#process`:
   ```ruby
   def process
     Commit.where(sha: params.sha).each do |commit|
       commit.create_status_from_github!(params)
     end
   end
   ``` [1](#0-0) 
   This is a **global** lookup by `sha` only. It never calls the base `Handler#stacks`/`repository_name` scoping (`app/models/shipit/webhooks/handlers/handler.rb:32-38`) that other handlers rely on to restrict effects to the repository that sent the webhook. [2](#0-1) 
3. `Commit#create_status_from_github!` then writes the status using the *matched commit's own* `stack_id` (the victim stack), not the sender's stack:
   ```ruby
   def create_status_from_github!(github_status)
     add_status do
       statuses.replicate_from_github!(stack_id, github_status)
     end
   end
   ``` [3](#0-2) 
4. `Commit#status` / `statuses_and_check_runs` feed `Status::Group.compact` [4](#0-3)  and `MergeRequest::StatusChecker < Status::Group` [5](#0-4) . `MergeRequest#all_status_checks_passed?` uses this forged status set:
   ```ruby
   def all_status_checks_passed?
     return false unless head
     StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
   end
   ``` [6](#0-5) 
5. `ProcessMergeRequestsJob#perform` iterates pending merge requests, calls `all_status_checks_passed?`, and on success invokes `merge_request.merge!`:
   ```ruby
   merge_requests.select(&:pending?).each do |merge_request|
     merge_request.refresh!
     next unless merge_request.all_status_checks_passed?
     merge_request.merge!
   ``` [7](#0-6) 
6. `MergeRequest#merge!` performs the merge using the victim stack's own credentials:
   ```ruby
   stack.github_api.merge_pull_request(
     stack.github_repo_name, number, merge_message,
     sha: head.sha, commit_message: 'Merged by Shipit', merge_method: stack.merge_method
   )
   ``` [8](#0-7)  where `stack.github_api` resolves to `Shipit.github(organization: repository.owner).api` [9](#0-8)  — i.e. exactly the victim org's own credential, never the attacker's.

Why existing guards fail: `verify_signature` only proves the webhook truly came from *some* org that has a Shipit GitHub App configured — it authenticates the sender, not the target of the `sha` claim inside the payload. `StatusHandler` trusts `params.sha` blindly across the whole `commits` table, breaking the intended repository-scoping pattern used elsewhere via `Handler#stacks`.

Attacker's exact request: attacker is a legitimate, unprivileged user/maintainer of some onboarded org/repo (`OrgTwo` in the multi-org config example) that has its own valid GitHub App installation and webhook secret configured in Shipit (per `docs/setup.md`'s "Using Multiple Github Applications" and `config/secrets.development.shopify.yml`/`secrets_double_github_app.yml`). The attacker triggers a genuine, GitHub-signed `status` event on their own repo (e.g. via GitHub Status API on a commit within their own repo) using a `sha` value that also exists in the victim's tracked repository/stack (achievable since content-addressed git SHAs are identical across forks, vendored/shared histories, or simply because the attacker forked the victim's public repo and the target commit already exists upstream). They set `state: success`, `context: <the victim stack's required CI context>`. GitHub signs and delivers this to `POST /webhooks` with the correct signature for the attacker's own org, so `verify_signature` passes.

### Impact Explanation
An unprivileged actor with control over any onboarded (even unrelated) repository/org in a multi-tenant Shipit deployment can inject a fabricated "success" CI status into another tenant's commit purely by SHA coincidence, causing that victim's pending merge request to be judged mergeable and merged automatically by `ProcessMergeRequestsJob` using the *victim's own* `GITHUB_TOKEN`/GitHub App credentials. This is an unauthorized merge triggered by cross-tenant forged data, matching the "Critical — a payload for one repository mutating another's stack/commit ... or an unauthorized deploy, rollback or merge" impact category. It is repeatable against any tracked stack/commit whose SHA the attacker can predict or reproduce (e.g. via forking public repos), and the blast radius spans all tenants sharing one Shipit instance.

### Likelihood Explanation
Requires: (1) a multi-org/multi-tenant Shipit deployment (explicitly supported and documented) where the attacker legitimately controls at least one onboarded org/repo; (2) a SHA collision opportunity — realistic via repo forking (identical git history/commits) or shared vendored commits, not a cryptographic hash break; (3) the victim repo's required status context name (often discoverable from public `shipit.yml`/CI config). No Shipit secrets, sessions, or privileged roles are needed — only the ability to emit a real, GitHub-signed webhook from a repo the attacker owns. This is feasible and repeatable at will.

### Recommendation
In `StatusHandler#process` (and any other handler doing sha-only lookups), scope the `Commit` lookup to the stacks associated with `payload.dig('repository','full_name')` (using the existing `Handler#stacks` helper), e.g. `stacks.flat_map(&:commits).where(sha: params.sha)`, instead of a global `Commit.where(sha:)`. Ensure the commit's own stack/repository matches the webhook's asserted repository before creating a `Status`.

### Proof of Concept
Minitest plan (`test/models/webhooks/handlers/status_handler_test.rb` or similar), no live GitHub:
1. Create two stacks/repos: `victim/repo` (with a pending `MergeRequest` whose `head` commit has `sha = SHARED_SHA` and a required status context `ci/circle` missing) and `attacker/repo` with a commit having the same `sha = SHARED_SHA`.
2. Stub `stack.github_api` (victim's) with `expects(:merge_pull_request)` — asserting it would be invoked with the victim's stack/credentials.
3. Invoke `Shipit::Webhooks::Handlers::StatusHandler.call({'sha' => SHARED_SHA, 'state' => 'success', 'context' => 'ci/circle', 'repository' => {'full_name' => 'attacker/repo'}})` (bypassing controller-level signature verification, simulating a validly-signed webhook from `attacker/repo`).
4. Assert: `victim_merge_request.head.reload.statuses.where(context: 'ci/circle').exists?` is true (forged cross-repo status landed on victim commit); `assert_predicate victim_merge_request.reload, :all_status_checks_passed?`.
5. Run `ProcessMergeRequestsJob.new.perform(victim_stack)` and assert `stack.github_api.merge_pull_request` (victim's stub) was called — i.e., the victim's own credential was used to merge based purely on attacker-forged data, with no assertion ever binding `params.sha`'s originating repository to the victim stack.

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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L304-306)
```ruby
    def status
      @status ||= Status::Group.compact(self, statuses_and_check_runs)
    end
```

**File:** app/models/shipit/merge_request.rb (L15-39)
```ruby
    class StatusChecker < Status::Group
      def initialize(commit, statuses, deploy_spec)
        @deploy_spec = deploy_spec
        super(commit, statuses)
      end

      private

      attr_reader :deploy_spec

      def reject_hidden(statuses)
        statuses.reject { |s| ignored_statuses.include?(s.context) }
      end

      def reject_allowed_to_fail(statuses)
        statuses.reject { |s| ignored_statuses.include?(s.context) }
      end

      def ignored_statuses
        deploy_spec&.merge_request_ignored_statuses || []
      end

      def required_statuses
        deploy_spec&.merge_request_required_statuses || []
      end
```

**File:** app/models/shipit/merge_request.rb (L164-176)
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
```

**File:** app/models/shipit/merge_request.rb (L193-197)
```ruby
    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
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

**File:** app/models/shipit/stack.rb (L434-440)
```ruby
    def github_api
      github_app.api
    end

    def github_app
      Shipit.github(organization: repository.owner)
    end
```
