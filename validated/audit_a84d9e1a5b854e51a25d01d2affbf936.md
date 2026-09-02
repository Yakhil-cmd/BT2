Confirmed: `Commit#add_status` calls `stack.schedule_merges` (which calls `ProcessMergeRequestsJob.perform_later(self)`) whenever `previous_status.simple_state != new_status.simple_state` and the new state is `pending` or `success`, and this is invoked from `Status#schedule_continuous_delivery` → `commit.schedule_continuous_delivery`... actually the merge scheduling is done directly inside `add_status`, triggered synchronously from `create_status_from_github!`. Critically, `stack` here is `commit.stack` — the stack that owns the pre-existing `Commit` row, not any stack derived from the incoming webhook's `repository` field.

### Title
StatusHandler processes status webhooks by SHA only, without verifying they belong to the requesting repository, enabling cross-tenant `ProcessMergeRequestsJob` triggering - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up `Commit.where(sha: params.sha)` and calls `create_status_from_github!` on every match, with no check that the commit's `stack`/`repository` corresponds to the webhook's own `repository` field. Since the webhook signature is only verified against the organization derived from the payload's own `repository.owner.login` (attacker-controlled and self-consistent), an attacker who owns any GitHub repository can send a validly-signed status event whose `sha` happens to match a victim stack's tracked commit, causing Shipit to write a `Status` row against the victim's `Commit`/`Stack` and enqueue `ProcessMergeRequestsJob` for the victim's stack.

### Finding Description
The broken binding: the question's premise is `stack enqueued for merge processing == the stack named by the verified webhook's repository`. Tracing the code shows this equality does **not** hold — it is never enforced.

- `WebhooksController#verify_signature` derives `repository_owner` from the *incoming* payload's `repository.owner.login` and verifies the HMAC using `Shipit.github(organization: repository_owner)`'s webhook secret [1](#0-0) . This only proves the payload was signed by *some* organization the attacker controls (their own installed GitHub App/webhook secret for their own repo) — it says nothing about which `Commit`/`Stack` will be touched.
- `StatusHandler#process` ignores the payload's `repository` entirely and matches purely by `sha`: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [2](#0-1) . Unlike other handlers, it does not use the base `Handler#stacks` scoping method that filters by `Repository.from_github_repo_name(repository_name)` [3](#0-2) .
- `Commit#create_status_from_github!` calls `add_status` which creates a `Status` scoped to `stack_id` (the commit's own, pre-existing stack) [4](#0-3) .
- Inside `add_status`, on a state transition to `pending` or `success`, it calls `stack.schedule_merges`, i.e. `ProcessMergeRequestsJob.perform_later(self)` for the victim's own stack — with no re-check of the requesting repository [5](#0-4) [6](#0-5) .
- `Status` also fires `after_commit :schedule_continuous_delivery` on create, which calls `commit.schedule_continuous_delivery`, feeding into `ContinuousDeliveryJob` if the stack is continuous-deployment-enabled [7](#0-6) [8](#0-7) .

Attacker's exact request: a `POST /webhooks` with header `X-Github-Event: status`, body `{"sha": "<victim's tracked commit sha>", "state": "success", "repository": {"owner": {"login": "<attacker-org>"}}, ...}`, signed with the attacker's own valid webhook secret for `attacker-org`. Because `verify_signature` only checks the signature against the org named in the payload (which the attacker controls), this passes. `StatusHandler` then finds the pre-existing `Commit` row(s) with that `sha` regardless of which stack/repository they actually belong to, and creates a `Status` for it, triggering `ProcessMergeRequestsJob` for whichever stack owns that commit.

The precondition that the attacker can "reproduce" the victim's `head.sha` requires the attacker to get a git object with byte-identical content to the victim's commit into their own repository (git SHA1 is content-addressed and repo-independent), e.g. by forking/mirroring the exact same commit, or by exploiting a public commit shared across repos. This is a real but narrow precondition — it is not "any sha the attacker wants," but any sha that already exists as a `Commit` row in Shipit's DB and that the attacker can also get GitHub to emit a status event for (which requires that exact commit object to exist in a repository the attacker controls, e.g. forks of the same public repo, or cross-posted commits).

None of the listed guards prevent this: `verify_signature` validates payload authenticity for the attacker's own org, not repository binding; `drop_unhandled_event` only checks event type presence; there is no `ExplicitParameters` schema field for repository matching in `StatusHandler::params` (only `sha`, `state`, `description`, `target_url`, `context`, `created_at`, `branches`) [9](#0-8) ; `force_github_authentication`/`User#authorized?`/`require_permission!` are session-based user auth, irrelevant to unauthenticated webhook ingestion; `Stack`/`Repository` model validations don't scope incoming webhook processing by requesting org.

### Impact Explanation
An attacker can write a `Status` row against a victim's `Commit`/`Stack` they do not control, and cause `ProcessMergeRequestsJob` to run against the victim stack, which calls `merge_request.refresh!` (using the victim stack's `github_api` credentials against GitHub) and, if all checks pass, `merge_request.merge!` [10](#0-9) . This matches "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy, rollback or merge" (Critical). It also can trigger continuous deployment (`ContinuousDeliveryJob`) if the victim stack has that enabled. The blast radius is any Shipit tenant/stack whose tracked commit sha the attacker can reproduce in a repository they control, i.e. cross-tenant.

### Likelihood Explanation
Requires: (1) attacker owns/controls a GitHub repository with a configured Shipit webhook/app installation (any Shipit user with such basic GitHub access satisfies this per the threat model), (2) the victim stack has `merge_queue_enabled: true` with a pending `MergeRequest` whose `head.sha` the attacker can reproduce as a real git object in their own repo and for which GitHub will emit a `status` event, and (3) the merge request must actually pass `all_status_checks_passed?` for `merge!` to fire (otherwise the impact is limited to spurious `Status` rows and `ProcessMergeRequestsJob` enqueue/CD scheduling, still an unauthorized write against another tenant's data). Feasible primarily against commits whose content is public/shared (e.g. cherry-picks, common base commits, forks of the same upstream). Repeatable per matching sha; low cost (single signed HTTP request).

### Recommendation
In `StatusHandler#process`, scope commit lookup to the webhook's own repository, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or equivalently `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`, using the existing `Handler#stacks` (scoped via `Repository.from_github_repo_name(repository_name)`) so that a status event can only affect commits belonging to stacks whose repository matches the verified webhook's `repository.full_name`.

### Proof of Concept
```ruby
test "status webhook from an unrelated repository cannot enqueue merge processing for a victim stack" do
  victim_stack = shipit_stacks(:shipit) # merge_queue_enabled: true, has a pending MergeRequest
  victim_commit = shipit_commits(:second) # shares its sha with a commit the attacker can reproduce
  attacker_repository_full_name = "attacker-org/attacker-repo"

  payload = {
    "sha" => victim_commit.sha,
    "state" => "success",
    "context" => "ci/travis",
    "created_at" => 1.day.ago.to_formatted_s(:db),
    "repository" => { "full_name" => attacker_repository_full_name, "owner" => { "login" => "attacker-org" } }
  }

  request.headers["X-Github-Event"] = "status"
  Shipit.github(organization: "attacker-org").stubs(:verify_webhook_signature).returns(true)

  assert_enqueued_with(job: ProcessMergeRequestsJob, args: [victim_stack]) do
    post :create, body: payload.to_json, as: :json
  end
  # Expected (fixed) behavior: assert_no_enqueued_jobs(only: ProcessMergeRequestsJob)
  # because victim_stack's repository != attacker_repository_full_name
end
```
Both sides of the equality: `stack enqueued (victim_stack)` vs `stack named by the webhook's own repository (attacker's stack, or none)` — they diverge, confirming the vulnerability.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
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

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```

**File:** app/models/shipit/commit.rb (L379-384)
```ruby
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

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```

**File:** app/jobs/shipit/process_merge_requests_job.rb (L10-31)
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
```
