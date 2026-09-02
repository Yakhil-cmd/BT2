### Title
Cross-repository Status forgery via `StatusHandler#process` (sha lookup without repository scoping) enables unauthorized merge of a pull request - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` resolves the target `Commit` purely by `sha`, ignoring the `repository` field present in every GitHub `status` webhook payload, and `Commit#create_status_from_github!` denormalizes `stack_id` from the matched `Commit` row rather than from the webhook's own repository. An attacker who can get a genuinely signed `status` webhook delivered to Shipit for *any* repository sharing the target sha (e.g. an identical commit object shared across a fork/rebase) can plant a `Status(stack_id: victim_stack.id, state: 'success')` row that `MergeRequest#all_status_checks_passed?` will treat as legitimate, driving `ProcessMergeRequestsJob` to call `stack.github_api.merge_pull_request` on the victim's PR.

### Finding Description
The broken binding, stated as an equality that the code assumes but never enforces:

`Status#stack_id (written by the webhook) == Stack.find_by(repository: webhook_payload['repository']).id`

What the code actually computes:

`Status#stack_id == Commit.where(sha: params.sha).first.stack_id`

with no reference at all to `params['repository']`.

Path:
1. `WebhooksController#verify_signature` only checks that the HMAC signature matches the GitHub App config keyed by `repository_owner` (`params.dig('repository','owner','login')`) — [1](#0-0) . This proves the payload came from *some* org/installation Shipit trusts, but says nothing about which specific repository the sha belongs to, and does not compare the payload's repository against the commit(s) it will touch.
2. `StatusHandler#process` fetches ALL `Commit` rows matching the sha across the entire database, with no `stack`/`repository` filter, and calls `create_status_from_github!` on each: [2](#0-1) .
3. `Commit#create_status_from_github!` writes a `Status` using `stack_id`, which is the *commit's own* `stack_id` attribute (denormalized at commit-creation time for the commit's actual stack), never the webhook payload's repository: [3](#0-2) .
4. `Status` itself only validates `belongs_to :stack` / `belongs_to :commit`, with no cross-check that the commit's repository matches any webhook-supplied repository: [4](#0-3) .
5. `MergeRequest#all_status_checks_passed?` builds a `StatusChecker` (a `Status::Group` subclass) from `head.statuses_and_check_runs`, which is simply `statuses + check_runs` for the commit row — it has no way to know a `Status` came from a different repository's webhook: [5](#0-4) [6](#0-5) .
6. `ProcessMergeRequestsJob#perform` calls `merge_request.refresh!` (which re-fetches real GitHub statuses via `stack.github_api.statuses`/`check_runs`, but does not delete the forged `Status` row) then checks `all_status_checks_passed?` and, if true, calls `merge_request.merge!`, which calls `stack.github_api.merge_pull_request`: [7](#0-6) [8](#0-7) [9](#0-8) .

Root cause: the `statuses` table denormalizes `stack_id` (added via `db/migrate/20161206104224_denormalize_stack_id_on_statuses.rb`, backfilled from `Commit.stack_id`), and the webhook write path (`StatusHandler` → `Commit#create_status_from_github!` → `Status.replicate_from_github!`) trusts that denormalized value blindly instead of deriving/validating it from the webhook's `repository` field. Existing guards (`verify_signature`, `drop_unhandled_event`, `ExplicitParameters` schema on `StatusHandler`) only validate the org-level signature and payload shape — none of them compare `params['repository']` to the `Commit`/`Stack` being updated, so the divergence described in the question is real and unguarded.

### Impact Explanation
A successful forged `status` webhook results in `stack.github_api.merge_pull_request` being invoked on a victim `Stack`'s pull request — a genuine unauthorized merge, matching the "Critical: unauthorized deploy, rollback or merge" category and "a payload for one repository mutating another's stack, commit ... " category. Repeatable against any victim `Stack`/`MergeRequest` for which the attacker can produce (or already share) a colliding sha for a pending head commit, and can get a status webhook delivered and correctly signed (i.e. their own repo is covered by the same GitHub App installation/org that Shipit trusts for the victim's stack — a realistic condition in any org where many repositories, including low-trust ones, are managed by one GitHub App installation). Blast radius spans every stack whose repository shares that GitHub App installation/org, since the flawed sha lookup is entirely unscoped by repository.

### Likelihood Explanation
Preconditions: (1) victim `MergeRequest#merge_status == 'pending'`, (2) `deploy_spec` `merge.require` includes a context the attacker can name in their forged payload, (3) attacker can get a `status` webhook delivered to Shipit with a valid signature for the org config Shipit uses for the victim stack — i.e., attacker controls (or has push/CI access to) some repository under that same trusted GitHub App installation, and (4) attacker can produce or reuse an identical commit sha shared with the victim's PR head (fork with identical tree/rebase-preserved commit — a well-known, easily engineered git property, not a hash break). Cost is low once these org-level conditions hold (no secrets, no privileged Shipit role needed), and the attack is repeatable per victim PR/stack sharing the same trusted installation.

### Recommendation
Scope the `Commit` lookup in `StatusHandler#process` (and analogous check-run/check-suite handlers) by the repository named in the webhook payload, not by sha alone — e.g. resolve the `Stack`/`Repository` from `params['repository']['full_name']` first, then only update commits belonging to that stack/repository, and reject or ignore the event if it doesn't match any commit's own stack repository. Additionally, `Status`/`Commit` writes originating from GitHub webhooks should validate that the webhook's repository matches `commit.stack.repository` before writing.

### Proof of Concept
Minitest plan (models/webhooks, no live GitHub):
1. Create two `Stack`/`Repository` fixtures, `victim_stack` (`org/victim-repo`) and `attacker_repo` (`org/attacker-repo`), both configured under the same trusted GitHub App org so `verify_signature` passes for both.
2. Create a pending `MergeRequest` on `victim_stack` whose `head` `Commit` has `sha = SHARED_SHA` and no existing `Status` for the required context (`deploy_spec` `merge.require: ['ci/build']`).
3. Also create (or reuse) a `Commit` row with the same `sha = SHARED_SHA` but `stack_id = attacker_repo.stack.id` (simulating the sha-collision precondition).
4. POST to `/webhooks` with `X-Github-Event: status`, a valid signature for `attacker_repo`'s org, and body `{ "sha": SHARED_SHA, "state": "success", "context": "ci/build", "repository": { "full_name": "org/attacker-repo", "owner": {"login": "org"} } }`.
5. Assert: `Shipit::Status.where(stack_id: victim_stack.id, commit_id: victim_head.id, context: 'ci/build', state: 'success').exists?` is `true` even though no CI ever posted to `org/victim-repo`.
6. Stub `victim_stack.github_api` and set `expects(:merge_pull_request)` as a mock expectation; call `ProcessMergeRequestsJob.new.perform(victim_stack)`.
7. Assert the mock expectation is satisfied (i.e. `merge_pull_request` was called) — proving the forged cross-repository status alone (with no legitimate victim-repo CI status ever posted) drove an unauthorized merge.

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

**File:** app/models/shipit/status.rb (L4-19)
```ruby
  class Status < Record
    include Common
    include DeferredTouch

    STATES = %w[pending success failure error].freeze
    enum :state, STATES.zip(STATES).to_h

    belongs_to :stack, required: true
    belongs_to :commit, required: true

    deferred_touch commit: :updated_at

    validates :state, inclusion: { in: STATES, allow_blank: true }, presence: true

    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
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

**File:** app/models/shipit/merge_request.rb (L239-245)
```ruby
    def refresh!
      update!(github_pull_request: stack.github_api.pull_request(stack.github_repo_name, number))
      head.refresh_statuses!
      head.refresh_check_runs!
      fetched! if fetching?
      @comparison = nil
    end
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
