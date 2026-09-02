### Title
Cross-tenant status webhook forgery escalates via `MergeRequest#merge!` into an unauthorized GitHub merge executed with the victim org's own credentials - ([File: app/models/shipit/merge_request.rb])

### Summary
`StatusHandler#process` writes commit statuses by matching `Commit.where(sha: params.sha)` with no check that the webhook's verified organization owns the stack/repository the matched commit belongs to. Because `MergeRequest#merge!` unconditionally uses `stack.github_api` (the token of the org that owns the *stack*, not the org that authenticated the webhook), a forged status accepted under an attacker-controlled org's signature can flip `all_status_checks_passed?` for a victim's merge request and cause `ProcessMergeRequestsJob` to call `stack.github_api.merge_pull_request` — a real GitHub API call authenticated with the victim org's own GitHub App/OAuth token against the victim's own repository.

### Finding Description
Binding claimed: `Shipit.github(organization: repository_owner_from_verified_webhook).token == token used to write commit.statuses for that request`. In reality the binding that governs the actual write is only `Commit#sha == params.sha`, with no scoping to `repository_owner`: [1](#0-0) 

`Commit` belongs to a `stack` [2](#0-1) , but `StatusHandler#process` never checks that the commit's `stack.repository` matches the org whose signature was verified in `WebhooksController#verify_signature` [3](#0-2) . Since git commit SHAs are content-addressed (function of tree/parent/author/committer/message/timestamps, all public on the victim's PR), an attacker can reproduce a bit-identical commit object in a repository they own, attach a "success" status to it via their own CI, and let GitHub deliver a status webhook that Shipit will correctly verify against the *attacker's own* org secret — yet the `Commit.where(sha:)` lookup matches the pre-existing victim commit row and calls `commit.create_status_from_github!(params)` on it, regardless of which org's signature validated the request.

Once the forged status exists, `ProcessMergeRequestsJob#perform(stack)` (scheduled periodically for the victim stack) calls `merge_request.refresh!` then checks `merge_request.all_status_checks_passed?` [4](#0-3) , which is satisfied by the forged status via `StatusChecker.new(head, head.statuses_and_check_runs, ...)` [5](#0-4) . It then invokes `merge_request.merge!`, which calls: [6](#0-5) 

Here `stack.github_api` always resolves to the token of the org that owns `stack` (the victim), independent of the org whose signature verified the webhook that produced the forged status. This confirms the question's binding is broken exactly as described: the actual GitHub call is executed with the victim's own credential and against the victim's own `stack.github_repo_name`, purely as a downstream consequence of a status forged under a different, attacker-controlled org's signature.

None of the existing guards close this gap: `verify_signature` only confirms the payload's claimed org matches a configured `Shipit.github_app`'s webhook secret [7](#0-6) ; it does not, and cannot, confirm that the commit sha referenced in a `status` event payload actually belongs to a stack owned by that same org. `StatusHandler`'s `ExplicitParameters` schema only validates payload shape (`sha`, `state`, etc.) [8](#0-7) , not repository ownership.

### Impact Explanation
Once a forged "success" status is accepted for the victim's PR head commit, the merge queue (`ProcessMergeRequestsJob`) will autonomously call `merge_pull_request` on GitHub using the **victim organization's own GitHub App/OAuth token**, merging the attacker's (or anyone's) PR into the victim's real repository without the PR actually satisfying the victim's configured CI/status requirements. This is an unauthorized deploy/merge executed with real, victim-owned GitHub credentials — squarely a Critical "unauthorized merge" / cross-tenant mutation per the stated impact categories. It is repeatable against any stack/repository whose commit SHA the attacker can reproduce in a repo they control, and is not limited to a single victim — any org onboarded to the same Shipit instance is exposed as long as merge-queue (`merge_queue_enabled`) is on for the target stack.

### Likelihood Explanation
Preconditions: the victim stack has `merge_queue_enabled` and a merge request in `pending` state with a known head SHA (visible on the public/forked PR); the attacker needs their own GitHub repository with a Shipit-recognized org/webhook configuration (so their own webhook signature verifies) and the ability to reproduce the victim's commit object's exact SHA (achievable since git commit hashing is purely a function of public commit metadata) and post a status for it via their own CI integration. No Shipit session, API token, or secret of the victim's is required — only a legitimately signed webhook from the attacker's own onboarded org. This makes the attack feasible and repeatable for any attacker with basic control over a GitHub repository with an active Shipit webhook.

### Recommendation
Scope `StatusHandler#process` (and any other handler that resolves records purely by `sha`) to commits belonging to stacks/repositories owned by the organization that authenticated the webhook (`repository_owner`), e.g. join through `stack.repository.owner` and filter `Commit.joins(:stack).where(sha: params.sha, shipit_stacks: { ... owner match ... })`, rejecting or ignoring statuses for shas outside the verified org's repositories.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb (new test)
test "status webhook verified for an unrelated org must not affect another org's commit" do
  victim_stack = shipit_stacks(:shipit) # owned by org 'shopify'
  victim_commit = victim_stack.commits.create!(sha: 'a' * 40, ...)

  # Attacker's webhook is verified under a DIFFERENT org ('attacker-org'),
  # yet references the victim's commit sha.
  payload = { "sha" => victim_commit.sha, "state" => "success", "context" => "ci/required" }
  StatusHandler.new(payload).process

  # Binding under test: org that verified signature ('attacker-org') != stack owner ('shopify')
  assert_not_equal 'attacker-org', victim_stack.repository.owner

  # Bug: the forged status is still written against the victim's commit.
  assert victim_commit.statuses.exists?(state: 'success', context: 'ci/required')
end

# test/jobs/shipit/process_merge_requests_job_test.rb (new test)
test "forged cross-org status causes merge_pull_request to run with victim's own github_api" do
  stack = shipit_stacks(:shipit) # merge_queue_enabled, owner 'shopify'
  merge_request = shipit_merge_requests(:pending_ready_to_merge)

  # Simulate cross-tenant forged status landing on merge_request.head via StatusHandler
  merge_request.head.statuses.create!(state: 'success', context: 'ci/required')

  Shipit.github(organization: 'shopify').api.expects(:merge_pull_request).with(
    stack.github_repo_name, merge_request.number, anything, has_entries(sha: merge_request.head.sha)
  )

  ProcessMergeRequestsJob.new.perform(stack)
end
```

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

**File:** app/models/shipit/commit.rb (L11-11)
```ruby
    belongs_to :stack
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

**File:** app/jobs/shipit/process_merge_requests_job.rb (L21-26)
```ruby
      merge_requests.select(&:pending?).each do |merge_request|
        merge_request.refresh!
        next unless merge_request.all_status_checks_passed?

        begin
          merge_request.merge!
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
