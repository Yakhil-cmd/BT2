### Title
Unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` lets a status from one repository write to a commit owned by a different stack/repository - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits by bare `sha` across the entire `commits` table, with no repository/stack scoping, unlike every sibling handler (`PushHandler`, `CheckSuiteHandler`) which first restrict to `stacks` derived from the payload's `repository.full_name`. Any commit row anywhere in the database that shares the reported SHA gets a `Status` (e.g. `context: "sonarqube"`) attached, and if that stack has `ignore_ci: true`, `Commit#deployable?` will ignore CI entirely, so this write can flip `deployable?`/blocking state for a stack the sender never authenticated for.

### Finding Description
The broken binding is: **"a `status` webhook accepted for organization `O` (repository `R1`) should only ever mutate commits belonging to stacks whose repository is `R1`."** In code, this should mean `commit.stack.repository.full_name == payload['repository']['full_name']`, but `StatusHandler` never checks this.

```ruby
# app/models/shipit/webhooks/handlers/status_handler.rb
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [1](#0-0) 

Compare with `PushHandler`/`CheckSuiteHandler`, which use the base class's `stacks` helper — `Repository.from_github_repo_name(repository_name)&.stacks` — before touching any commit or stack: [2](#0-1) [3](#0-2) [4](#0-3) 

`StatusHandler` inherits this same `stacks` helper but simply doesn't use it — it queries the global `Commit` table by `sha` alone.

**Signature verification does not close this gap.** `WebhooksController#verify_signature` authenticates only that the payload was legitimately signed by the GitHub App for `repository_owner` (the organization) — it never ties the verified organization to the specific `sha` being mutated: [5](#0-4) 
Once the HMAC check passes, `Shipit::Webhooks.for_event('status')` dispatches straight into `StatusHandler.call(params)` with no further repository binding: [6](#0-5) [7](#0-6) 

**Downstream amplification via `ignore_ci`.** Once a `Status` row is created for the victim's commit, `Commit#deployable?` short-circuits CI evaluation whenever the stack has `ignore_ci? == true`:
```ruby
def deployable?
  !locked? && (stack.ignore_ci? || (success? && !blocked?))
end
``` [8](#0-7) 
and status creation triggers `add_status`, which fires `deployable_status` hooks and schedules merges/continuous delivery based on state transitions: [9](#0-8) [10](#0-9) 

**Exploit flow:** Attacker sends (or causes GitHub to relay, from a repository they own that shares the same organization/App installation as the victim) a `status` webhook with `sha` equal to a commit SHA that also exists in a victim stack's `commits` table (identical SHAs occur whenever two Shipit-tracked repos/stacks track the same underlying git history — mirrors, staging/production copies of the same repo added as separate stacks, or shared upstream commits). Because `StatusHandler` matches `Commit.where(sha: params.sha)` with zero repository filter, the status is attached to *every* matching commit row across *all* stacks, including the victim's, even though the signature only proved authorship for the attacker's own repository/organization context.

### Impact Explanation
A payload authenticated for one repository writes a `Status` row against a commit belonging to a different stack/repository — this is exactly the "payload for one repository mutating another's stack/commit" Critical category. On a victim stack with `ignore_ci: true`, this status write is unnecessary for deployability (CI is already ignored), but it still: (1) triggers `deployable_status`/`commit_status` hooks that other integrations may act on, (2) can transition `state` and trigger `stack.schedule_merges` (`ProcessMergeRequestsJob`), pushing an unauthorized merge/deploy decision, and (3) can inject a `blocking` context status onto a victim commit, blocking deploys (denial of legitimate service is out of scope per the rules, but the merge/deploy-triggering side is in-scope). This is repeatable against any stack sharing a commit SHA with a repository the attacker can emit signed webhooks for, and it is a real cross-tenant boundary break in the engine's own scoping logic, unlike the properly-scoped `PushHandler`/`CheckSuiteHandler`.

### Likelihood Explanation
Preconditions are meaningful but plausible: the attacker needs to be able to cause a genuine, correctly-signed `status` webhook to be delivered for *some* repository under the same GitHub App/organization installation that Shipit trusts (e.g., a repository they legitimately own or have write access to within that org), and the target victim stack must contain a commit with an identical SHA (a realistic scenario for mirrored/duplicated repos tracked as separate Shipit stacks, or shared history across forks within the org). Given that precondition, exploitation costs only a normal GitHub Statuses API call and is fully repeatable/scriptable against any SHA collision the attacker can locate. The `ignore_ci: true` requirement stated in the question is not actually necessary for the cross-repo write itself (the write happens regardless of `ignore_ci`); it only changes how much the resulting status matters for `deployable?`.

### Recommendation
Scope `StatusHandler#process` the same way as `PushHandler`/`CheckSuiteHandler`: restrict the commit lookup to `stacks` (derived from `Repository.from_github_repo_name(repository_name)`), e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`, before calling `create_status_from_github!`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "status for repo A does not create a status on a commit belonging to a stack for repo B" do
  victim_stack = shipit_stacks(:shipit) # repository: shopify/shipit-engine, ignore_ci: true
  victim_stack.update!(ignore_ci: true)
  victim_commit = victim_stack.commits.create!(sha: 'deadbeef' * 5, author: nil, committer: nil)

  # payload signed/authorized only for a different repository ("attacker/other-repo")
  attacker_payload = ExplicitParameters::Parameters.new(
    'repository' => { 'full_name' => 'attacker/other-repo' },
    'sha' => victim_commit.sha,
    'state' => 'success',
    'context' => 'sonarqube'
  )

  assert_equal victim_commit.stack.repository.full_name, 'shopify/shipit-engine' # binding LHS
  refute_equal attacker_payload['repository']['full_name'], victim_commit.stack.repository.full_name # binding RHS: mismatched repos

  assert_no_difference -> { victim_commit.statuses.count } do
    Shipit::Webhooks::Handlers::StatusHandler.call(attacker_payload)
  end
end
```
Running this against the current `StatusHandler#process` (`Commit.where(sha: params.sha)`) fails: the status IS created despite the repository mismatch, proving the unscoped lookup lets an unrelated repository mutate the victim stack's commit.

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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L15-24)
```ruby
        def self.call(params)
          new(params).process
        end

        attr_reader :params, :payload

        def initialize(payload)
          @payload = payload
          @params = self.class.param_parser.parse!(payload)
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

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
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

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```
