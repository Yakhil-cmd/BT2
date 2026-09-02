### Title
Cross-tenant forged GitHub `status` webhook lets org-attacker inject a CI status onto org-victim's commit, triggering an unauthorized deploy - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`WebhooksController#verify_signature` derives the signing organization solely from `payload['repository']['owner']['login']` and validates the HMAC against that organization's own `webhook_secret` [1](#0-0) [2](#0-1) . `Shipit::Webhooks::Handlers::StatusHandler#process` then looks up the commit by `sha` **globally, with no scoping to the verified organization or repository**, and writes a status onto whatever commit it finds [3](#0-2) . This breaks the required binding `verifying_org == organization_owning(Commit#sha)`, letting an attacker who controls their own onboarded organization forge a `success` status on a victim organization's commit, which can flip `Stack#deployable?` and fire an unauthorized deploy.

### Finding Description
Required binding: `repository_owner_verified_by_signature == organization_that_owns(Commit.where(sha: params.sha))`. This binding is never enforced.

Path:
1. `WebhooksController#verify_signature` computes `repository_owner` from the payload's `repository.owner.login` (or `organization.login`), fetches `Shipit.github(organization: repository_owner)` and calls `github_app.verify_webhook_signature(signature, raw_post)` [1](#0-0) . `verify_webhook_signature` is a pure per-organization HMAC-SHA1 check against that organization's configured `webhook_secret` [4](#0-3) . If the attacker administers/onboards their own organization `org-attacker` into this Shipit instance, they legitimately know `org-attacker`'s webhook secret (it is configured by whoever sets up that org's webhook/App, i.e., the org owner), so they can produce a **valid** signature for any payload as long as `repository.owner.login == "org-attacker"`.
2. Once signature verification succeeds, `Shipit::Webhooks.for_event('status')` dispatches to `StatusHandler#process`, which runs `Commit.where(sha: params.sha).each { |c| c.create_status_from_github!(params) }` [3](#0-2) . This is a table-wide lookup by `sha` with **no filter on repository or organization** — it matches any commit in the database, including ones belonging to `org-victim`'s stack.
3. The attacker's exact request: `POST /webhooks` with header `X-Github-Event: status`, body `{"repository":{"owner":{"login":"org-attacker"}}, "sha":"<org-victim's real commit sha>", "state":"success", "context":"ci/forged"}`, signed with `X-Hub-Signature: sha1=<HMAC(org-attacker secret, body)>`.
4. `create_status_from_github!` persists a `Status` for the victim's commit under the victim's own stack, and creating a passing status is exactly the trigger the test suite documents for kicking off continuous deployment: `@commit.statuses.create!(state: 'success', ...)` directly enqueues `ContinuousDeliveryJob` [5](#0-4) . The underlying model logic is `Commit#schedule_continuous_delivery`, which checks `deployable? && stack.continuous_deployment? && stack.deployable?` before enqueuing `ContinuousDeliveryJob.perform_later(stack)` [6](#0-5) . `ContinuousDeliveryJob#perform` then unconditionally proceeds to `stack.trigger_continuous_delivery` if the stack is in continuous-deployment mode and not occupied [7](#0-6) .

Why existing guards fail: `verify_signature`'s only check is HMAC validity against the org named in the payload's `repository.owner.login`; it never cross-references that organization against the repository/stack that actually owns the commit being mutated. `ExplicitParameters` in `StatusHandler` only validates the shape of the payload (`sha`, `state`, etc. as strings) [8](#0-7) , not ownership. No model-level check in `Commit` or `Status` restricts which organization may write a status for a given commit.

### Impact Explanation
An attacker who legitimately controls one organization onboarded into a shared/multi-tenant Shipit instance can forge a passing (or failing) CI status on any commit sha in any other tenant's stack, without ever building that commit or possessing that commit's real CI results. If the victim stack has `continuous_deployment: true`, this can directly cause an **unauthorized deploy** of that commit — matching the Critical category "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy." The blast radius spans all tenants sharing the Shipit host, since the `Commit.where(sha:...)` lookup is completely unscoped by organization.

### Likelihood Explanation
Preconditions: (1) the Shipit instance is multi-tenant, hosting at least one organization the attacker legitimately controls (`org-attacker`) alongside the victim's organization; (2) the attacker knows a real commit sha belonging to the victim's stack (trivial for public repositories, or any repo the attacker can read); (3) the victim stack has `continuous_deployment` enabled and no other blocking condition (`required_statuses`, lock, occupied task, etc.). Attacker cost is a single signed HTTP POST, fully repeatable against any known sha in any victim stack on the same instance.

### Recommendation
In `StatusHandler#process` (and analogous handlers), reject or scope the commit lookup to commits whose `stack.repository` (or `github_repo_name`) matches the `repository.owner.login`/`repository.full_name` verified during signature validation, e.g. `Commit.where(sha: params.sha).where(stack: Stack.by_repository_owner(repository_owner))`, or pass the verified repository owner from the controller into the handler and enforce `commit.stack.repository.owner == verified_repository_owner` before calling `create_status_from_github!`.

### Proof of Concept
```ruby
test "StatusHandler must not write a status for a commit owned by another organization" do
  victim_stack = shipit_stacks(:shipit)
  victim_stack.update!(continuous_deployment: true)
  victim_commit = victim_stack.commits.last
  victim_commit.statuses.destroy_all

  attacker_org = 'org-attacker'
  Shipit.stubs(:github).with(organization: attacker_org).returns(
    Shipit::GitHubApp.new(attacker_org, webhook_secret: 'attacker-secret')
  )

  payload = {
    'repository' => { 'owner' => { 'login' => attacker_org } },
    'sha' => victim_commit.sha,
    'state' => 'success',
    'context' => 'ci/forged'
  }
  body = payload.to_json
  signature = 'sha1=' + OpenSSL::HMAC.hexdigest('sha1', 'attacker-secret', body)

  assert_no_difference('victim_commit.statuses.count') do
    post shipit.webhooks_path,
      params: body,
      headers: { 'X-Github-Event' => 'status', 'X-Hub-Signature' => signature, 'Content-Type' => 'application/json' }
  end

  refute victim_stack.reload.deployable?
end
```
Binding assertion: before, `verifying_org = "org-attacker"` and `organization_owning(victim_commit.sha) = victim_stack.repository.owner`, which differ. Current (buggy) code allows `create_status_from_github!` to run and `victim_commit.statuses.count` to increase despite the mismatch, and `victim_stack.deployable?` can become `true`, enqueuing `ContinuousDeliveryJob`.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** test/models/commits_test.rb (L233-243)
```ruby
    test "updating state to success triggers new deploy when stack has continuous deployment" do
      @stack.reload.update(continuous_deployment: true)
      @stack.deploys.destroy_all

      assert_difference "Deploy.count" do
        assert_enqueued_with(job: ContinuousDeliveryJob, args: [@stack]) do
          @stack.commits.last.statuses.create!(stack_id: @stack.id, state: 'success', context: 'ci/travis')
        end
        ContinuousDeliveryJob.new.perform(@stack)
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

**File:** app/jobs/shipit/continuous_delivery_job.rb (L10-21)
```ruby
    def perform(stack)
      return unless stack.continuous_deployment?

      # If there is a schedule defined for this stack, make sure we are within a
      # deployment window before proceeding.
      return if stack.continuous_delivery_schedule && !stack.continuous_delivery_schedule.can_deploy?

      # checks if there are any tasks running, including concurrent tasks
      return if stack.occupied?

      stack.trigger_continuous_delivery
    end
```
