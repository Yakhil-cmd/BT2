### Title
Cross-tenant Status forgery via unscoped `Commit.where(sha:)` in `StatusHandler` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits by `sha` alone across the entire database, with no scoping to the repository/organization that produced the signed webhook payload. Since `WebhooksController#verify_signature` only proves the payload came from the org named in `params['repository']['owner']['login']`, an attacker who owns any repo (org A) can send a validly-signed `status` event whose `sha` collides with a commit tracked under an unrelated org B's stack, causing a `Status` row to be written against org B's commit/stack.

### Finding Description
The binding that must hold is: **organization whose `webhook_secret` verified the request body (`repository_owner` used in `Shipit.github(organization: repository_owner)`) == organization owning every `Commit`/`Stack` row the handler subsequently mutates**.

Tracing the path:
- `WebhooksController#create` parses `request.raw_post` into `params` and dispatches to handlers keyed only by `X-Github-Event`: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [1](#0-0) .
- `verify_signature` resolves `repository_owner` from `params.dig('repository', 'owner', 'login')` (or `organization.login`) and validates the signature against `Shipit.github(organization: repository_owner)`'s `webhook_secret` [2](#0-1) [3](#0-2) . This only proves the *body* was signed by org A's secret; it says nothing about which `Commit`/`Stack` rows the handler may touch afterward.
- The base `Handler` class exposes a `stacks` helper that correctly scopes lookups to the repository named in the payload: `Repository.from_github_repo_name(repository_name)&.stacks || Stack.none`, where `repository_name` is `payload.dig('repository', 'full_name')` [4](#0-3) . `CheckSuiteHandler` uses this correctly: `stacks.where(branch: params.check_suite.head_branch).each { |stack| stack.commits.where(sha: ...) }` [5](#0-4) .
- `StatusHandler#process`, however, never calls `stacks` or checks `repository_name` at all — it queries globally: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [6](#0-5) . Any `Commit` row in the whole installation sharing that `sha` — regardless of which org/stack it belongs to — gets a `Status` created.
- `create_status_from_github!` delegates straight into `Status.replicate_from_github!(stack_id, ...)` with the target commit's own `stack_id`, so the write lands on whatever stack actually owns that commit row, not the attacker's stack [7](#0-6) [8](#0-7) .
- `Status` creation is not a no-op side effect: `after_create :enable_ci_on_stack` and `after_commit :schedule_continuous_delivery` fire on the victim stack [9](#0-8) , and `Commit#add_status`/`create_status_from_github!` path can enqueue `ProcessMergeRequestsJob` and toggle CI/deploy-eligibility state as shown by webhook-transition tests [10](#0-9) .

**Attacker request**: Attacker owns `orgA/repo` and holds `orgA`'s legitimate `webhook_secret` (since it is their own repo's webhook). They send `POST /webhooks` with header `X-Github-Event: status`, a signature valid for org A's secret, and a body `{"repository": {"owner": {"login": "orgA"}, "full_name": "orgA/repo"}, "sha": "<sha colliding with a commit in orgB's stack>", "state": "success", ...}`. `verify_signature` passes because the signature genuinely matches org A's secret for the literal bytes of this body — the check never inspects whether the `sha` inside belongs to org A. `StatusHandler` then finds and writes a `Status` on the org B commit.

Existing guards checked and why they don't prevent this: `drop_unhandled_event` only checks the event type is registered, not payload/repo consistency [11](#0-10) ; the `ExplicitParameters` schema for `StatusHandler` only validates types (`sha` is a `String`) and imposes no repository/ownership constraint [12](#0-11) ; `verify_signature`/`GithubApp#verify_webhook_signature` verify byte-for-byte HMAC of the whole body against org A's secret only — it cannot and does not verify semantic content like which commits are safe to touch [13](#0-12) .

### Impact Explanation
A `sha` collision (real collisions require identical 40-hex sha values across two independently-tracked commits, which in practice requires either coincidental short-sha reuse across unrelated small repos, or an attacker deliberately crafting/choosing a commit whose sha happens to match one already tracked in a victim stack, e.g. via fork/rebase tricks producing identical tree+parent+committer metadata) lets an attacker with only their own repo's legitimate webhook secret write a `Status` (CI/build result) onto a completely unrelated organization's commit/stack. This can flip a victim commit's `Commit#state` (e.g., force `success`), triggering `enable_ci_on_stack`, `ProcessMergeRequestsJob`, and — critically — continuous-delivery deploy triggers on stacks with `continuous_deployment: true`, per the deploy-trigger logic exercised in `commits_test.rb` [14](#0-13) . This is a cross-tenant write into another organization's Commit/Stack data driven purely by an authenticated-for-A payload, matching the "payload for one repository mutating another's stack/commit" Critical category.

### Likelihood Explanation
Preconditions: attacker needs a repo (and thus webhook secret) under any org configured in Shipit, and needs a `sha` value that also exists as a tracked `Commit` row under a victim stack. Exact 40-character SHA-1 collision across arbitrary repos is not attacker-controlled at will, so exploitability in practice depends on Shipit's deployment tracking short/predictable commit shas, forks that share commit history with the victim's tracked branch (a very plausible real-world scenario — e.g. a contributor forking the victim repo, whose fork shares actual commit SHAs with the upstream repo, and then registering their fork as a separate, attacker-controlled repo/org in Shipit), or an attacker able to observe/guess victim commit shas (commit shas are often public on GitHub). Given forks legitimately share SHAs with upstream, this scenario is realistically achievable without needing a cryptographic collision. The bug is deterministic and repeatable against any victim commit sha the attacker can name, once identified.

### Recommendation
Scope `StatusHandler#process` to the repository named in the payload, mirroring `CheckSuiteHandler`: replace `Commit.where(sha: params.sha)` with a lookup restricted to `stacks.where(...)`-derived commits (i.e., `stacks.flat_map(&:commits).select { |c| c.sha == params.sha }` or `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`), so a status payload can only mutate commits belonging to the repository that authenticated the webhook.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb
test ":status payload for org A must not create a Status on org B's commit sharing the same sha" do
  GithubHook.any_instance.stubs(:verify_signature).returns(true) # simulates a *valid* org-A secret verification
  request.headers['X-Github-Event'] = 'status'

  org_b_commit = shipit_commits(:cyclimse_first) # belongs to a different stack/org than :shipit
  colliding_sha = org_b_commit.sha

  body = {
    'sha' => colliding_sha,
    'state' => 'success',
    'context' => 'ci/attacker',
    'repository' => { 'owner' => { 'login' => 'shopify' }, 'full_name' => 'shopify/shipit' }, # org A's repo
    'branches' => [{ 'name' => 'master' }]
  }.to_json

  assert_no_difference -> { org_b_commit.statuses.count } do
    post :create, body: body, as: :json
  end
end
```
Before the fix, this assertion fails: `org_b_commit.statuses.count` increases by 1 even though the request was only authenticated (signature-verified) for `shopify/shipit`, demonstrating the broken binding `repository_owner-that-signed != organization-owning-mutated-commit`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L19-22)
```ruby
    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-16)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```

**File:** app/models/shipit/status.rb (L23-33)
```ruby
    class << self
      def replicate_from_github!(stack_id, github_status)
        find_or_create_by!(
          stack_id:,
          state: github_status.state,
          description: github_status.description,
          target_url: github_status.target_url,
          context: github_status.context,
          created_at: github_status.created_at
        )
      end
```

**File:** test/models/commits_test.rb (L245-252)
```ruby
    test "updating state to success skips deploy when stack has CD but a deploy is in progress" do
      @stack.reload.update(continuous_deployment: true)
      @stack.trigger_deploy(@commit, @commit.committer)

      assert_no_difference "Deploy.count" do
        @commit.statuses.create!(stack_id: @stack.id, state: 'success', context: 'ci/travis')
      end
    end
```

**File:** test/models/commits_test.rb (L763-777)
```ruby
    test "#add_status schedule a MergeMergeRequests job if the commit transition to `pending` or `success`" do
      commit = shipit_commits(:second)
      github_status = OpenStruct.new(
        state: 'success',
        description: 'Cool',
        context: 'metrics/coveralls',
        created_at: 1.day.ago.to_formatted_s(:db)
      )

      assert_equal 'failure', commit.state
      assert_enqueued_with(job: ProcessMergeRequestsJob, args: [@commit.stack]) do
        commit.create_status_from_github!(github_status)
        assert_equal 'success', commit.state
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
