### Title
`StatusHandler#process` writes CI status to commits of any repository by bare SHA match, cross-repo, enabling forged ship/block on a production stack - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up affected commits with `Commit.where(sha: params.sha)` and applies the incoming GitHub status to every matching row in the database, without restricting to the repository that the webhook was authenticated for. Every other handler in the engine scopes work through `Handler#stacks`, which resolves `Repository.from_github_repo_name(repository_name)&.stacks` [1](#0-0) , but `StatusHandler` bypasses this and queries `Commit` directly by SHA alone [2](#0-1) .

### Finding Description
The broken binding is: `status.repository == commit.stack.repository` is **not** enforced, when it should be, for every `Status` created from a webhook.

Path: `POST /webhooks` → `WebhooksController#create` parses the raw JSON and dispatches purely on `X-Github-Event` header, calling `Shipit::Webhooks.for_event('status')` → `StatusHandler.call(params)` [3](#0-2) . Before dispatch, `verify_signature` validates the HMAC using `Shipit.github(organization: repository_owner)`, where `repository_owner` is read straight from the payload's `repository.owner.login` (or `organization.login`) [4](#0-3) . The `webhook_secret` used for HMAC verification is configured per organization/GitHub App installation, not per repository [5](#0-4) [6](#0-5) . This means any repository that shares the same GitHub App/organization installation as a victim stack produces a validly-signed webhook.

Once signature verification passes, `StatusHandler#process` does not re-check `payload['repository']['full_name']` at all — it fetches `Commit.where(sha: params.sha)` globally and calls `commit.create_status_from_github!(params)` on every match, across every stack in the installation [2](#0-1) . Because git commit SHAs are content-addressed, the same SHA can legitimately exist across forks/mirrors/other repositories within the same org that share commit history (e.g., a shared upstream commit cherry-picked or present in a fork), or the attacker's own repository could otherwise reuse it. Since `verify_signature` only checks organization-level authenticity — not that the specific `repository.full_name` in the payload matches the stack being mutated — any repo in that org can inject a status for a SHA that also exists on a victim's tracked repository/stack.

`create_status_from_github!` creates a `Status` row scoped to `commit.stack_id` (the commit's actual stack, i.e., the victim's) [7](#0-6) , which then drives `deployable?`/`blocked?` checks used for continuous deployment/merge gating, and can enqueue `ProcessMergeRequestsJob`/`ContinuousDeliveryJob` [8](#0-7) [9](#0-8) .

This contrasts directly with the base `Handler` class, which provides a `stacks` helper explicitly scoping to `Repository.from_github_repo_name(repository_name)` [1](#0-0)  — other handlers (e.g. push, pull_request) use this pattern, but `StatusHandler` does not use `stacks` or otherwise validate `payload['repository']` before writing.

None of the existing guards (`verify_signature`, `drop_unhandled_event`, `ExplicitParameters` schema in `StatusHandler`) check that the SHA's owning stack/repository matches the webhook's authenticated repository; the `ExplicitParameters` schema only validates types of `sha`/`state`/`context`, not repo ownership [10](#0-9) .

### Impact Explanation
A status/CI-check webhook authenticated for **repository A** (any repo sharing the same GitHub App/org installation as the victim) can create/flip a `Status` on **stack B**'s commit purely because the SHA matches, without any relationship between repo A and stack B's repository being checked. If stack B is configured as `ci/lint`-required and is a production environment, this forged status can satisfy required-status gating and trigger `ProcessMergeRequestsJob`/`ContinuousDeliveryJob`, causing an unauthorized ship (or conversely block a legitimate deploy by injecting a `failure`/`error` status). This is a cross-tenant/cross-repository record injection matching the "payload for one repository mutating another's stack/commit" Critical category.

### Likelihood Explanation
Exploitability depends on preconditions: the attacker needs a repository within the same GitHub App/organization installation as the victim's Shipit-tracked stack (shared `webhook_secret`), and a SHA collision/sharing scenario (fork of the same upstream history, shared monorepo submodule commit, or a repo the attacker controls that happens to share history with the victim repo — common in multi-repo orgs, forks, or migrated repos). This is plausible in real-world large-org Shipit deployments where many repositories share one GitHub App installation, which is a standard, documented configuration pattern for this engine (`Shipit.github(organization:)` is one config entry per org, not per repo). No Shipit session, token, or secret is required beyond a repo within the same org emitting a genuine GitHub status event (which any contributor with commit-status write access, or CI integration, on that repo can trigger).

### Recommendation
In `StatusHandler#process`, scope the commit lookup to the stacks belonging to the authenticated repository, mirroring the base `Handler#stacks` helper, e.g. restrict to `stacks.flat_map(&:commits).where(sha: params.sha)` or add `commit.stack.repository == Repository.from_github_repo_name(payload.dig('repository','full_name'))` before calling `create_status_from_github!`. Reject/ignore statuses whose payload repository does not match the commit's own stack repository.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb (conceptual, minitest)
test "status webhook from unrelated repo in same org must not mutate a foreign stack's commit" do
  victim_stack = shipit_stacks(:shipit) # production environment, requires 'ci/lint'
  shared_sha = 'deadbeefcafefeed0000000000000000000000'
  victim_commit = victim_stack.commits.create!(sha: shared_sha, ...)

  # Simulate: attacker controls "attacker/other-repo" in the SAME org/app installation
  payload = {
    'sha' => shared_sha,
    'state' => 'success',
    'context' => 'ci/lint',
    'repository' => { 'full_name' => 'attacker/other-repo', 'owner' => { 'login' => victim_org_login } }
  }

  # Binding under test: status.repository == commit.stack.repository
  assert_not_equal 'attacker/other-repo', victim_commit.stack.repository.full_name

  Shipit::Webhooks::Handlers::StatusHandler.call(payload)

  victim_commit.reload
  # FAILS today: status gets attached to victim_commit/victim_stack despite mismatched repository
  refute victim_commit.statuses.exists?(context: 'ci/lint'), "status should not apply cross-repository"
end
```

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** lib/shipit/github_app.rb (L44-57)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]

      oauth = (@config[:oauth] || {}).with_indifferent_access
      @oauth_id = oauth[:id]
      @oauth_secret = oauth[:secret]
      @oauth_teams = Array.wrap(oauth[:teams])
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
