### Title
StatusHandler#process writes GitHub status onto ANY tenant's Commit matched only by `sha`, with no repository/stack scoping check against the payload's `repository` field - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` resolves the target `Commit` purely by `Commit.where(sha: params.sha)`, without any join or filter on `stack`/`repository`, unlike its sibling handlers. Because `WebhooksController#verify_signature` only proves that the request body was signed by *some* `GithubApp` matching the `repository.owner.login` named in that body, and `StatusHandler` never re-checks that the commit it mutates belongs to a stack under that same repository, an attacker holding a legitimate `webhook_secret` for their own GitHub App/org can forge a `status` event naming their own repo, but targeting a `sha` value that happens to belong to a completely different tenant's stack, and have `create_status_from_github!` executed against it.

### Finding Description
Binding claimed: `org whose webhook_secret verified the body == org owning the mutated Commit row`.

Trace:
- `WebhooksController#verify_signature` picks the verifying `GitHubApp` from `repository_owner`, which is read straight out of the unverified JSON body: `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [1](#0-0) . It then calls `github_app.verify_webhook_signature(signature, raw_post)` using that app's `webhook_secret` [2](#0-1) . This only proves "the sender knows *some* org's secret and named that org in the body" - it does not prove the payload's `sha`/commit actually belongs to that org's repositories.
- After signature success, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the full raw params (including `repository`) to the handler [3](#0-2) .
- `StatusHandler`'s `params` schema requires only `sha`, `state`, and optional description/target_url/context/created_at/branches - it never even declares/requires a `repository` field [4](#0-3) .
- `process` does: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [5](#0-4) . This is a global, unscoped lookup across every `Stack`/`Repository`/tenant in the database.
- Compare this to every other handler that mutates state: `CheckSuiteHandler` scopes through `stacks.where(branch: ...)` where `stacks` is defined in the base `Handler` as `Repository.from_github_repo_name(repository_name)&.stacks || Stack.none`, i.e., scoped by the payload's own `repository.full_name` [6](#0-5) [7](#0-6) . Pull-request handlers likewise resolve a `repository` via `Repository.from_github_repo_name(params.repository.full_name)` before touching any `PullRequest`/`Stack` row [8](#0-7) . `StatusHandler` is the one handler that omits this scoping entirely.
- `create_status_from_github!` calls `add_status`, which can trigger `stack.schedule_merges` when the injected state is `pending` or `success` [9](#0-8) , and continuous-deployment tests confirm that a `success` status transition enqueues a real `ContinuousDeliveryJob` [10](#0-9) .

Attack: attacker owns GitHub App "AttackerApp" installed on `attacker/repo`, with its own valid `webhook_secret`. Attacker learns (or guesses, e.g. via public commit history, PR pages, or a public/openly-browsable Shipit UI) the 40-hex `sha` of a commit belonging to victim tenant's stack (e.g. `victim/repo`). Attacker POSTs to `/webhooks` with `X-Github-Event: status`, body `{"sha": "<victim_sha>", "state": "success", "repository": {"owner": {"login": "attacker"}}}`, signed with `sha1=HMAC(AttackerApp.webhook_secret, raw_post)`. `verify_signature` resolves `Shipit.github(organization: "attacker")`, verifies successfully (attacker legitimately owns this secret), and `StatusHandler#process` finds `Commit.where(sha: victim_sha)` - which belongs to the victim's stack - and writes a forged status onto it, potentially triggering `schedule_merges`/continuous deployment for the victim stack.

Existing guards do not stop this: `verify_signature` only checks the signature against the org named in the (attacker-controlled) body, it never cross-checks that org against the resolved `Commit`'s repository; `ExplicitParameters` schema for `StatusHandler` never requires/validates `repository`; there is no `require_permission!`, `stacks` scope, or model validation invoked in this handler's `process`.

### Impact Explanation
An attacker with any legitimately-obtained `webhook_secret` for their own installed GitHub App can write arbitrary `Status` rows (state/description/target_url/context/created_at) onto any `Commit` in the entire Shipit instance, across tenants, keyed only by a public-ish `sha` value. Because status transitions can trigger `stack.schedule_merges` and continuous-deployment (`ContinuousDeliveryJob`), this is not merely a data-integrity issue but can cause an unauthorized deploy/merge decision for a victim's stack. This matches the Critical category "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy". It is fully repeatable against any commit sha the attacker can learn, for any tenant repository configured in the same Shipit instance.

### Likelihood Explanation
Preconditions: the attacker must operate their own GitHub App/org already registered in the Shipit host's `github:` config (i.e., they are a legitimate, if unprivileged, tenant of the multi-org Shipit instance) and must know a target commit `sha` from a different tenant's stack - shas are not secret and are commonly discoverable (PR pages, git history, CI logs, public Shipit dashboards). No Shipit session, API token, or other tenant's secret is required. This is a low-cost, single-HTTP-request, fully repeatable attack once the attacker holds any valid `webhook_secret` for their own app.

### Recommendation
In `StatusHandler`, require and validate `repository.full_name` in the `params` schema, then scope the lookup through the repository/stack relationship exactly like `CheckSuiteHandler` does, e.g. `stacks.each { |stack| stack.commits.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) } }`, using the base `Handler#stacks` (which resolves via `Repository.from_github_repo_name(payload.dig('repository','full_name'))`) so that only commits belonging to stacks under the signing organization's own repository can be mutated.

### Proof of Concept
Minitest plan (in `test/controllers/webhooks_controller_test.rb` style, using two GithubApp fixtures with distinct `webhook_secret`s configured in `Shipit.github`):

```ruby
test ":status payload signed by org A cannot mutate a commit belonging to org B's stack" do
  # Arrange: org A ("attacker") and org B ("victim") each have distinct GithubApp webhook_secret configured.
  attacker_secret = Shipit.github(organization: 'attacker-org').webhook_secret
  victim_commit = shipit_commits(:victim_org_commit) # belongs to a stack whose Repository owner is "victim-org"

  body = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'repository' => { 'owner' => { 'login' => 'attacker-org' } }
  }.to_json
  signature = "sha1=#{OpenSSL::HMAC.hexdigest('sha1', attacker_secret, body)}"

  @request.headers['X-Github-Event'] = 'status'
  @request.headers['X-Hub-Signature'] = signature

  # Binding under test: org whose secret verified the body ('attacker-org')
  #   should equal org owning the mutated row (victim_commit.stack.repository.owner => 'victim-org').
  # Before: no status exists for victim_commit with state 'success'.
  assert_not_equal 'success', victim_commit.reload.status.state

  assert_difference -> { victim_commit.statuses.count }, 1 do
    post :create, body:, as: :json
  end
  assert_response :ok

  # After: victim_commit now has a forged 'success' status despite the payload
  # being signed only by 'attacker-org', proving the bound orgs diverged.
  assert_equal 'success', victim_commit.reload.status.state
end
```

If this test passes (write succeeds and `victim_commit`'s status changes), it proves `StatusHandler` performs no repository-scoping check downstream of signature verification.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-54)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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
