This confirms the vulnerability. The `Handler` base class provides a `stacks` helper that scopes to the repository named in the payload via `Repository.from_github_repo_name(repository_name)&.stacks` [1](#0-0) , and `PushHandler`/`CheckSuiteHandler` correctly use it to restrict effects to stacks belonging to the repository named in the payload [2](#0-1) [3](#0-2) . `StatusHandler#process`, however, never calls `stacks` or filters by repository at all — it queries `Commit.where(sha: params.sha)` globally across the entire `commits` table and mutates every matching row [4](#0-3) .

### Title
Cross-organization commit status forgery via unscoped `Commit.where(sha:)` lookup - (`app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits solely by `sha`, with no filter on `repository`/`stack`, while sibling handlers (`PushHandler`, `CheckSuiteHandler`) correctly scope via `Handler#stacks`, which resolves `Repository.from_github_repo_name(payload.dig('repository','full_name'))`. Any organization whose GitHub App is registered with Shipit can send a validly-signed `status` webhook for its own repository and, if any other organization's tracked stack happens to have a `Commit` row with the identical `sha`, mutate that unrelated commit's `statuses`, corrupting the cross-tenant CI/deploy state.

### Finding Description
Binding claimed: `webhook_secret owner (org A)` == `organization owning the Stack/Commit mutated`. Trace:

1. `WebhooksController#create` parses the raw JSON body and dispatches to `Shipit::Webhooks.for_event(event)` handlers [5](#0-4) .
2. `verify_signature` resolves the GitHub App purely from `repository_owner` (`params.dig('repository','owner','login')`) and calls `github_app.verify_webhook_signature` [6](#0-5) . This only proves the payload was signed by org A's `webhook_secret` — it says nothing about which `Commit`/`Stack` rows the handler is permitted to touch afterward.
3. `StatusHandler#process` ignores the `repository` field of the payload entirely and executes `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [4](#0-3) . `sha` is a 40-hex-char string with no `stack_id`/`repository_id` component, so if org B's stack (tracking, e.g., a shared upstream commit or one it forked before diverging) has a `Commit` row with the same `sha`, that row is matched and mutated too.
4. `create_status_from_github!` → `add_status` writes a new `Status`, updates `previous_status`/`new_status`, and can fire `Hook.emit(:commit_status, ...)`, `Hook.emit(:deployable_status, ...)`, and `stack.schedule_merges` [7](#0-6) . If org B's stack has `continuous_deployment: true`, a spoofed `success` status can enqueue an actual deploy for org B's stack, entirely from a request authenticated only against org A's secret.

Guards checked and found insufficient for this class: `verify_signature`/`GitHubApp#verify_webhook_signature` only authenticate that org A signed the payload with org A's secret [8](#0-7) ; they do not — and structurally cannot — assert anything about which `Stack`/`Commit` the *handler* subsequently mutates, since that check happens downstream inside each handler's own query logic. `ExplicitParameters` (`params do ... end` block in `StatusHandler`) validates the presence/shape of `sha`, `state`, etc., but not repository ownership [9](#0-8) . The `Handler#stacks` helper exists precisely to close this gap by resolving `Repository.from_github_repo_name(payload.dig('repository','full_name'))`, but `StatusHandler` never calls it [1](#0-0) .

### Impact Explanation
A `status` webhook validly signed by org A's `webhook_secret` (for org A's own repository) mutates `Status`/`Commit` rows belonging to *any* stack across *any* organization that has a `Commit` with the matching `sha` — matching "a payload for one repository mutating another's stack/commit" (Critical). Repeatable per request against any sha value known or guessable by the attacker (e.g., commits from a shared upstream/fork ancestry, or any sha string at all if the attacker can also predict/control an existing commit sha in the target stack). If the victim stack has `continuous_deployment` enabled, this becomes an unauthorized deploy trigger (`stack.schedule_merges`, `ContinuousDeliveryJob`), which is explicitly listed as Critical impact.

### Likelihood Explanation
Preconditions: attacker must control (or already operate) a GitHub App/organization registered in Shipit's multi-org `github:` config with its own valid `webhook_secret` — this is a normal, low-cost setup for any onboarded org, not a privileged secret belonging to the victim. No knowledge of org B's `webhook_secret` is needed. The only nontrivial requirement is that org B's `Commit.sha` value be known/guessable by the attacker, which is realistic for forked/shared-upstream repositories (the scenario the question describes) or via commit shas leaked through PRs, forks, or public repos. Cost per attempt is a single signed HTTP POST to `/webhooks`; fully repeatable and scriptable against arbitrary shas.

### Recommendation
Scope `StatusHandler#process` to the reporting repository, mirroring `PushHandler`/`CheckSuiteHandler`: use `stacks` (derived from `Repository.from_github_repo_name(payload.dig('repository','full_name'))`) and only update `Commit` rows belonging to those stacks, e.g. `stacks.each { |stack| stack.commits.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) } }`, instead of the global `Commit.where(sha: params.sha)`.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (minitest addition)
test ":status webhook for org A repository must not mutate org B's commit with same sha" do
  shared_sha = "a" * 40

  repo_a = Shipit::Repository.create!(owner: "org-a", name: "repo-a")
  repo_b = Shipit::Repository.create!(owner: "org-b", name: "repo-b")
  stack_a = Shipit::Stack.create!(repository: repo_a, environment: "production", branch: "master")
  stack_b = Shipit::Stack.create!(repository: repo_b, environment: "production", branch: "master")
  commit_a = stack_a.commits.create!(sha: shared_sha, message: "m", author: shipit_users(:walrus), committer: shipit_users(:walrus), authored_at: Time.now, committed_at: Time.now)
  commit_b = stack_b.commits.create!(sha: shared_sha, message: "m", author: shipit_users(:walrus), committer: shipit_users(:walrus), authored_at: Time.now, committed_at: Time.now)

  request.headers['X-Github-Event'] = 'status'
  body = {
    sha: shared_sha, state: 'success', context: 'ci', target_url: 'https://ci.example.com',
    repository: { full_name: "org-a/repo-a", owner: { login: "org-a" } }
  }.to_json

  GithubHook.any_instance.stubs(:verify_signature).returns(true) # simulate org A's valid signature only

  post :create, body:, as: :json

  assert_equal 1, commit_a.reload.statuses.count   # binding holds for org A: authenticated owner == mutated owner
  assert_equal 0, commit_b.reload.statuses.count    # binding must hold for org B too: currently FAILS (statuses.count == 1)
end
```
Before the fix, `commit_b.statuses.count` is `1` (vulnerable — org B's commit mutated by org A's signed webhook). After scoping `StatusHandler` via `stacks`/`repository`, it is `0`.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```
