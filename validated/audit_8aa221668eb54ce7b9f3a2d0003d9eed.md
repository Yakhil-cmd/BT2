### Title
`Shipit::Webhooks::Handlers::StatusHandler#process` forges CI status on any repository's commit by SHA collision, enabling unauthorized deploy - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves the target `Commit` purely by `sha` (`Commit.where(sha: params.sha)`), never checking that the webhook payload's `repository.full_name` matches the `Stack`/`Repository` the matched `Commit` actually belongs to. Because git SHA1s are content-addressed, an attacker who owns any repository containing a copy of a victim commit (e.g. a fork) can legitimately trigger a real, validly-signed GitHub `status` event for that SHA and have Shipit attach a forged `success` status to the victim stack's commit, which `Commit#deployable?` and `Api::DeploysController#create` then trust.

### Finding Description
The broken binding, stated as an equality that is never checked: `payload.dig('repository','full_name') == commit.stack.repository.full_name` for the `Commit` rows written by `StatusHandler`.

Code path:
- `app/controllers/shipit/webhooks_controller.rb` verifies the HMAC signature only against `Shipit.github(organization: repository_owner)` [1](#0-0)  — this proves the payload was signed by *some* GitHub App installation for that organization, not that the `sha`/`repository` combination inside the payload is authoritative for the commit being updated.
- `StatusHandler#process` then does: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [2](#0-1) . Its `params` schema doesn't even require `repository` [3](#0-2) , and it never calls the base `Handler#stacks`/`repository_name` scoping helper that other handlers (e.g. `PullRequest::OpenedHandler`, `CheckSuiteHandler`) use to filter by `Repository.from_github_repo_name(...)` [4](#0-3) [5](#0-4) .
- `create_status_from_github!` → `statuses.replicate_from_github!` persists a `Status` row via `find_or_create_by!` using only `state/description/target_url/context/created_at` [6](#0-5) , with no provenance/repo field recorded at all.
- `Commit#deployable?` reads `success?` (derived from the latest `Status`) and no other authenticity check [7](#0-6) .
- `Api::DeploysController#create` gates on exactly this: `param_error!(:require_ci, ...) if params.require_ci && !commit.deployable?` [8](#0-7) .

Attacker action: own/fork a repository that shares a commit SHA with a Shipit-tracked repository (trivial via forking, since forks retain identical commit objects/SHAs), then use a GitHub token they legitimately hold for their own repo to POST a commit status (`state: success`) for that SHA on their own repo. GitHub genuinely delivers a `status` webhook, signed with the shared GitHub App secret, with `repository.full_name = attacker/fork` and `sha = <shared sha>`. Shipit's signature check passes (the app is validly installed on the attacker's org/repo), and `StatusHandler` attaches the forged success status to the victim stack's `Commit` regardless of the mismatched `repository.full_name`.

Note on the "race" framing in the question: `refresh_statuses!` only *adds* statuses via `find_or_create_by!` [9](#0-8) ; it never deletes or invalidates prior rows. So the forged row is not a transient race window that gets "overwritten" — it persists indefinitely as an extra `Status` row unless it happens to collide with a genuine future GitHub-reported status. This makes the actual exploit window larger and more reliable than a race, not smaller.

Why existing guards fail: `verify_signature`/`drop_unhandled_event` only validate the webhook's authenticity for *an* organization the attacker legitimately controls — they say nothing about whether that organization is the one that owns the specific commit being updated. `ExplicitParameters` schema for `StatusHandler` doesn't require or check `repository` at all, unlike other handlers that explicitly re-derive `Repository.from_github_repo_name(params.repository.full_name)` before acting.

### Impact Explanation
An attacker can cause a `Status` row with `state: success` to be attached to a commit belonging to a victim's stack that they do not own or have any permission on, purely by forging a webhook payload whose `sha` collides with a commit shared through forking. Combined with `Api::DeploysController#create`'s `require_ci` check relying solely on `commit.deployable?`, this can cause an unauthorized deploy to be accepted for a repository the attacker never authenticated against. This matches the "Critical — a payload for one repository mutating another's stack/commit... or an unauthorized deploy" category. The attack is repeatable against any stack whose tracked repository has (or ever had) a fork, and against any historical commit shared between fork and upstream.

### Likelihood Explanation
Preconditions: the victim repository must be forkable (public GitHub repos generally are), the shared GitHub App/organization webhook must accept events from the attacker's own installation (a standard multi-tenant GitHub App setup, which is exactly what `Shipit.github(organization: repository_owner)` supports), and Shipit must have already synced the target commit (any commit shared with the fork's history, including old master commits, satisfies this). No Shipit secret, session, or team membership is required — only ownership of a fork and a GitHub personal token for that fork, both of which any GitHub user can obtain by forking a public repo. This is a low-cost, deterministic, repeatable attack, not merely theoretical.

### Recommendation
In `StatusHandler#process` (and any other handler that resolves records purely by SHA), require and validate `params.repository.full_name`, resolve the `Repository`/`Stack` via `Repository.from_github_repo_name`, and scope the `Commit` lookup to that repository's stacks (`stack.commits.where(sha: params.sha)`) instead of a global `Commit.where(sha: params.sha)`. Reject/ignore the event if the resolved repository does not match.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb
test ":status forges a status onto a commit belonging to a different repository" do
  GithubHook.any_instance.stubs(:verify_signature).returns(true)

  victim_commit = shipit_commits(:fifth) # belongs to shipit_stacks(:shipit), e.g. "shopify/shipit-engine"
  refute_predicate victim_commit, :deployable?

  request.headers['X-Github-Event'] = 'status'
  forged_payload = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'context' => 'ci/forged',
    'created_at' => Time.now.iso8601,
    'branches' => [{ 'name' => 'master' }],
    'repository' => { 'full_name' => 'attacker/unrelated-fork' } # never validated
  }.to_json

  assert_difference '-> { victim_commit.reload.statuses.count }', 1 do
    post :create, body: forged_payload, as: :json
  end

  # equality check: repository provenance never matched, yet status was accepted
  assert_not_equal 'attacker/unrelated-fork', victim_commit.stack.repository.full_name
  assert_predicate victim_commit.reload, :deployable?
end
```

```ruby
# test/controllers/api/deploys_controller_test.rb
test "#create accepts a deploy for a commit whose only success status came from a mismatched repository payload" do
  # Given the forged Status above already persisted on @commit via StatusHandler
  assert_difference -> { @stack.deploys.count }, 1 do
    post :create, params: { stack_id: @stack.to_param, sha: @commit.sha, require_ci: true }
  end
  assert_response :accepted
end
```

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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```

**File:** app/models/shipit/status.rb (L24-33)
```ruby
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

**File:** app/models/shipit/commit.rb (L156-169)
```ruby
    def refresh_statuses!
      github_statuses = stack.handle_github_redirections do
        stack.github_api.statuses(github_repo_name, sha, per_page: 100)
      end
      github_statuses.each do |status|
        create_status_from_github!(status)
      end
    end

    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/controllers/shipit/api/deploys_controller.rb (L19-22)
```ruby
      def create
        commit = stack.commits.by_sha(params.sha) || param_error!(:sha, 'Unknown revision')
        param_error!(:force, "Can't deploy a locked stack") if !params.force && stack.locked?
        param_error!(:require_ci, "Commit is not deployable") if params.require_ci && !commit.deployable?
```
