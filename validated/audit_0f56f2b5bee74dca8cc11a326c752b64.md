### Title
`StatusHandler#process` matches commits globally by SHA with no repository scoping, allowing cross-tenant status injection - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` authenticates a `status` webhook only against the `repository_owner` derived from `params.dig('repository','owner','login')` [1](#0-0) [2](#0-1) , but `StatusHandler#process` never uses `payload['repository']` to scope its query - it looks up commits solely by `sha` across the entire `Commit` table [3](#0-2) . Any org that owns a valid `webhook_secret` can therefore write a `Status` onto a `Commit` belonging to a completely different tenant's stack, as long as the two repos happen to share a SHA (trivially achievable using well-known git constants like the empty tree `4b825dc642cb6eb9a060e54bf8d69288fbee4904`, or any commit an attacker can arrange to duplicate across forks).

### Finding Description
The claimed binding is: `repository_owner` (verified in `WebhooksController#verify_signature`, defined as `params.dig('repository','owner','login')` [2](#0-1) ) == `repository.full_name` of every `Commit` mutated by `StatusHandler#process`.

Tracing the code: `verify_signature` looks up `Shipit.github(organization: repository_owner)` and validates the HMAC signature against that organization's configured `webhook_secret` [1](#0-0) . This only proves the request was signed by *some org's* secret - the org named in the payload's `repository.owner.login`. It says nothing about which `Commit` rows the handler is permitted to touch.

`StatusHandler#process` then runs:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [3](#0-2) 

This is a bare, unscoped `Commit` query - no `Repository`, `Stack`, or `payload['repository']` filter is applied. Compare this to `CheckSuiteHandler#process`, which correctly scopes via `stacks.where(branch: ...)`, where `stacks` is derived from `Repository.from_github_repo_name(repository_name)` and `repository_name` is `payload.dig('repository', 'full_name')` [4](#0-3) [5](#0-4) . `StatusHandler` inherits from the same `Handler` base class (which exposes `stacks`) but does not call it at all.

So the equality the question poses does NOT hold after tracing: `repository_owner` (verified, org A) has no enforced relationship to `commit.stack.repository.full_name` (could be org B) for any commit whose `sha` collides with the attacker-supplied value.

Exploit flow:
1. Attacker controls org A, has A's real `webhook_secret` (their own GitHub App installation - this is a legitimate credential the attacker owns for their own org, not a stolen secret).
2. Attacker POSTs `X-Github-Event: status` to `/webhooks` with a valid HMAC signature computed using A's `webhook_secret`, `repository.owner.login = "org-A"`, and `sha = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"` (the empty-tree SHA, or any SHA the attacker can arrange to exist in both org A's and org B's git history/stack, e.g. via an identical no-op commit).
3. `verify_signature` succeeds because it only checks A's secret against A's payload signature - it never checks that the target `Commit` actually belongs to org A.
4. `StatusHandler#process` finds any `Commit` row anywhere in the database with that `sha`, including one belonging to org B's stack, and calls `commit.create_status_from_github!(params)` on it, writing a forged status (`state`, `description`, `context`, `target_url`) to org B's commit.
5. If `context` matches a `required_statuses` context on org B's stack and `state` is `success`, this can unblock or trigger continuous deployment via `Commit#create_status_from_github!` → `add_status` → `schedule_continuous_delivery` path [6](#0-5) [7](#0-6) .

No existing guard prevents this: `drop_unhandled_event` only checks the event type is handled; the `ExplicitParameters` schema in `StatusHandler` only validates types/presence of `sha`/`state`/etc., not repository ownership [8](#0-7) ; there is no `require_permission!`/`current_user` check on this unauthenticated webhook endpoint by design (webhooks aren't user-session-authenticated - they rely on signature-to-repo binding, which is exactly the binding missing here).

### Impact Explanation
An attacker who owns any GitHub org with a Shipit-integrated webhook secret can write forged `Status` records onto any other tenant's `Commit` whenever a SHA collision (even an intentionally engineered one, like an identical empty/no-op commit) exists between the two repos. This is a cross-repository/cross-tenant write of another tenant's `Commit#statuses`, matching the Critical category "a payload for one repository mutating another's stack, commit, task or team." It is repeatable against any repository/stack as long as a shared SHA can be found or engineered, and could enable unauthorized continuous deployment on the victim stack if the forged status matches a required CI context.

### Likelihood Explanation
Preconditions: attacker needs their own GitHub org onboarded to the same Shipit instance (a normal, low-privilege setup step, not a secret compromise), and a SHA that exists in both their repo and the victim's. Git objects like the empty tree SHA (`4b825dc642cb6eb9a060e54bf8d69288fbee4904`) are universal and exist in virtually every git repository, making the collision trivial to obtain without any coordination with the victim. This requires no privileged Shipit role, no stolen secrets, and is fully repeatable via direct `POST /webhooks` requests with the attacker's own valid signature.

### Recommendation
Scope `StatusHandler#process` to only mutate commits within stacks belonging to the repository named in the verified payload, mirroring `CheckSuiteHandler`'s pattern, e.g.:
```ruby
def process
  stacks.flat_map { |stack| stack.commits.where(sha: params.sha) }.each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
using the `stacks` helper (derived from `payload.dig('repository','full_name')`) already provided by the base `Handler` class, so status updates are constrained to the repository that was actually signature-verified.

### Proof of Concept
Minitest plan (in `test/models/shipit/webhooks/handlers/status_handler_test.rb`, or extending `test/controllers/webhooks_controller_test.rb`):
```ruby
test "status webhook signed for org A must not mutate a commit belonging to org B's stack" do
  # Arrange: two stacks/repos belonging to different "tenants"
  stack_a = shipit_stacks(:shipit) # repository owner "shopify" (org A analog)
  stack_b = Shipit::Stack.create!(repository: Shipit::Repository.create!(owner: 'tenant-b', name: 'other-repo'))
  shared_sha = '4b825dc642cb6eb9a060e54bf8d69288fbee4904'

  commit_b = stack_b.commits.create!(
    sha: shared_sha, author: shipit_users(:walrus), committer: shipit_users(:walrus),
    authored_at: Time.now, committed_at: Time.now, message: 'noop'
  )

  request.headers['X-Github-Event'] = 'status'
  GithubHook.any_instance.stubs(:verify_signature).returns(true) # signature validated as org A's own secret

  body = {
    'sha' => shared_sha, 'state' => 'success', 'context' => 'ci/travis',
    'repository' => { 'owner' => { 'login' => 'shopify' }, 'full_name' => 'shopify/shipit-engine' } # org A only
  }.to_json

  assert_no_difference -> { commit_b.statuses.count } do
    post :create, body:, as: :json
  end

  commit_b.reload
  assert_not_equal 'success', commit_b.state, "commit belonging to tenant B's stack must not be mutated by a status signed for tenant A"
end
```
Assertions: (1) the request never queries or references `params['repository']` inside `StatusHandler#process` when locating the commit to mutate (verifiable by stubbing/spying `Repository.from_github_repo_name` and asserting it's not invoked, contrasted with `CheckSuiteHandler`); (2) `commit_b.statuses.count` changes despite the payload's `repository.owner.login` being `"shopify"` and `commit_b.stack.repository` being `tenant-b/other-repo`, proving `repository_owner` (verified) != `commit.stack.repository.full_name` (mutated).

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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
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
