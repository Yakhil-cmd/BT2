Confirmed: `Commit` has `belongs_to :stack` with no uniqueness constraint scoping `sha` to a repository/organization, and `StatusHandler#process` queries `Commit.where(sha: params.sha)` globally with no `repository_name`/`stacks` filter, unlike `CheckSuiteHandler` which correctly scopes via `stacks.where(branch: ...)` derived from `Repository.from_github_repo_name(repository_name)`. [1](#0-0) 

### Title
StatusHandler#process mutates commits/statuses across repositories without scoping by verified `repository_name` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits solely by `sha` across the entire `Commit` table, never filtering by the `repository_name` (or derived `stacks`) that the webhook signature actually authenticated. Any onboarded GitHub organization on a shared/multi-tenant Shipit instance can trigger a validly-signed `status` webhook for a commit SHA it shares with another tenant's stack (e.g., via a fork, which is byte-for-byte identical history up to the fork point) and inject an attacker-controlled `Shipit::Status` row onto that victim commit.

### Finding Description
The binding that should hold is: `payload.dig('repository','full_name')` (the repository the verified signature authenticates) `== stack.repository.full_name` for every `Commit` mutated by the handler.

`StatusHandler#process` does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [2](#0-1) 

This is a raw, unscoped lookup against the global `Commit` table — it never calls `Handler#repository_name` or `Handler#stacks`, both of which exist on the base `Handler` class precisely for this purpose:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [3](#0-2) 

By contrast, `CheckSuiteHandler` (handling a structurally similar CI-signal event) correctly scopes to the repository named in the verified payload before touching any commit:
```ruby
stacks.where(branch: params.check_suite.head_branch).each do |stack|
  stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
end
``` [4](#0-3) 

`Commit` has no uniqueness constraint tying `sha` to a specific repository/organization — only `belongs_to :stack` [5](#0-4) , so identical SHAs can and do legitimately coexist across unrelated `Stack`/`Repository` rows (the canonical case being a fork, which shares full commit history/SHAs with its upstream up to the divergence point).

`WebhooksController#verify_signature` only checks that the payload is signed by the webhook secret configured for `repository_owner` (the org login in the payload) — it says nothing about which specific repository within that org, nor does it ever cross-check against the repository that actually owns the `Commit` row being mutated:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  ...
``` [6](#0-5) 

**Exploit flow:** Attacker Org A is a legitimate, low-privilege tenant on a shared Shipit instance (has its own GitHub App installation and `webhook_secret`, as documented for multi-org setups) [7](#0-6) . Attacker forks victim Org B's tracked repository into Org A. All pre-fork commits share identical SHAs between the fork and Org B's stack. Attacker, using only their own GitHub API access to their own fork, creates a commit status (via GitHub's API) on one of those shared/inherited SHAs. GitHub delivers a `status` webhook to Shipit, signed with Org A's `webhook_secret`, with `repository.full_name = "OrgA/fork"` and `sha` = the shared commit SHA. `verify_signature` passes because Org A's secret genuinely signed it. `StatusHandler#process` then finds and mutates the `Commit` row belonging to Org B's stack, calling `create_status_from_github!` with attacker-supplied `state`/`description`/`context`/`target_url`.

### Impact Explanation
A `Shipit::Status` row is created on a victim organization's commit from a payload that was never signed by that victim's `webhook_secret`, violating tenant isolation on a shared Shipit deployment. Since `Status` creation drives `Commit#deployable?`/`#blocked?` logic, fires `commit_status`/`deployable_status` hooks, and can enqueue `ProcessMergeRequestsJob` [8](#0-7) , an attacker can inject fake CI success/failure signals into a victim's deploy/merge pipeline. This matches "a payload for one repository mutating another's stack, commit" — Critical severity. It is repeatable against any commit SHA the victim's stack shares with any repository the attacker controls (forks being the trivial, always-available case).

### Likelihood Explanation
Requires: (1) a multi-tenant Shipit deployment with more than one GitHub organization configured (documented supported feature), (2) attacker owns/controls a repository under one of those organizations (e.g., by being a member of that org, or the org itself onboarding this attacker's repo), (3) a SHA collision with the victim's tracked commit — trivially satisfied via forking a victim's public repository, since forks share full ancestor history/SHAs. No Shipit secrets are needed; GitHub itself signs the request using the attacker's own org's legitimate app credentials. Cost is a single GitHub API call to set a status on an inherited commit.

### Recommendation
Scope `StatusHandler#process` to the repository authenticated by the payload, mirroring `CheckSuiteHandler`:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`):
1. Create `repository_a` (`full_name: "OrgA/fork"`) and `stack_a`, and `repository_b` (`full_name: "OrgB/original"`) and `stack_b`.
2. Create `Commit.create!(stack: stack_a, sha: "deadbeef"*5)` and `Commit.create!(stack: stack_b, sha: "deadbeef"*5)` — identical SHA, different stacks/repositories.
3. Build a payload: `{ "sha" => "deadbeef"*5, "state" => "success", "repository" => { "full_name" => "OrgA/fork" } }`.
4. Call `Shipit::Webhooks::Handlers::StatusHandler.call(payload)`.
5. Assert the equality that should hold but doesn't: `payload.dig('repository','full_name') == stack_b.repository.full_name` is `false`, yet `assert_equal 1, commit_b.reload.statuses.count` (status created on Org B's commit despite Org A's payload never authenticating Org B), alongside `assert_equal 1, commit_a.reload.statuses.count` (legitimately expected on Org A's own commit). The failing/unexpected assertion is the one on `commit_b.statuses.count`, proving cross-tenant mutation.

### Citations

**File:** app/models/shipit/commit.rb (L4-18)
```ruby
  class Commit < Record
    include DeferredTouch

    RECENT_COMMIT_THRESHOLD = 10.seconds

    AmbiguousRevision = Class.new(StandardError)

    belongs_to :stack
    has_many :statuses, -> { order(created_at: :desc) }, dependent: :destroy, inverse_of: :commit
    has_many :check_runs, -> { order(created_at: :desc) }, dependent: :destroy, inverse_of: :commit
    has_many :commit_deployments, dependent: :destroy
    has_many :release_statuses, dependent: :destroy
    belongs_to :merge_request, inverse_of: :merge_commit, optional: true

    deferred_touch stack: :updated_at
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-16)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
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

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
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
