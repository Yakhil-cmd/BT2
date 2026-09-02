Confirmed. I have enough evidence to answer.

### Title
Unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` lets any repository's status webhook write CI status onto another repository's commit sharing the same SHA - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits by bare SHA across the *entire* `commits` table with no repository/stack scoping, unlike every other webhook handler in the codebase (e.g. `PushHandler`, the `PullRequest` handlers) which all resolve `stacks` from `Repository.from_github_repo_name(repository_name)` before touching any record. Since the `commits` table has a unique index on `(sha, stack_id)` — not on `sha` alone — the same SHA can legitimately exist as separate `Commit` rows under many different stacks (e.g., forks, mirrors, or repos sharing history), and a webhook whose signature is valid for one org/repo can flip CI state and trigger merges/deploys on a completely unrelated stack's commit row.

### Finding Description
The broken binding is: **"a status must only mutate `Commit` rows belonging to the stack(s) of the repository that authenticated it"** — i.e. `commit.stack.repository == payload.repository` should hold for every `Commit` mutated by `StatusHandler`. This binding does not hold.

Code path:
1. `Shipit::WebhooksController#create` dispatches the raw JSON payload to `Shipit::Webhooks.for_event('status')`, i.e. `StatusHandler.call(params)` [1](#0-0)  after `verify_signature` checks the payload's HMAC against `Shipit.github(organization: repository_owner)`, where `repository_owner` is read straight from the attacker-controlled payload (`params.dig('repository','owner','login')`) [2](#0-1) [3](#0-2) . This only proves the payload was signed by *some* organization whose GitHub App/webhook secret is configured in Shipit — it says nothing about which stack the `sha` belongs to.
2. `StatusHandler#process` then does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [4](#0-3) 
This is the only handler in the codebase that skips the `Handler#stacks` scoping helper (`Repository.from_github_repo_name(repository_name)&.stacks`) [5](#0-4)  that every other handler uses, e.g. `PushHandler#process` explicitly scopes via `stacks.not_archived.where(branch:)` [6](#0-5) .
3. `Commit` `belongs_to :stack` and the DB enforces uniqueness only on the pair `(sha, stack_id)`, not on `sha` alone [7](#0-6) [8](#0-7) . So distinct stacks (belonging to unrelated repositories, e.g. a fork, a repo sharing git history, or coincidentally identical SHA rows created via GithubSyncJob) can each have their own `Commit` row for the same `sha`.
4. `create_status_from_github!` calls into `add_status`, which triggers `Hook.emit(:deployable_status, ...)` and `stack.schedule_merges` when the state becomes `pending`/`success` [9](#0-8)  — this is exactly the mechanism that unblocks/ships a stack.

Attack: the attacker owns (or has push access to) any repository whose organization/webhook secret is already trusted by the Shipit installation (this is the only requirement `verify_signature` imposes), and whose git history shares a commit SHA with the victim's stack (trivial via a fork, since content-addressed git SHAs are identical across forks/mirrors of the same commit). The attacker sends `POST /webhooks` with `X-Github-Event: status`, a valid signature for their own repo/org, and a body `{"sha": "<shared-sha>", "state": "success", "context": "ci/coverage", "repository": {...attacker repo...}}`. `StatusHandler` finds and updates the victim's `Commit` row for that SHA (in addition to the attacker's own), regardless of `repository` field content, because `repository` is never consulted after signature verification.

No existing guard stops this: `verify_signature` validates *who signed*, not *which stack the payload's SHA belongs to*; `ExplicitParameters` (`params do requires :sha ... end`) only validates types/presence, not ownership; `stacks`/`Repository.from_github_repo_name` scoping exists in the base `Handler` class but is never invoked by `StatusHandler`.

### Impact Explanation
A payload signed for repository A can create a `Status` row, flip `commit.state`, and fire `Hook.emit(:deployable_status, ...)` plus `stack.schedule_merges` for a `Commit` belonging to an entirely different stack/repository B, as long as A and B ever shared a commit SHA (fork, mirrored history, cherry-pick). This is a payload for one repository mutating another repository's stack/commit state, matching the "Critical: a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy" category. It is repeatable against any stack whose repository has ever shared history with an attacker-controlled repo trusted by the same Shipit GitHub App configuration.

### Likelihood Explanation
Preconditions: the attacker needs a repository under an organization/GitHub App installation whose webhook secret Shipit already trusts (commonly the same secret is shared across all repos of one org/installation, so any org member with a sandbox repo qualifies), and a commit SHA shared with the victim stack (trivially obtained by forking the victim repo — fork commits retain identical SHAs). No Shipit session, API token, or team membership is required. The attack is cheap (a single signed HTTP POST) and repeatable against any stack sharing history with the attacker's repo.

### Recommendation
Scope `StatusHandler#process` the same way as every other handler: resolve `stacks` from `Repository.from_github_repo_name(payload.dig('repository','full_name'))` and restrict the `Commit` lookup to `stacks.joins(...).where(sha: params.sha)` (or filter `Commit.where(sha: params.sha)` further by `stack_id: stacks.pluck(:id)`), so a status can only ever mutate commits belonging to the repository that authenticated the webhook.

### Proof of Concept
```ruby
# test/models/webhooks/handlers/status_handler_test.rb
test "status for one repository does not affect another repository's commit sharing the same sha" do
  shared_sha = "a" * 40

  victim_repo  = shipit_repositories(:shipit) # or create!(full_name: "acme/victim")
  attacker_repo = Shipit::Repository.create!(full_name: "acme/attacker-fork")
  attacker_stack = attacker_repo.stacks.create!(repository: attacker_repo, environment: "production", branch: "master")
  victim_stack = victim_repo.stacks.first

  victim_commit = victim_stack.commits.create!(sha: shared_sha, author: shipit_users(:shipit), authored_at: Time.now, committer: shipit_users(:shipit), committed_at: Time.now, message: "victim")
  attacker_commit = attacker_stack.commits.create!(sha: shared_sha, author: shipit_users(:shipit), authored_at: Time.now, committer: shipit_users(:shipit), committed_at: Time.now, message: "attacker")

  # BEFORE: victim_commit.state != 'success', unrelated to attacker's payload
  assert_not_equal 'success', victim_commit.reload.state

  payload = {
    'sha' => shared_sha,
    'state' => 'success',
    'context' => 'ci/coverage',
    'repository' => { 'full_name' => attacker_repo.full_name, 'owner' => { 'login' => 'acme' } }
  }

  Shipit::Webhooks::Handlers::StatusHandler.call(payload)

  # AFTER: victim_commit was mutated by a payload that only authenticated for attacker_repo
  assert_equal 'success', victim_commit.reload.state
  assert_equal 'success', attacker_commit.reload.state
end
```
This demonstrates the equality `commit.stack.repository == payload.repository` is violated: `victim_commit` (belonging to `victim_repo`) is mutated by a payload whose `repository` field names `attacker_repo`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb (L1-5)
```ruby
class IndexCommitsOnStackIdAndSha < ActiveRecord::Migration[5.1]
  def change
    add_index :commits, %i(sha stack_id), unique: true
  end
end
```

**File:** app/models/shipit/commit.rb (L11-12)
```ruby
    belongs_to :stack
    has_many :statuses, -> { order(created_at: :desc) }, dependent: :destroy, inverse_of: :commit
```

**File:** app/models/shipit/commit.rb (L366-384)
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
```
