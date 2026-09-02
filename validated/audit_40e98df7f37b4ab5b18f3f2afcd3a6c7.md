Confirms the index is only `(stack_id, sha)`, not a global unique constraint on `sha` — so duplicate `sha` values across different stacks/repos are fully permitted by the schema. Other handlers (`pull_request/*`) correctly scope lookups through `stacks` / `from_github_repo_name(repository_name)`, but `StatusHandler` does not.### Title
`StatusHandler#process` writes a `Status` for any `Commit` matching `sha` without asserting the commit's repository matches the webhook payload's repository - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` resolves the target `Commit` purely via `Commit.where(sha: params.sha)`, a global (non-scoped) lookup, and immediately calls `commit.create_status_from_github!(params)`. It never uses the inherited `Handler#stacks`/`Handler#repository_name` helpers to constrain the lookup to commits belonging to the payload's own repository, so a webhook validly signed for repo A can mutate `Status`/`Commit` state belonging to a completely different tenant's `Stack`/repo B, as long as any commit row anywhere in the database shares the same `sha`.

### Finding Description
The broken binding is: `commit.stack.repository.full_name == payload.dig('repository', 'full_name')` — this must hold before `create_status_from_github!` is called, but it is never checked.

Code path:
- `app/controllers/shipit/webhooks_controller.rb#verify_signature` verifies the HMAC signature using `Shipit.github(organization: repository_owner)` — i.e., against the org named in the *attacker's own* payload, which the attacker legitimately owns and has a valid `webhook_secret` for. [1](#0-0) 
- `Shipit::Webhooks.for_event('status')` dispatches to `Handlers::StatusHandler`. [2](#0-1) 
- `StatusHandler#process` does: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`. [3](#0-2) 
- The base `Handler` class exposes `stacks` (scoped via `Repository.from_github_repo_name(repository_name)&.stacks`) and `repository_name` (`payload.dig('repository', 'full_name')`) precisely for this purpose, but `StatusHandler` never calls either. [4](#0-3) 
- Other handlers in the same module (e.g. `PullRequest::LabeledHandler`) correctly resolve the repository from the payload and scope all subsequent lookups/mutations to `repository.review_stacks`. [5](#0-4) 
- `Commit#create_status_from_github!` writes a `Status` directly from attacker-controlled `state`/`description`/`target_url`/`context`/`created_at` fields with no re-fetch from GitHub and no repository check. [6](#0-5) 
- The DB uniqueness constraint on `commits` is `(sha, stack_id)`, not global on `sha` alone, so identical `sha` values legitimately coexist across different stacks/repos (e.g., shared history from forks, or an attacker simply guessing/observing a victim's public commit sha and submitting it verbatim — no hash collision required, since the attacker fully controls the `sha` field in their own signed payload). [7](#0-6) 

Existing guards (`verify_signature`, `drop_unhandled_event`, `ExplicitParameters` schema) only validate that the request is a legitimately-signed `status` event *for the attacker's own org* and that required fields are present — none of them assert that the resolved `Commit#stack#repository` matches `payload['repository']['full_name']`. Existing tests (`test/controllers/webhooks_controller_test.rb`) only exercise the intended single-tenant case and never assert cross-repository isolation.

### Impact Explanation
An attacker who legitimately owns some GitHub org/repo (and thus its `webhook_secret`) can send an arbitrary-content `status` webhook naming any `sha` value. If that `sha` happens to also exist as a `Commit` row belonging to a different tenant's `Stack` (e.g., because both repos share commit history from a common fork lineage, or because the attacker simply knows/observes the victim's public commit SHA and puts it in their own payload — trivial since GitHub SHAs are public), a `Status` row is created/mutated on the victim's `Commit`, with attacker-chosen `state`, `description`, `target_url`, and `context`. This can flip `commit.state` (e.g., force `success`), which feeds into `Commit#deployable?`/`blocked?` and downstream continuous-deployment/merge scheduling (`stack.schedule_merges`, `ContinuousDeliveryJob`), and can also fire `commit_status`/`deployable_status` hooks for the victim stack. This is a payload from repo A mutating repo B's `Stack`/`Commit` state — matching the Critical category ("a payload for one repository mutating another's stack, commit, task or team").

### Likelihood Explanation
Preconditions: the attacker only needs their own valid GitHub org/repo with its own `webhook_secret` (an unprivileged, self-service capability), and a target `sha` value that matches an existing `Commit` row in a victim `Stack`. GitHub commit SHAs are public information (visible via GitHub UI/API, PR pages, Shipit's own public stack pages), so obtaining a target sha requires no secret. The attack is fully repeatable against any commit sha the attacker can observe, is stack-agnostic (any tenant using Shipit's shared webhook endpoint), and costs only a single signed HTTP POST per attempt.

### Recommendation
In `StatusHandler#process`, scope the commit lookup to the payload's own repository before mutating anything, e.g. use the inherited `stacks`/`repository_name` helpers: `Commit.where(sha: params.sha, stack_id: stacks.select(:id)).each { |commit| commit.create_status_from_github!(params) }`, or explicitly assert `commit.stack.repository.full_name == repository_name` (case-insensitively, matching `Repository.from_github_repo_name`) before calling `create_status_from_github!`, skipping/rejecting any commit that doesn't belong to the payload's repository.

### Proof of Concept
Minitest plan (in `test/controllers/webhooks_controller_test.rb`, no live GitHub required, using `GithubHook.any_instance.stubs(:verify_signature).returns(true)` as existing tests do):

```ruby
test ":status payload for repo A must not mutate a commit belonging to stack B" do
  # victim_stack belongs to repo "shopify/other-repo", attacker owns "shopify/attacker-repo"
  victim_stack = shipit_stacks(:shipit) # repository full_name = "shopify/shipit-engine" (fixture)
  victim_commit = shipit_commits(:first) # belongs to victim_stack

  request.headers['X-Github-Event'] = 'status'
  body = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'description' => 'forged',
    'context' => 'attacker/forged',
    'repository' => { 'full_name' => 'shopify/attacker-repo', 'owner' => { 'login' => 'shopify' } }
  }.to_json

  assert_no_difference -> { victim_commit.statuses.count } do
    post :create, body: body, as: :json
  end

  refute_equal 'success', victim_commit.reload.state
end
```

Assert the binding both sides: before the request, `victim_commit.stack.repository.full_name` ("shopify/shipit-engine") != payload `repository.full_name` ("shopify/attacker-repo"); after the fix, the write must be a no-op because that inequality holds; currently (unfixed) the write succeeds because `StatusHandler#process` never evaluates this inequality at all.

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

**File:** app/models/shipit/webhooks.rb (L19-19)
```ruby
          'status' => [Handlers::StatusHandler],
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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L65-68)
```ruby
          def repository
            @repository ||= Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
                            Shipit::NullRepository.new
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

**File:** db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb (L1-5)
```ruby
class IndexCommitsOnStackIdAndSha < ActiveRecord::Migration[5.1]
  def change
    add_index :commits, %i(sha stack_id), unique: true
  end
end
```
