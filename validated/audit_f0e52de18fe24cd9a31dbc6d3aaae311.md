### Title
`StatusHandler#process` writes `Status` rows to every `Stack` sharing a commit `sha`, ignoring the webhook's own `repository.full_name` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` only authenticates that the payload's `repository.owner.login` matches an app registered for that org [1](#0-0) , but `StatusHandler#process` never uses `repository_name`/`stacks` to scope its query — it runs `Commit.where(sha: params.sha)` against the entire `commits` table and calls `create_status_from_github!` on every match, regardless of which `Stack`/`Repository` they belong to [2](#0-1) . Other handlers in the same base class correctly scope through `stacks` (built from `Repository.from_github_repo_name(repository_name)`), e.g. `PushHandler` and `CheckSuiteHandler` [3](#0-2) [4](#0-3) , but `StatusHandler` does not.

### Finding Description
**Broken binding (equality that should hold but doesn't):** `commit.stack.repository.full_name == payload['repository']['full_name']` for every `Commit` that receives a `Status` write from a single webhook.

**Trace:**
1. `WebhooksController#create` parses the raw JSON body and dispatches to handlers for the `status` event: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [5](#0-4) .
2. `verify_signature` only checks that the payload is HMAC-signed by the org identified in `repository.owner.login` (i.e., `repository_owner`) [6](#0-5) . This authenticates *one* repository's identity, not a scoping of the query that follows.
3. `Handler#initialize` parses `params` via `ExplicitParameters`; `StatusHandler`'s schema only validates `sha`, `state`, and optional fields — it never requires/uses `repository` at all in `process` [7](#0-6) .
4. `process` runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — a global, unscoped lookup across **all** stacks/repositories in the installation [2](#0-1) .
5. `Commit#create_status_from_github!` calls `statuses.replicate_from_github!(stack_id, github_status)`, which creates a `Status` row scoped to `commit.stack_id` — so each matching commit gets a `Status` written against its *own* `stack_id`, not the webhook's originating stack [8](#0-7) [9](#0-8) .

**Root cause:** unlike `PushHandler`/`CheckSuiteHandler`, which restrict their queries through `stacks` (derived from the payload's `repository.full_name`), `StatusHandler` queries the `Commit` model directly by `sha` alone with no `stack_id`/`repository` filter.

**Attacker's exact request:** Any GitHub org/repo owner who has a legitimately configured Shipit webhook (this requires no special privilege beyond owning/administering a repo that is already wired to Shipit, and the ability to push a commit whose `sha` happens to collide with a commit already present in an unrelated stack — realistic for empty/initial commits, cherry-picks, or squash-merges reproduced verbatim across forks) sends a normal, correctly-signed `status` webhook (`POST /webhooks` with `X-Github-Event: status`) naming only their own repository. Because GitHub SHA1 commit hashes are derived from tree+parent+author+message+timestamp, identical content (e.g., an initial empty commit, or a cherry-pick with same author/timestamp/message) can produce identical `sha` values across repositories in different `Stack`s.

**Why existing guards fail:** `drop_unhandled_event` and `verify_signature` establish that the request is a legitimate webhook *from the named repository's org* — they do not, and cannot, constrain which `Commit`/`Stack` rows get mutated once inside `process`. `ExplicitParameters` only validates field shape, not stack scoping. There is no `stack_id`/`repository` filter applied at all in `StatusHandler`.

### Impact Explanation
A single correctly-signed webhook from Stack A's repository writes a `Status` (and triggers `after_create :enable_ci_on_stack`, `schedule_continuous_delivery`, hooks such as `deployable_status`) against every other unrelated `Stack`/`Commit` that happens to share the same `sha`, including stacks belonging to entirely different GitHub organizations that never authenticated this payload. This is a cross-repository write: "payload for one repository mutating another's stack/commit," matching the **Critical** impact category. It can, per `Commit#deployable?`/`blocked?` and `enable_ci_on_stack`, actually make an unrelated commit appear "green"/deployable in a foreign stack it has no legitimate relationship to, and it is repeatable against any stack sharing a colliding `sha` with the attacker's own repository.

### Likelihood Explanation
Requires: (1) Shipit already tracking ≥2 independent stacks whose commit histories happen to include an identical `sha` (realistic for empty initial commits like `git init` root commits, or squash/cherry-pick reproductions with identical author/committer/timestamp/message/tree), and (2) the attacker controls (or is the legitimate maintainer of) at least one of those repositories so they can trigger a genuinely signed `status` webhook. No secrets, sessions, or elevated GitHub roles are needed beyond normal repository administration of the attacker's own repo — the exploit is entirely a consequence of `StatusHandler` never checking repository identity against the matched `Commit` rows.

### Recommendation
Scope `StatusHandler#process` the same way `PushHandler`/`CheckSuiteHandler` do: restrict the lookup through `stacks` derived from `repository_name`, e.g. `stacks.each { |stack| stack.commits.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) } }`, so only commits belonging to stacks whose `Repository#full_name` matches the payload's `repository.full_name` can receive the new `Status`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "process only creates statuses for commits within the originating repository's stacks" do
  stack_a = shipit_stacks(:shipit) # repository full_name e.g. "shopify/shipit-engine"
  stack_b = create_stack(repository: create_repository(full_name: "other-org/other-repo"))
  stack_c = create_stack(repository: create_repository(full_name: "third-org/third-repo"))

  shared_sha = "a" * 40
  commit_a = stack_a.commits.create!(sha: shared_sha, author: shipit_users(:shipit), authored_at: Time.now, committer: shipit_users(:shipit), committed_at: Time.now, message: "shared")
  commit_b = stack_b.commits.create!(sha: shared_sha, author: shipit_users(:shipit), authored_at: Time.now, committer: shipit_users(:shipit), committed_at: Time.now, message: "shared")
  commit_c = stack_c.commits.create!(sha: shared_sha, author: shipit_users(:shipit), authored_at: Time.now, committer: shipit_users(:shipit), committed_at: Time.now, message: "shared")

  payload = {
    "sha" => shared_sha,
    "state" => "success",
    "context" => "ci",
    "created_at" => Time.now.iso8601,
    "repository" => { "full_name" => stack_a.repository.full_name, "owner" => { "login" => stack_a.repository.owner } }
  }

  assert_difference -> { commit_a.statuses.count }, 1 do
    Shipit::Webhooks::Handlers::StatusHandler.call(payload)
  end

  # BROKEN BINDING: webhook named only stack_a's repository, but commit_b/commit_c (foreign stacks) were also mutated
  assert_equal 1, commit_b.reload.statuses.count, "expected 0: Status written to foreign Stack B not named in the webhook"
  assert_equal 1, commit_c.reload.statuses.count, "expected 0: Status written to foreign Stack C not named in the webhook"
end
```
This demonstrates that `commit_b.stack.repository.full_name` and `commit_c.stack.repository.full_name` both differ from the payload's `repository.full_name`, yet both received the write — confirming the cross-repository mutation.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L7-24)
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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
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
