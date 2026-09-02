### Title
Cross-stack/cross-repository commit status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`Shipit::Commit#refresh_statuses!` always scopes its GitHub API read to the owning stack's own repository via `stack.github_api.statuses(github_repo_name, sha, ...)`, but the webhook-driven `StatusHandler#process` calls `commit.create_status_from_github!(params)` on every `Commit` row in the entire database that merely shares the reported `sha`, with no check that the commit's owning stack/repository matches the webhook's `payload['repository']['full_name']`. This breaks the repository-scoping invariant every other status-writing path (including `PushHandler`, which explicitly filters via the `stacks` helper) upholds.

### Finding Description
The broken binding, stated as an equality that should hold but does not:
`commit.stack.github_repo_name == payload.dig('repository', 'full_name')`

- Pull path (safe): `Commit#refresh_statuses!` fetches statuses strictly for `stack.github_repo_name` using that stack's own credentials, then applies them only to `self` (the commit that belongs to that same stack): [1](#0-0) [2](#0-1) 

- Webhook path (unsafe): `StatusHandler#process` looks up commits purely `by sha`, with zero repository/stack scoping, and mutates every match: [3](#0-2) 

- The base `Handler` class exposes exactly the scoping primitive that would fix this — `stacks`, derived from `payload.dig('repository', 'full_name')` — and `PushHandler` correctly uses it before mutating anything: [4](#0-3) [5](#0-4) 

`StatusHandler` never calls `stacks`, so the repository context that `verify_signature` establishes (the payload's `repository.owner.login`, used only to select which GitHub App secret to check against) is never carried forward to constrain *which commit* gets updated: [6](#0-5) [7](#0-6) 

`verify_signature` only proves the webhook was signed with a secret associated with some org known to Shipit — it says nothing about which `Stack`/`Commit` in the database the event is permitted to touch. Because a single physical repository is commonly tracked by more than one `Stack` (e.g., staging and production environments pointing at the same GitHub repo, sharing history/SHAs), or because a fork replays upstream SHAs, a validly-signed status webhook that legitimately originates from one repository/stack context can update `Commit` rows belonging to a *different* stack purely because `sha` matches, with `create_status_from_github!` writing directly into `statuses` and re-evaluating `deployable?`/`schedule_continuous_delivery` for that other stack.

### Impact Explanation
An attacker who can trigger a real, correctly-signed status webhook for any repository whose org is configured in Shipit (e.g., by having push/PR access sufficient to have CI or a bot post a commit status, or by controlling a fork that shares SHAs with a tracked repo) can write commit statuses (`state`, `context`, `description`, `target_url`) onto **any** `Commit` record system-wide sharing that SHA, including commits belonging to a stack/environment (e.g., production) the attacker has no authorization over. Because `Commit#status` and `deployable?`/`blocked?` drive `schedule_continuous_delivery` and gating of deploys, forging a "success" status on a shared-SHA commit in a different stack can unblock or trigger an unauthorized deploy — matching the Critical impact category of "a payload for one repository mutating another's stack, commit, task or team" / "an unauthorized deploy."

### Likelihood Explanation
Requires: (1) a validly-signed webhook, obtainable by any repo/org already configured with a Shipit-integrated GitHub App (the attacker doesn't need Shipit secrets — GitHub itself signs the webhook once the app is installed and the attacker can cause a status event, e.g., via their own CI or the GitHub Status API against a repo they control), and (2) a shared `sha` existing in a victim `Stack`'s `commits` table, which is a realistic precondition given the stated scenario (same repository tracked by multiple stacks, or forked history). No Shipit session, API token, or secret is needed. This is repeatable against any commit whose SHA is known/guessable (SHAs of merged commits are public).

### Recommendation
Scope `StatusHandler#process` the same way `PushHandler` is scoped: restrict the commit lookup to commits belonging to stacks derived from `payload.dig('repository', 'full_name')`, e.g. `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`, before calling `create_status_from_github!`.

### Proof of Concept
```ruby
# test/models/webhooks/status_handler_scoping_test.rb
test "StatusHandler#process only mutates commits belonging to the reporting repository's stacks" do
  attacker_stack = shipit_stacks(:shipit)          # repo "attacker/repo"
  victim_stack   = shipit_stacks(:cyclimse)        # different repo, e.g. "victim/repo"

  shared_sha = "a" * 40
  victim_commit   = victim_stack.commits.create!(sha: shared_sha, message: "victim")
  attacker_commit = attacker_stack.commits.create!(sha: shared_sha, message: "attacker")

  payload = {
    'sha' => shared_sha,
    'state' => 'success',
    'context' => 'ci/attacker',
    'repository' => { 'full_name' => attacker_stack.repository.full_name }
  }

  Shipit::Webhooks::Handlers::StatusHandler.call(payload)

  # Equality that should hold: only commits whose stack matches the reporting repo are mutated.
  assert_equal 1, attacker_commit.reload.statuses.count
  assert_equal 0, victim_commit.reload.statuses.count, "victim stack's commit must not receive attacker-supplied status"
end
```
This test currently fails against the existing `StatusHandler#process`, since `Commit.where(sha:)` mutates `victim_commit` as well, demonstrating the missing repository scoping.

### Citations

**File:** app/models/shipit/commit.rb (L156-163)
```ruby
    def refresh_statuses!
      github_statuses = stack.handle_github_redirections do
        stack.github_api.statuses(github_repo_name, sha, per_page: 100)
      end
      github_statuses.each do |status|
        create_status_from_github!(status)
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
