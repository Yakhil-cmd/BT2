### Title
Cross-repository status webhook mutates and triggers Hook.emit for an unrelated victim stack via SHA collision - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits solely by `Commit.where(sha: params.sha)` with no scoping to the repository that authenticated the webhook, unlike every other handler in the engine which resolves `stacks` from `payload.dig('repository', 'full_name')`. Because a properly-signed webhook is only bound to the *organization/repository that owns it*, not to the shas it may reference, an attacker who controls their own repository (fork or otherwise) can emit a real, validly-signed GitHub status event referencing a SHA that also exists in a victim's stack (e.g., shared ancestor commits between a public repo and any of its forks), causing Shipit to write a `Status` row against the victim's `stack_id` and fire `Hook.emit(:commit_status/:deployable_status, victim_stack, ...)`.

### Finding Description
The broken binding is: `payload.dig('repository', 'full_name') == commit.stack.repository.full_name` for every `Commit` matched by `params.sha`. This does not hold.

Path:
- `WebhooksController#verify_signature` only validates that the payload's `repository.owner.login` matches the signing GitHub App organization [1](#0-0) . It has no notion of which shas are legitimately owned by that repository.
- The base `Handler` class explicitly provides a `stacks` helper scoped by `Repository.from_github_repo_name(repository_name)` for handlers that need repo-bound behavior [2](#0-1) .
- `StatusHandler#process`, however, ignores this scoping entirely and queries commits globally: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [3](#0-2) .
- `Commit#create_status_from_github!` then calls `statuses.replicate_from_github!(stack_id, github_status)` inside `add_status` [4](#0-3) , using **the matched commit's own `stack_id`** (i.e., the victim stack, not the attacker's), because `stack_id` is delegated from the `belongs_to :stack` association on `Commit`.
- `add_status` then fires `Hook.emit(:commit_status, stack, ...)` and `Hook.emit(:deployable_status, stack, ...)` where `stack` is `commit.stack` — the victim's stack [5](#0-4) .

Exploit flow: an attacker owns/controls a repository whose commit history shares ancestor SHAs with a victim repository tracked by Shipit (e.g., a public fork relationship, or any repo where the attacker can arrange a shared/duplicate SHA with a repo the victim also tracks). The attacker sets a commit status via the GitHub API on their own repo for that shared SHA. GitHub sends a webhook, correctly signed for the attacker's own organization, to `POST /webhooks`. `verify_signature` passes because it only checks the signing org against the payload owner — it never checks that the sha belongs to that repo/owner. `StatusHandler` then matches **every** `Commit` row with that sha across the entire Shipit installation, including the victim's, and writes a new `Status` under the victim's `stack_id` and fires the victim's configured `Hook`s.

This bypasses `verify_signature`, `drop_unhandled_event`, and the `ExplicitParameters` schema, none of which check sha ownership; and it also bypasses the repo-scoping helper (`stacks`) that other handlers use, because `StatusHandler` simply doesn't call it.

### Impact Explanation
The attacker causes a database write (a new `Shipit::Status` row) attached to a stack/commit they never authenticated for, and triggers outbound `Hook.emit(:deployable_status, victim_stack, ...)` and `Hook.emit(:commit_status, victim_stack, ...)` against the victim's configured webhook/Slack integrations, without the victim's CI ever running. Depending on the injected `state` (`success`/`failure`/`error`/`pending`), this can flip `commit.deployable?` for the victim stack, potentially unblocking `schedule_continuous_delivery` and affecting continuous deployment decisions (`stack.schedule_merges`) — i.e., a payload from one repository mutating another repository's stack/commit state. This matches the "payload for one repository mutating another's stack, commit, task or team" Critical category, and separately the outbound-hook amplification is a lower-severity notification-integrity issue.

### Likelihood Explanation
Preconditions: the victim stack must have a `Commit` row whose `sha` collides with a sha the attacker can legitimately generate a signed status event for. The most realistic vector is shared commit history via forks (any public repo can be forked by anyone, and un-diverged ancestor commits retain identical SHA1s in both fork and origin) — this makes it broadly reachable, not a theoretical hash-collision requirement. The attacker needs no Shipit credentials at all; they only need to be able to trigger a real, GitHub-signed status webhook for a repository/org they control, which any GitHub user can do via the API/Actions on their own repos. Repeatable per commit/sha shared between the two histories.

### Recommendation
Scope `StatusHandler#process` to the repository that authenticated the webhook, mirroring the `stacks` helper used elsewhere, e.g. restrict the `Commit` lookup to `stacks.flat_map(&:commits).where(sha: params.sha)` (or join through `Stack`/`Repository` matching `payload.dig('repository', 'full_name')`) before calling `create_status_from_github!`, so a status can only be applied to commits belonging to stacks of the authenticated repository.

### Proof of Concept
In `test/models/shipit/webhooks/handlers/status_handler_test.rb` (new or existing file):
```ruby
test "status webhook for repo A does not mutate or emit hooks for stack of repo B with colliding sha" do
  victim_stack = shipit_stacks(:shipit) # repository "shopify/shipit-engine" e.g.
  attacker_repo_full_name = "attacker/unrelated-repo"
  shared_sha = victim_stack.commits.first.sha

  # Simulate: the attacker's own repo also has a commit with `shared_sha`
  # (fork ancestor sha collision) -- but the Commit record actually in the
  # DB belongs to `victim_stack`.

  payload = {
    'sha' => shared_sha,
    'state' => 'success',
    'repository' => { 'full_name' => attacker_repo_full_name, 'owner' => { 'login' => 'attacker' } },
  }

  Hook.expects(:emit).with(:deployable_status, victim_stack, has_entries(commit: victim_stack.commits.first)).never
  Hook.expects(:emit).with(:commit_status, victim_stack, anything).never

  Shipit::Webhooks::Handlers::StatusHandler.call(payload)

  assert_equal 0, victim_stack.commits.first.statuses.where(created_at: nil).count # no cross-repo write
end
```
Currently this assertion fails: `StatusHandler.call(payload)` matches `victim_stack`'s commit purely by `sha`, creates a `Status` under `victim_stack.id`, and fires `Hook.emit(:deployable_status, victim_stack, ...)`, demonstrating the cross-repository write and hook emission with no live GitHub call required (matching commit fixtures already used in `test/models/commits_test.rb`).

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
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
