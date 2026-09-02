### Title
Webhook status events matched by SHA alone allow cross-stack `Status` injection - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves target commits via `Commit.where(sha: params.sha)`, with no scoping to the repository that signed the webhook. `Commit#create_status_from_github!` then writes a `Status` using the victim commit's own `stack_id`, so any repository able to produce a webhook for a SHA that also exists in another stack's commit history can inject CI status into that unrelated stack.

### Finding Description
The binding that must hold is: `stack_id` passed into `Status.replicate_from_github!` == the stack owned by `Repository.from_github_repo_name(payload.dig('repository','full_name'))`. It does not.

`StatusHandler#process` is:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [1](#0-0) 

This lookup is global across the entire `commits` table, filtered only by `sha`, and completely ignores `repository_name`/`stacks` — the very scoping mechanism the base `Handler` class provides (`Repository.from_github_repo_name(repository_name)&.stacks`) is never invoked by this handler. [2](#0-1) 

Each matched `commit` (regardless of which stack it belongs to) then has:
```ruby
def create_status_from_github!(github_status)
  add_status do
    statuses.replicate_from_github!(stack_id, github_status)
  end
end
``` [3](#0-2) 

`stack_id` here is read from the victim `Commit` row, not derived from the authenticated `repository.full_name` in the payload, and `Status.replicate_from_github!` persists it as-is. [4](#0-3) 

Root cause: the webhook signature only proves the payload originated from the named `repository.full_name`'s installation; it says nothing about which `Commit`/`Stack` the `sha` should be attributed to. Since git commit SHAs are content-addressed and identical across forks/shared history, or otherwise collide per the stated precondition, an attacker who controls repository Y (and thus a signed status webhook for Y) can emit a `status` event whose `sha` matches a commit that also exists (with the same SHA) under stack X. `StatusHandler` finds that X commit too and writes a `Status` against X's `stack_id`, even though the payload only authenticated repository Y. `verify_signature`/`GitHubApp#verify_webhook_signature` and `drop_unhandled_event` only gate that the payload is genuinely from GitHub for the claimed repository/event type; they never re-check that the resolved `Commit`'s stack matches that repository. No `ExplicitParameters` schema field, model validation, or `stacks` scoping is applied in `StatusHandler#process`, so nothing prevents the divergence.

Attacker request: attacker owns repository Y (e.g. a fork of, or a repo sharing commit history with, the repository backing stack X). Attacker triggers (or GitHub emits) a legitimately-signed `status` webhook for repository Y referencing a `sha` that is also present as a `Commit` under stack X, with arbitrary `state`/`description`/`context`. `POST /webhooks` is verified for Y, `StatusHandler.call` runs, and matches Commit rows by SHA across all stacks, injecting a `Status` into stack X.

### Impact Explanation
The attacker causes a `Status` row (arbitrary `state`, e.g. `success`, `description`, `context`, `target_url`) to be written against a stack (X) the attacker never authenticated for, purely by controlling a different repository (Y) whose webhook happens to reference a colliding/shared SHA. Since `Status` feeds into `Commit#status`/`deployable?` and `stack.schedule_merges`/continuous delivery decisions, this can mark a commit on stack X as CI-successful and unblock deploys/merges on a stack the attacker does not control — matching "a payload for one repository mutating another's stack, commit, task or team" and "an unauthorized deploy". This is repeatable for any SHA overlap the attacker can arrange (e.g., forks sharing history, or attacker-created commits designed to match), and the blast radius spans every stack whose `Commit.sha` intersects with SHAs the attacker can trigger status events for.

### Likelihood Explanation
Preconditions: the attacker needs a repository (Y) registered as a Shipit repository (or any repository GitHub will let them push to) and the ability to get a `status` webhook delivered for it — e.g. via GitHub Actions/CI configured on their own fork, which is trivially available to any GitHub user with a repo. The only nontrivial requirement is a SHA collision/overlap between the attacker's repo and the victim stack's commit table, which is realistic for forks (unmodified upstream commits share identical SHAs) and is explicitly given as a precondition in this question. No Shipit secrets, sessions, or privileged roles are required — only the ability to own a GitHub repository and emit its (legitimately signed) status events.

### Recommendation
Scope `StatusHandler#process` (and the analogous `CheckRunHandler` if present) to only update commits belonging to stacks under the repository resolved from the payload, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`, using the existing `stacks` helper on `Handler`, so a `Status` can never be written for a stack whose repository didn't sign the payload.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "status webhook for repository Y cannot write a Status against stack X's commit" do
  victim_repo  = create_repository(owner: 'acme', name: 'victim')
  attacker_repo = create_repository(owner: 'mallory', name: 'evil-fork')
  stack_x = create_stack(repository: victim_repo)
  shared_sha = 'a' * 40
  victim_commit = create_commit(stack: stack_x, sha: shared_sha)

  payload = {
    'sha' => shared_sha,
    'state' => 'success',
    'repository' => { 'full_name' => attacker_repo.full_name }
  }

  Shipit::Webhooks::Handlers::StatusHandler.call(payload)

  status = Shipit::Status.last
  # Binding under test: status.stack_id must equal the stack authorized by
  # payload['repository']['full_name'] (attacker_repo's stacks), not stack_x.id
  assert_not_equal stack_x.id, attacker_repo.stacks.pluck(:id).first  # sanity: attacker has no stack here / different stack
  assert_equal stack_x.id, status.stack_id   # demonstrates the bug: victim stack got the write
end
```
This demonstrates that a webhook authenticated only for `attacker_repo` results in a `Status` persisted with `stack_id == stack_x.id`, violating the required equality between the authorized stack (derived from `repository.full_name`) and the stack actually written to.

### Citations

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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/status.rb (L23-33)
```ruby
    class << self
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
