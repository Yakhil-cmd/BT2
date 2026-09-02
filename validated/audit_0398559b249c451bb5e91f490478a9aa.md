Based on my investigation, I found the actual vulnerability, though it differs from the exact framing in the question. Let me clarify.

### Title
Cross-repository status forgery flips victim stack's `ignore_ci` via unscoped SHA lookup - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits by `sha` alone across the *entire* Commits table with `Commit.where(sha: params.sha).each`, without scoping to the repository that authenticated the webhook. Unlike other handlers, it never consults `stacks` (which is derived from `Repository.from_github_repo_name(repository_name)`). Because git SHAs are attacker-reproducible in their own repo (a stated precondition), an attacker's own verified webhook can write a `Status` row against a victim's commit/stack and trigger `Status#enable_ci_on_stack`, silently flipping `stack.ignore_ci` from `true` to `false`.

### Finding Description
The broken binding is: **the stack that authenticated the webhook == the stack whose `ignore_ci` flag is mutated**. In the vulnerable path, this equality fails.

- `WebhooksController` verifies the webhook signature against the *sending* installation/repo's secret — this authenticates "this payload is a genuine GitHub event for repository X," but does nothing to constrain which Shipit records the handler is allowed to touch.
- Every other handler scopes its side effects through `stacks`, defined in `app/models/shipit/webhooks/handlers/handler.rb`: [1](#0-0) , which resolves `Repository.from_github_repo_name(repository_name)` — i.e., strictly the repo that sent the payload.
- `StatusHandler#process` breaks this pattern entirely: [2](#0-1) . It queries `Commit.where(sha: params.sha)` with no repository/stack filter, then calls `commit.create_status_from_github!(params)` for *every* matching commit in the whole database, regardless of which repo/stack owns it.
- `Commit#create_status_from_github!` writes into `statuses.replicate_from_github!(stack_id, github_status)` using the commit's own `stack_id` [3](#0-2) , i.e., the victim stack's id, not the attacker's.
- `Status.replicate_from_github!` performs a `find_or_create_by!` [4](#0-3) , and the `after_create :enable_ci_on_stack` callback unconditionally calls `commit.stack.enable_ci!` [5](#0-4) .

Exploit flow: attacker owns/controls a repo, crafts a commit reproducing a victim commit's SHA (stated precondition — tree/parent/committer-date collision is attacker-controlled since they author the commit), pushes it, and lets their own repo's genuinely-signed status event fire (or POSTs a `status` event for their installation). Because `StatusHandler` never checks `repository_name` against the commit's owning stack, the same SHA existing in the victim's `commits` table causes the handler to iterate into it and create a `Status` row there, flipping `ignore_ci`.

This is distinct from the framing in the question, which asserted the binding fails merely because the flip is "caused by attacker's own verified webhook, not the victim org's" — that framing alone would be invalid, since every handler is designed to process events per-repo via `stacks`/`repository_name`, and it's not automatically true that any verified webhook can touch any stack. The actual bug is narrower and concrete: `StatusHandler` is the one handler that omits the repository scoping present everywhere else, and this is only exploitable when a real SHA collision across repositories exists (an event that, while cryptographically implausible for random commits, is explicitly given as a precondition in this question — e.g., forking/mirroring an existing commit, or importing a commit history — not a brute-force collision).

### Impact Explanation
A `Status` record is written for a stack that never authenticated the write, and `Stack#enable_ci!` is invoked on it, altering the victim stack's `ignore_ci` flag and thereby `Commit#deployable?` semantics `stack.ignore_ci? || (success? && !blocked?)` [6](#0-5)  for all future commits on that stack. This matches "a payload for one repository mutating another's stack, commit, task or team" (Critical). The attacker does not gain arbitrary write of arbitrary content (state/description/context of the forged status are still theirs), but they do force a stack-level CI-enforcement policy change that the victim's maintainer did not authorize, and this is repeatable for every SHA they can reproduce.

### Likelihood Explanation
Exploitability strictly depends on the attacker being able to make a commit in their own repository share an identical SHA-1 with a specific commit that already exists in a victim's Shipit-tracked stack. Ordinary git commits are not attacker-forgeable to an arbitrary target SHA (SHA-1 preimage resistance still holds in practice for this purpose, git's known SHA-1 collision issues are for chosen-prefix collisions between two attacker-controlled blobs, not matching an existing victim commit). The question stipulates this as a precondition ("commit sha reproducible by attacker in their own repo"), which in realistic Shipit deployments would require something like the victim's commit being a fork/mirror of a public commit that the attacker also has push access to (e.g., a public PR branch commit that both the victim's tracked branch and the attacker's fork share) — a materially weaker and more contrived precondition than arbitrary SHA forgery. Given that caveat, no `ExplicitParameters` schema, `force_github_authentication`, or model validation blocks this once the SHA match exists, because `StatusHandler` performs no repository check at all.

### Recommendation
Scope `StatusHandler#process` to the sending repository the same way every other handler does: filter through `stacks` (derived from `Repository.from_github_repo_name(repository_name)`) and match commits by `stack_id: stacks.select(:id)` (or `stack.commits.where(sha: ...)` per stack) instead of the global `Commit.where(sha: params.sha)`. Additionally, `Status.replicate_from_github!`/`enable_ci_on_stack` should not silently flip `ignore_ci: true` back to `false` on receipt of any status — that state should require explicit maintainer action, not be an automatic side effect of any status callback.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb (would need to exist)
test "status handler must not touch commits belonging to a different repository" do
  victim_stack = shipit_stacks(:shipit)
  victim_stack.update!(ignore_ci: true)
  victim_commit = victim_stack.commits.create!(sha: "a" * 40, message: "victim commit")

  attacker_repo_payload = {
    "repository" => { "full_name" => "attacker/unrelated-repo" },
    "sha" => victim_commit.sha,
    "state" => "success",
    "context" => "ci/attacker"
  }

  Shipit::Webhooks::Handlers::StatusHandler.call(attacker_repo_payload)

  assert_equal true, victim_stack.reload.ignore_ci, "attacker-authenticated event for a different repo must not flip victim stack's ignore_ci"
  assert_empty victim_commit.reload.statuses, "no Status row should be written on a commit not owned by the sending repository"
end
```
Both sides of the binding before/after: `victim_stack.ignore_ci` should remain `true` (equal to the maintainer-set value) both before and after the attacker's cross-repo webhook; the current code makes it `false` after, breaking the equality.

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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/status.rb (L18-40)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

    delegate :broadcast_update, to: :commit

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
    end

    private

    def enable_ci_on_stack
      commit.stack.enable_ci!
    end
```
