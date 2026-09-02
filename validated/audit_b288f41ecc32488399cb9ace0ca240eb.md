### Title
`StatusHandler#process` attaches GitHub status webhooks to commits by SHA alone, ignoring the payload's own repository, letting a status forged from an unrelated repo flip `Commit#blocked?` on a victim stack - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up target commits with `Commit.where(sha: params.sha)`, with no filter on the repository that the webhook actually originated from, even though the base `Handler` class already provides a `stacks` scoping helper for exactly this purpose that this handler never calls. Because `Commit#create_status_from_github!` persists the new `Status` under the matched commit's own `stack_id`, a status forged in an attacker-controlled repository whose commit history shares a SHA with the victim's repository (e.g. via a public fork) is written straight into the victim stack and can flip `Commit#blocked?`/`deployable?` for undeployed commits the attacker has no relationship to.

### Finding Description
The binding the code is supposed to preserve is: `Status.context/state contributing to Commit#blocked? == a status legitimately reported for stack.repository (the SHA's own repo)`. That binding is broken.

Path:
- `StatusHandler#process` receives `params.sha`/`params.state`/`params.context` and does:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [1](#0-0) 
This query is completely unscoped by repository - `sha` is a global column across every `Commit` row in the database, spanning every stack/repository configured in the Shipit instance.

- The base `Handler` class defines exactly the scoping primitive this should use — `stacks`, derived from `payload.dig('repository', 'full_name')` — but `StatusHandler` never calls it:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [2](#0-1) 

- Once a same-SHA commit belonging to an unrelated victim stack is matched, `create_status_from_github!` writes the new `Status` scoped to *that matched commit's own* `stack_id`, not the payload's repository:
```ruby
def create_status_from_github!(github_status)
  add_status do
    statuses.replicate_from_github!(stack_id, github_status)
  end
end
``` [3](#0-2) 
`replicate_from_github!` then does `find_or_create_by!(stack_id:, state:, ..., context:, created_at:)` on `Status`. [4](#0-3) 

- `Commit#blocked?` evaluates blocking purely from stored `Status` rows scoped to the victim's own stack, with no notion of which repository originally emitted them:
```ruby
def blocked?
  return false if stack.blocking_statuses.empty?

  stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
end
``` [5](#0-4) 
`blocking?` is derived from `Status::Group`/`Status::Common` purely off `context`/`state`, with `stack.blocking_statuses` also just a configured list of context names. [6](#0-5) 

Exploit flow: the attacker (per the stated threat model) owns/controls a repository — e.g. a public fork of the victim repository — whose shared git history contains commits with the exact same SHAs as older, undeployed commits in the victim stack (forks preserve identical commit-object hashes for the shared ancestry). The attacker triggers a genuine, correctly-signed GitHub status event on their own repo/commit (e.g. via GitHub's status API on their fork). The webhook is delivered to Shipit, passes signature verification (it is a real, correctly-signed GitHub event for a repo the attacker legitimately controls), and is routed to `StatusHandler`. `StatusHandler#process` then matches *every* `Commit` row with that SHA — including the one that belongs to the victim's stack — and calls `create_status_from_github!` on it, writing a `Status` under the victim's `stack_id` with an attacker-chosen `context` and `state` (`failure` to block, `success` to try to unblock). If that `context` is one of `stack.blocking_statuses`, `Commit#blocked?` on later, still-undeployed sibling commits in the victim's queue now evaluates using this forged row.

None of the existing guards catch this: `verify_signature`/webhook-signature checks only prove the event came from GitHub for *some* repository (the attacker's own), not that it matches the stack being mutated; `drop_unhandled_event` and `ExplicitParameters` only validate shape, not repository identity; and there is no `Repository`/`Stack` scoping applied anywhere in `StatusHandler#process` (unlike the `stacks` helper other handlers are expected to use).

### Impact Explanation
This lets an attacker who controls an unrelated repository (e.g. a fork of the victim's public repo) write `Status` rows into a completely different tenant's `Stack`, directly mutating `blocked?`/`deployable?` for arbitrary undeployed commits they have no authorization over. This is a payload for one repository mutating another repository's stack/commit state, satisfying the Critical impact category: it can suppress deploys the victim expects to proceed (griefing/DoS on the deploy pipeline) or force `deployable?` to become true earlier than a legitimate CI signal would allow, enabling deploys of commits whose real CI status the attacker faked. It is repeatable against any victim stack whose commit history overlaps (via forking or shared history) with a repository the attacker controls, and requires no session, token, or team membership.

### Likelihood Explanation
Preconditions: the attacker needs a repository they control (trivial — public fork of the target repo) that shares SHA history with the victim (guaranteed for any public fork, since fork ancestry preserves identical commit hashes), and the Shipit instance must accept genuinely GitHub-signed webhooks from that repository (consistent with the described attacker capability of "emit webhooks from a repository they own"). No secrets, tokens, or special configuration on the victim side are required. Attacker cost is minimal — create a status via the GitHub API on their own fork/commit and let GitHub deliver the webhook. This is straightforwardly repeatable against any public repository tracked by Shipit.

### Recommendation
Scope `StatusHandler#process` to only update commits belonging to stacks whose repository matches the webhook payload's `repository.full_name`, mirroring the `stacks` helper already defined in the base `Handler` class, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` (or equivalently filter `Commit.where(sha: params.sha)` by `stack_id: stacks.pluck(:id)`) before calling `create_status_from_github!`.

### Proof of Concept
Minitest plan (in `test/models/commits_test.rb`, mirroring the existing `#deployable? is false if a blocking status is failing on a previous undeployed commit` test):
1. Create `stack_a` (victim) with `blocking_statuses` including `"ci/blocking"`, and two commits `c1` (older, undeployed) and `c2` (newer) in `stack_a`.
2. Create `stack_b` (attacker-controlled, different `Repository`) with a commit whose `sha` equals `c1.sha` (simulating fork history collision).
3. Build a status payload (`ExplicitParameters`-shaped) with `sha: c1.sha`, `state: 'failure'`, `context: 'ci/blocking'`, and `repository.full_name` set to `stack_b`'s repository (not `stack_a`'s).
4. Invoke `Shipit::Webhooks::Handlers::StatusHandler.call(payload)`.
5. Assert the equality that should hold but doesn't: `Status.where(stack_id: stack_a.id, context: 'ci/blocking').exists?` should be `false` (status was reported for `stack_b`'s repo, not `stack_a`'s) — but it is `true`.
6. Assert `c2.reload.blocked?` is `false` (no legitimate blocking status exists in `stack_a`) — but it evaluates to `true`, proving the cross-repository injection flips `blocked?`/`deployable?` on the victim stack.

### Citations

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

**File:** app/models/shipit/commit.rb (L57-58)
```ruby
    delegate :broadcast_update, :github_repo_name, :hidden_statuses, :required_statuses, :blocking_statuses,
             :soft_failing_statuses, to: :stack
```

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L231-237)
```ruby
    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
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
