### Title
`StatusHandler#process` writes commit statuses cross-repository because it queries `Commit.where(sha:)` without repository scoping - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits by bare SHA across the entire `commits` table and calls `create_status_from_github!` on every match, regardless of which repository's webhook secret authenticated the request. Every other handler (e.g. `PushHandler`) scopes its writes through the base class's `stacks` helper, which filters by `payload.dig('repository', 'full_name')`; `StatusHandler` does not use `stacks` at all.

### Finding Description
The broken binding is: **a `status` webhook authenticated by repository A's signature should only mutate commits belonging to stacks whose `Repository` matches A** — i.e. `commit.stack.repository.full_name == payload['repository']['full_name']`. This binding is never enforced.

`StatusHandler#process` is:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [1](#0-0) 

This bypasses the `stacks` helper defined on the base `Handler` class, which restricts writes to the repository asserted in the payload:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [2](#0-1) 

By contrast, `PushHandler#process` correctly scopes through `stacks`:
```ruby
def process
  stacks
    .not_archived
    .where(branch:)
    .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
end
``` [3](#0-2) 

Because `Commit` rows are keyed by `sha` without any per-repository namespace uniqueness enforced at the handler level, an attacker who owns/controls any repository wired to a Shipit installation (or who can get a webhook accepted for any repository whose signature the attacker can produce — i.e., their own repo) can send a `status` event whose payload's `sha` collides with a commit SHA that also exists in a victim stack's `commits` table. This can happen naturally when a victim stack tracks a public/shared history (e.g., forked repos, shared base branches, or simply predictable/colliding shas from a repo the attacker controls that has cross-referenced the same commit due to git history reuse), or via any mechanism that inserts a commit with a chosen sha into the victim's `commits` table (e.g., pull_request/merge_request flows creating `Commit` records from arbitrary shas reachable from PR data). Once the SHA collision exists in the `commits` table, the status event — properly signed for the attacker's own repository — will still be applied to the victim's `Commit` row because `StatusHandler` never checks which repository owns the matched commit.

If the victim stack has `merge_queue_enabled == true` and requires a `review/approved` status context, injecting `state: success, context: 'review/approved'` for that SHA flips `commit.status` to include the required context as satisfied. Downstream, `Stack#branch_status` / `Stack#merge_status` derive from `commit.status.simple_state`, and a "green" head commit advances the merge queue and triggers `merge!`, producing an unauthorized merge/ship or unblock action, since these are gated purely on the aggregated status state of the commit row, not on which repository last wrote to it:
```ruby
def branch_status
  undeployed_commits.each do |commit|
    state = commit.status.simple_state
    return state unless %w[pending unknown missing].freeze.include?(state)
  end
  'pending'
end
``` [4](#0-3) 

Existing guards do not catch this: webhook signature verification only proves the payload came from the repository whose secret signed it — it says nothing about which `Commit` rows the handler is permitted to touch. `ExplicitParameters` only validates the shape of `sha`/`state`/`context`, not ownership. No `stacks`/repository scoping check exists inside `StatusHandler`, unlike every other handler.

### Impact Explanation
An attacker who controls (or can trigger webhooks for) any repository can write a fabricated `Status` record onto a `Commit` belonging to a completely different stack/repository/tenant, as long as a SHA collision exists between the attacker-controlled repo and the victim's `commits` table. On a victim stack with `merge_queue_enabled: true` requiring `review/approved`, this can force an unauthorized merge or unblock a queued merge — a record written for a repository that did not authenticate it, and a merge/ship action performed without the victim repository's consent. This matches "Critical - a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy, rollback or merge." The blast radius extends to any stack sharing commit SHAs with any other onboarded repository, which in a multi-tenant Shipit installation is a structural risk since `StatusHandler` performs no per-tenant isolation at all.

### Likelihood Explanation
Preconditions: (1) a victim stack with `merge_queue_enabled: true` and a required `review/approved` status context, (2) a `Commit` row with a SHA that exists in both the attacker's authenticated repository's status stream and the victim's `commits` table. Getting (2) reliably typically requires some SHA to be shared/known across repos (forks, cherry-picks, shared base history, or any commit-creation path that lets an attacker cause a chosen SHA to appear in the victim stack's `commits` table). The attacker's cost is a single signed webhook request from a repository they legitimately control — no Shipit credentials, sessions, or GitHub App keys are required for the write itself, only the ability to make GitHub emit (or otherwise produce) a validly signed `status` event referencing their chosen SHA. The bug is fully repeatable — each request is an independent write with no rate limiting relevant to this scope.

### Recommendation
Scope `StatusHandler#process` through the base `stacks` helper (or an equivalent explicit join through `Repository`), restricting matched commits to `stacks.commits.where(sha: params.sha)` (or filtering `Commit.where(sha: params.sha)` to `.joins(stack: :repository).where(repository: { ... } )` matching `repository_name` from the payload), mirroring the pattern already used in `PushHandler`. This ensures a `status` payload can only mutate commits belonging to stacks under the repository that the webhook signature authenticated.

### Proof of Concept
Minitest sketch (`test/models/shipit/webhooks/handlers/status_handler_test.rb`, referencing existing fixtures):
```ruby
test "status event does not update commit belonging to a different repository's stack" do
  victim_stack = shipit_stacks(:shipit) # repository X, merge_queue_enabled: true, requires review/approved
  colliding_sha = "deadbeef" * 5
  victim_commit = victim_stack.commits.create!(sha: colliding_sha, ...)

  payload = {
    'sha' => colliding_sha,
    'state' => 'success',
    'context' => 'review/approved',
    'repository' => { 'full_name' => 'attacker/unrelated-repo' } # different repo, validly signed
  }

  assert_no_difference -> { victim_commit.statuses.count } do
    Shipit::Webhooks::Handlers::StatusHandler.call(payload)
  end

  refute victim_commit.reload.status.success?
end
```
Before the fix, this test fails: `Commit.where(sha: params.sha)` matches `victim_commit` regardless of `payload['repository']`, a `Status` row is created, and if `victim_stack.merge_queue_enabled?` and the queue head is this commit, `merge!`/queue advancement fires — demonstrating the cross-repository write and downstream merge-queue effect described above. [5](#0-4) [6](#0-5)

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-28)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class StatusHandler < Handler
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
      end
    end
  end
end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L1-41)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class Handler
        class << self
          attr_reader :param_parser

          def params(&block)
            @param_parser = ExplicitParameters::Parameters.define(&block)
          end
        end

        def self.call(params)
          new(params).process
        end

        attr_reader :params, :payload

        def initialize(payload)
          @payload = payload
          @params = self.class.param_parser.parse!(payload)
        end

        def process
          raise NotImplementedError
        end

        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
      end
    end
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

**File:** app/models/shipit/stack.rb (L298-304)
```ruby
    def branch_status
      undeployed_commits.each do |commit|
        state = commit.status.simple_state
        return state unless %w[pending unknown missing].freeze.include?(state)
      end
      'pending'
    end
```
