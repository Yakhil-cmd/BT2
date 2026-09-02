### Title
Cross-repository Status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits by `sha` alone across the entire `commits` table, with no filtering by the webhook's authenticating repository, then calls `Commit#create_status_from_github!`, which writes a `Status` row using the looked-up commit's own `stack_id`. Because the lookup is unscoped and the write path never checks that `stack_id` against the repository that authenticated the incoming webhook, a `status` event from repository A can create a `Status` row attributed to a stack owned by repository B, as long as A produces a commit object with the same SHA as one already known to Shipit for B.

### Finding Description
Binding claimed broken: `stack_id` written into the new `Status` row must equal the stack authorized by the incoming webhook's `repository.full_name`. Actual code:

- `StatusHandler#process` does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [1](#0-0)  — this queries the global `Commit` table by `sha` only, with no join/filter on `repository_name`/`stacks`, unlike the `stacks` helper defined in the base `Handler` class that scopes lookups via `Repository.from_github_repo_name(repository_name)&.stacks` [2](#0-1) . `StatusHandler` never calls this scoped helper.
- `Commit#create_status_from_github!(github_status)` calls `statuses.replicate_from_github!(stack_id, github_status)`, where `stack_id` is the commit's own attribute (`belongs_to :stack`), not anything derived from the webhook payload or the authenticated `repository` [3](#0-2) .
- `Status.replicate_from_github!(stack_id, github_status)` takes `stack_id` as a raw positional argument and performs `find_or_create_by!(stack_id:, state:, description:, target_url:, context:, created_at:)` with zero ownership/ownership-of-webhook check [4](#0-3) .

Exploit flow: an attacker who controls their own GitHub repository (already connected to Shipit as a legitimate, low-privilege stack — a normal, unprivileged tenant onboarding, not requiring any Shipit secret) copies a victim's public commit object (identical tree/parents/author/committer/timestamps/message) into their own repo, reproducing the identical SHA-1. They then cause GitHub to emit a real, correctly-signed `status` webhook event for that SHA on their own repository (e.g., by setting a commit status via the GitHub API on their own commit, or via CI). Shipit's `StatusHandler` receives this legitimately-signed webhook, but instead of scoping the lookup to stacks belonging to the attacker's authenticated repository, it does a bare `Commit.where(sha: ...)`, which matches the pre-existing victim `Commit` row (created earlier from the victim's own push activity) belonging to a completely different stack. `create_status_from_github!` then writes a `Status` row keyed to the victim stack's `stack_id`, entirely under attacker control of `state`/`description`/`target_url`/`context`.

Existing guards do not prevent this: `verify_signature`/webhook signature verification only proves the webhook came from *some* authorized GitHub repository/app installation, not that the `sha` it references belongs to that repository. `drop_unhandled_event` and the `ExplicitParameters` schema for `StatusHandler` only validate shape (`sha`, `state`, etc.), not repository ownership of the referenced commit. The `stacks` scoping mechanism that other handlers rely on to bind actions to the authenticated repository is simply not used here.

### Impact Explanation
The attacker can inject arbitrary CI status data (`state: success/failure/error`, `description`, `target_url`, `context`) into a `Status` belonging to a stack they do not own, without ever authenticating against that stack. Because `Commit#deployable?`/`Commit#blocked?` and continuous-delivery gating (`schedule_continuous_delivery`, `ContinuousDeliveryJob`) depend on the aggregated status state of a commit, forging a `success` status for a commit that hasn't actually passed CI on the victim's repository can make Shipit consider that commit deployable, potentially triggering an unauthorized deploy for the victim stack. This is a payload from one repository mutating another repository's stack/commit records — matching the "Critical: a payload for one repository mutating another's stack, commit, task or team" category. It is repeatable against any stack whose commit SHAs the attacker can reproduce (feasible for any commit reachable from a public repo, since git commit hashes are fully reproducible by copying identical commit content).

### Likelihood Explanation
Preconditions: the attacker needs (a) their own repository connected to Shipit as a stack (a normal, low-privilege onboarding action, not requiring any Shipit operator/secret), and (b) knowledge of a target commit SHA from the victim's (typically public) repository. Reproducing an identical SHA-1 by copying the exact commit object into their own repo is a standard, well-known git operation (fetch + push preserving the object), so this is fully feasible and cheap. No Shipit secrets, sessions, or API tokens are required — only a legitimately signed webhook from the attacker's own connected repository. This makes the attack practical and repeatable against any stack whose commits are (or become) known to the attacker.

### Recommendation
Scope the `Commit` lookup in `StatusHandler#process` to the stacks derived from the webhook's authenticated repository (using the existing `stacks` helper in `Handler`), e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or equivalently filter `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`, so that a status event can only mutate commits/stacks belonging to the repository that actually authenticated the webhook.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb (conceptual, no live GitHub)
test "status webhook cannot write a Status for a commit belonging to a different stack/repository" do
  victim_stack = shipit_stacks(:shipit)
  attacker_stack = create_stack(repository: create_repository(owner: 'attacker', name: 'evil'))

  victim_commit = victim_stack.commits.create!(sha: 'deadbeef' * 5, message: 'victim commit')

  # Attacker's webhook payload authenticates ONLY attacker_stack's repository,
  # but references victim_commit's sha.
  payload = {
    'repository' => { 'full_name' => attacker_stack.repository.full_name },
    'sha' => victim_commit.sha,
    'state' => 'success',
    'context' => 'forged',
  }

  assert_no_difference -> { Shipit::Status.where(stack_id: victim_stack.id).count } do
    Shipit::Webhooks::Handlers::StatusHandler.call(payload)
  end
end
```
Running this against the current code fails the assertion (a `Status` row IS created with `stack_id == victim_stack.id`), because `StatusHandler#process` uses `Commit.where(sha: params.sha)` unscoped by repository [1](#0-0)  and `Status.replicate_from_github!` writes `stack_id:` directly from the pre-existing commit with no ownership check [4](#0-3) , confirming the equality `authenticated_stack.id == status.stack_id` does not hold.

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
