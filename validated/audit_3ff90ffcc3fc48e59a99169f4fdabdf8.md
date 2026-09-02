### Title
Cross-tenant commit status forgery via unscoped `Commit.where(sha:)` in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`WebhooksController#verify_signature` only authenticates the webhook body against the `webhook_secret` of the organization named in the payload's `repository.owner.login`. `StatusHandler#process` then applies the status update to *every* `Commit` row sharing the same `sha`, with no filter on repository/stack ownership, so a status webhook authenticated for org A also mutates commits belonging to org B if the same sha happens to exist in both stacks.

### Finding Description
The intended binding is: `organization_that_signed_the_webhook == organization_owning_every_Commit_row_mutated`. The code path is:

1. `WebhooksController#verify_signature` computes `repository_owner` from `params.dig('repository','owner','login')` and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`, validating the HMAC only against org A's `webhook_secret`. [1](#0-0) [2](#0-1) 

2. `create` dispatches the parsed JSON to the handler with no reference to which org verified it: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`. [3](#0-2) 

3. `StatusHandler#process` looks up commits purely `Commit.where(sha: params.sha)` — no join/filter on `stack_id`, `repository_id`, or the `repository_owner`/`repository.full_name` that was actually verified — and calls `commit.create_status_from_github!(params)` on every match, across every Stack/Repository in the database. [4](#0-3) 

Root cause: SHA is not a repository-scoped unique key in Shipit's schema (multiple `Stack`/`Repository` rows can independently record a `Commit` with the same `sha`, e.g. a fork pushing a copy of a public commit). The handler assumes sha uniqueness implies ownership uniqueness, but the only authentication performed upstream is scoped to a single org derived from the payload, not to the specific `Commit` rows this handler will touch.

Attacker flow: attacker forks/owns a repo (org B) connected to Shipit as its own Stack, and pushes/creates a commit with the identical sha as some existing public commit that's already tracked under org A's Stack (trivial since git commit shas are content-addressed and copyable, e.g. cherry-pick or fetching the same commit into their fork). Attacker's own repo emits a `status` webhook (or attacker can trigger one, e.g. via their own CI) signed with **org B's** `webhook_secret`. `verify_signature` succeeds because it validates against org B (the org in the payload), which the attacker legitimately owns/controls. `StatusHandler#process` then finds both org B's Commit row and org A's Commit row (same sha) and rewrites CI state (`state`, `description`, `target_url`) on org A's commit too — a write to org A's Stack that org A never authenticated.

None of the existing guards prevent this: `verify_signature` only checks the signing org, not which Commit rows get mutated; there is no `ExplicitParameters` constraint tying sha to repository; `drop_unhandled_event` and `check_if_ping` are unrelated; there's no `stacks`-scope or `Repository`/`Stack` validation preventing duplicate shas across different stacks.

### Impact Explanation
A payload authenticated by org B's `webhook_secret` causes a database write on a `Commit` belonging to org A's `Stack`/`Repository`, changing that commit's CI status (`state`, `context`, `description`, `target_url`), which can affect merge/deploy gating logic in Shipit that reads commit statuses. This is a cross-tenant write triggered by a webhook authenticated for a different, attacker-controlled organization — matching the Critical category "a payload for one repository mutating another's stack/commit". It's repeatable against any sha the attacker can duplicate into their own fork/stack, and generalizes to any pair of Stacks sharing a sha.

### Likelihood Explanation
Preconditions: two Stacks already exist in Shipit tracking the same sha (attacker forks a public repo tracked by Shipit and gets their fork also configured as a Shipit Stack, then pushes/fetches the identical commit). This requires the attacker's own fork to be onboarded as a Stack (something an unprivileged GitHub user commonly can do if the host app allows self-service stack creation), and requires no secrets beyond the attacker's own repo's `webhook_secret`, which the attacker legitimately possesses for their own org. Given these ordinary preconditions, the exploit is cheap and fully repeatable.

### Recommendation
Scope the commit lookup in `StatusHandler#process` (and any other sha-based handler) to the repository actually verified in `verify_signature`, e.g. filter through `Stack`/`Repository` matching `params.dig('repository','full_name')` or `repository_owner`, instead of a bare `Commit.where(sha:)` across all tenants. Pass the verified repository identity from the controller into the handler and enforce it in the query (e.g., `Commit.joins(:stack).where(sha: params.sha, stacks: { repository_id: verified_repository.id })`).

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`, out-of-scope path noted only for reference — actual test lives under `test/`):

```ruby
test "status webhook verified only for org A also mutates org B's commit sharing the same sha" do
  shared_sha = 'a' * 40

  stack_a = shipit_stacks(:shipit)          # belongs to org A
  stack_b = create(:stack, repository: create(:repository, owner: 'org-b', name: 'fork'))

  commit_a = create(:commit, stack: stack_a, sha: shared_sha)
  commit_b = create(:commit, stack: stack_b, sha: shared_sha)

  # Binding under test: verifying_org == mutated_commit.stack.repository.owner
  assert_equal 'org-b', commit_b.stack.repository.owner # attacker's own org signs
  refute_equal 'org-b', commit_a.stack.repository.owner # commit_a belongs to org A

  params = Shipit::Webhooks::Handlers::StatusHandler::Params.new(
    sha: shared_sha, state: 'success', context: 'ci', description: 'ok', target_url: 'http://x'
  )

  Shipit::Webhooks::Handlers::StatusHandler.new.process(params) # simulates verified-by-org-B dispatch

  assert_equal 'success', commit_a.reload.status.state # FAILS the intended binding: org A's row mutated
  assert_equal 'success', commit_b.reload.status.state
end
```

This demonstrates that a single verification against org B propagates writes to `commit_a`, which belongs to a stack/org that never signed the request — violating `verifying_org == owner_of_every_mutated_Commit`.

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
