### Title
Unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` lets any repository's webhook write status/blocking state onto commits belonging to another repository's stack - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits by bare SHA across the entire `commits` table with no repository scoping, unlike the base `Handler#stacks` helper used by other handlers (e.g. `push_handler.rb`) which scopes to `Repository.from_github_repo_name(repository_name)&.stacks`. Because `commits.sha` is only indexed/scoped `(stack_id, sha)` and not globally unique, a status webhook that is validly signed for repository A can flip a `Status` row (context `ci/integration`, state `success`) on a `Commit` that actually belongs to a different stack/repository B whenever the two share a commit SHA (common with forks, mirrors, or repos with shared history).

### Finding Description
The broken binding: the intended invariant is `commit.stack.repository.full_name == payload['repository']['full_name']` for every commit touched by a status webhook, i.e. `Status.for(commit) ⟺ webhook_repository == commit.repository`. This invariant is enforced for other events via `Handler#stacks` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`), which restricts affected records to `Repository.from_github_repo_name(repository_name)&.stacks`. `StatusHandler#process` does not use this helper at all: [1](#0-0) 

Instead it runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`, which is a global, unscoped query against the `commits` table across every stack/repository in the Shipit instance.

`Shipit::WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-30`) only proves that the payload was signed by GitHub for the organization named in `payload['repository']['owner']['login']` — it authenticates *who sent the request*, not *which commit records may be mutated*. Nothing after that maps the verified repository back onto the SHA lookup in `StatusHandler`.

Once `commit.create_status_from_github!(params)` runs (`app/models/shipit/commit.rb:165-169`), it creates a `Status` row via `statuses.replicate_from_github!`, which feeds into `Commit#status`, `Commit#blocked?` (`app/models/shipit/commit.rb:231-237`) and `Commit#deployable?` (`app/models/shipit/commit.rb:227-229`). If the victim stack has `blocking_statuses` configured requiring `ci/integration`, injecting a `success` status for that context on a commit shared with the attacker's own repo can clear (or, with a `failure`/`error` state, set) `blocked?`, directly gating `deployable?` and thus continuous delivery/merge behavior (`schedule_continuous_delivery`, `stack.schedule_merges` in `add_status`, `app/models/shipit/commit.rb:281-287` and `366-386`).

Exploit flow: attacker owns/controls repository A (can install/authorize GitHub webhooks on it, e.g. via a public GitHub App install or by pushing to their own repo and letting GitHub deliver a real, correctly signed `status` event). Attacker crafts or arranges a commit SHA in repo A that is identical to a SHA present in victim stack B's `commits` table (fork/mirror/shared-history scenario is sufficient — no hash collision needed). Attacker (or GitHub, triggered by attacker's CI) sends a `status` webhook with `context: ci/integration`, `state: success` for that SHA. `verify_signature` succeeds because it validates against repo A's/organization A's app secret, which is legitimate for repo A. `StatusHandler#process` then updates the `Status` for **every** `Commit` row with that SHA, including the one belonging to victim stack B, silently flipping B's `blocked?`/`deployable?` state.

### Impact Explanation
A payload correctly authenticated for repository A causes a state mutation (status/blocking state, and consequently deploy-gating `deployable?`) on repository B's stack/commit records — this is exactly the "payload for one repository mutating another's stack, commit, task or team" Critical category. The blast radius is any Shipit instance hosting multiple stacks that can share commit SHAs (forks, mirrors, monorepo-derived stacks, or shared upstream history), and the attack is repeatable at will since the attacker fully controls the SHA/context/state they push from their own authenticated repository.

### Likelihood Explanation
Preconditions: victim stack must have `blocking_statuses` (or `required_statuses`) configured for a context the attacker can also emit (e.g. `ci/integration`), and a SHA collision/overlap must exist between attacker-controlled repo A and victim stack B's commit history — a realistic scenario for forked repositories, repositories that mirror a shared upstream, or organizations running multiple Shipit stacks off overlapping git history. Attacker cost is low: no Shipit credentials, GitHub App secret, or team membership needed — only control of a repository with a genuine GitHub webhook signed by GitHub itself. The attack is fully repeatable and scriptable.

### Recommendation
Scope `StatusHandler#process` the same way other handlers scope their writes: restrict the `Commit` lookup to commits belonging to stacks under `Repository.from_github_repo_name(payload.dig('repository','full_name'))` (i.e., reuse/extend the existing `stacks` helper in `app/models/shipit/webhooks/handlers/handler.rb`) before calling `create_status_from_github!`, e.g. `Commit.where(sha: params.sha, stack_id: stacks.select(:id)).each { ... }`.

### Proof of Concept
Minitest plan (no live GitHub, direct handler invocation as `WebhooksController` would after signature verification):
1. Create `repository_a` (`full_name: "attacker/repo"`) with `stack_a`, and `repository_b` (`full_name: "victim/repo"`) with `stack_b` where `stack_b`'s deploy spec configures `blocking_statuses` to include `ci/integration`.
2. Create `commit_b` under `stack_b` with a fixed `sha` (e.g. `"a" * 40`) and no existing `ci/integration` status, and assert `commit_b.blocked?` reflects the pre-status state (e.g. blocked by an existing separate blocking commit, or assert `commit_b.deployable?` is `false` prior to the injected success while another blocking status exists).
3. Create `commit_a` under `stack_a` with the **same** `sha` value.
4. Build a webhook payload: `{ "sha" => sha, "state" => "success", "context" => "ci/integration", "repository" => { "full_name" => "attacker/repo", "owner" => { "login" => "attacker" } } }`.
5. Call `Shipit::Webhooks::Handlers::StatusHandler.call(payload)` directly (bypassing controller-level signature check, which is orthogonal to this bug).
6. Assert: `commit_b.reload.blocked?` (or `.deployable?`) changed as a result — proving repo A's payload mutated stack B's commit — while `commit_a` also received the same status (expected, same-repo case), demonstrating the equality `commit.stack.repository.full_name == payload['repository']['full_name']` is violated for `commit_b`.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
