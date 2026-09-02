### Title
`StatusHandler#process` writes `Status` records by bare SHA across all repositories, letting an attacker's own webhook flip `review/approved` on a victim's commit - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits with `Commit.where(sha: params.sha)` with no repository/stack scoping, unlike the base `Handler` class's `stacks` helper that every repository-scoped handler is meant to use. Because Shipit's `commits` table only enforces uniqueness on the pair `["sha", "stack_id"]` (not on `sha` alone), the same SHA can legitimately exist in more than one stack (e.g. a victim stack and an attacker-controlled fork/stack sharing history), so a status webhook that GitHub only ever signed for the attacker's own repository ends up writing a `Status` onto the victim's `Commit` row.

### Finding Description
The broken binding is: **"a `status` webhook authenticated for repository R should only create/update statuses on commits belonging to stacks of R."** In code, this should read `commit.stack.repository == authenticated_repository` for every `commit` touched by the handler. In `StatusHandler`, the actual code is: [1](#0-0) 

`Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` queries the entire `commits` table by bare SHA, with no reference to `repository_name`/`stacks`. Compare this to the scoping helper defined for exactly this purpose in the base class: [2](#0-1) 

`stacks` resolves `Repository.from_github_repo_name(repository_name)&.stacks`, i.e. it restricts to the stacks that belong to the repository named in the *authenticated* payload. `StatusHandler` never calls it, so it is the odd one out among the registered handlers.

The commit's `sha` column is only uniquely constrained together with `stack_id` (`index_commits_on_sha_and_stack_id`, see `test/dummy/db/schema.rb:85`), which is by design to allow the same SHA to exist across multiple stacks (forks, mirrors, shared history). This is confirmed by `Commit.by_sha` operating within a stack scope (`stack.commits.by_sha`) elsewhere in the codebase, e.g. `app/models/shipit/pull_request.rb:52-58` and `app/models/shipit/merge_request.rb:303-309`, both of which correctly scope lookups through `stack.commits`.

`verify_signature` in `WebhooksController` (`app/controllers/shipit/webhooks_controller.rb:24-49`) only proves the payload came from a GitHub org matching `repository.owner.login` in the payload — it authenticates that the *sender* owns *some* repository, not that the SHA referenced belongs to that repository. Once past that check, `StatusHandler` is invoked for every commit sharing the SHA, system-wide, regardless of which repository actually authenticated the request.

**Exploit flow**: an attacker registers/owns a repository whose commit history overlaps a victim's tracked repository (e.g. a fork of the victim repo, added as its own Shipit stack, or sharing a common ancestor commit that is also present in the victim's stack). The attacker pushes a legitimately signed `status` webhook for their own repository with `sha` set to a SHA also present in the victim's commit history, `context: review/approved`, `state: failure`. `StatusHandler#process` matches both the attacker's own commit row and the victim's commit row (same SHA, different `stack_id`), and calls `commit.create_status_from_github!(params)` on the victim's `Commit` too. This creates a `Status` on the victim's commit through `commit.statuses.replicate_from_github!(stack_id, github_status)` (`app/models/shipit/commit.rb:165-168`), using the *victim's own* `stack_id`, so the status is fully "valid-looking" in the victim's stack.

Because `Status::Common#required?`/`#blocking?` evaluate `context` against the *victim's own* `required_statuses`/`blocking_statuses` (delegated to the victim's `stack`, `app/models/shipit/commit.rb:57-58`, `app/models/shipit/status/common.rb:46-52`), if the victim's `deploy_spec` requires `review/approved`, this attacker-injected `failure` status transitions the victim commit's `state` (per the `unknown/pending -> failure` transition rules exercised in `test/models/commits_test.rb:671-712`), which propagates into `Stack#branch_status`/`Stack#merge_status` (`app/models/shipit/stack.rb:286-300`), blocking deploys or merges on the victim's stack — a cross-repository write triggered entirely by a payload the victim never authenticated.

### Impact Explanation
An unprivileged attacker who controls any Shipit-tracked repository (their own fork, or any repo they can add as a stack) can, with a single legitimately-signed webhook for their own repository, mutate `Status` records tied to a **different tenant's stack and commit**, forcing that stack's deployability/merge state to flip based on a fabricated `review/approved: failure` (or `success`) verdict. This is repeatable against any victim stack whose commit history shares a SHA with an attacker-controlled repository, and directly fits the specified Critical category: "a payload for one repository mutating another's stack, commit ... or an unauthorized deploy, rollback or merge" being blocked or forced. The blast radius is bounded to commits with shared SHAs (typically forks/mirrors of the same upstream history), but within that boundary the attacker has full control over injecting arbitrary state/context statuses onto the victim's commit.

### Likelihood Explanation
Preconditions: the attacker needs (a) a GitHub repository they control that can deliver a validly-signed webhook to the shared Shipit instance (i.e. it is tracked as/associated with a Shipit stack or otherwise covered by `Shipit.github(organization: repository_owner)`), and (b) at least one commit SHA shared with the victim's tracked repository (trivially achievable by forking the victim repo — fork commits retain identical SHAs for shared history). No Shipit session, API token, or GitHub team membership is required — only the ability to push to their own repo and have GitHub deliver the webhook. This is low-cost and fully repeatable against any SHA the attacker can arrange to share with a target.

### Recommendation
Scope `StatusHandler#process` to the requesting repository's stacks, mirroring the base `Handler#stacks` helper and the pattern already used in `PullRequest#find_or_create_commit_from_github_by_sha!` / `MergeRequest#find_or_create_commit_from_github_by_sha!`:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
This ensures a status webhook only ever mutates commits belonging to stacks of the repository that authenticated the request.

### Proof of Concept
minitest plan (model-level, no live GitHub, mirrors existing style in `test/models/status_test.rb` / `test/controllers/webhooks_controller_test.rb`):
1. Create `victim_stack` (repo `victim/app`) and `attacker_stack` (repo `attacker/app`), each with a `Commit` row sharing the identical `sha` (`"deadbeef" * 5`) but different `stack_id`.
2. Configure `victim_stack.cached_deploy_spec` to require `context: 'review/approved'` (via `required_statuses`), and assert `victim_commit.reload.state != 'failure'` before the call — the equality under test: `victim_commit.stack_id == victim_stack.id && victim_commit.state == 'pending'`.
3. Invoke `Shipit::Webhooks::Handlers::StatusHandler.call({'sha' => shared_sha, 'state' => 'failure', 'context' => 'review/approved', 'repository' => {'full_name' => 'attacker/app', 'owner' => {'login' => 'attacker'}}})` directly (bypassing controller-level signature verification, which is orthogonal to this bug).
4. Assert `victim_commit.reload.statuses.count` increased by 1 and `victim_commit.reload.state == 'failure'`, and `victim_stack.reload.branch_status == 'failure'` — proving a webhook that only authenticated `attacker/app` mutated `victim_stack`'s deployability state, violating the stated invariant that "a `review/approved` status affects only the repository that authenticated it."

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
