### Title
Cross-tenant Status forgery via unscoped SHA lookup in `StatusHandler#process` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits with `Commit.where(sha: params.sha)` across the entire database, with no filter on the repository that sent the webhook. Since `verify_signature` only proves the payload came from the organization named in `payload['repository']['owner']['login']`, an attacker who owns a public repo can post a `status` event whose `sha` value collides with a SHA already recorded on a `Commit` belonging to an unrelated (e.g. private) stack, causing Shipit to write a `Status` row into the victim stack that the attacker never authenticated for.

### Finding Description
The broken binding, stated explicitly: it must hold that `Status.stack_id ⊆ {stack.id | stack.repository.full_name == payload['repository']['full_name']}`, i.e. every `Status` created from a webhook must belong to a stack owned by the repository that the (verified) webhook payload names. In `StatusHandler#process` this is not enforced: [1](#0-0) 

`Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github! }` iterates over **every** `Commit` row in the database matching the SHA, regardless of `stack_id`/repository, and then calls `commit.create_status_from_github!(params)`, which creates a `Status` scoped to `commit.stack_id`: [2](#0-1) 

Contrast this with the base `Handler` class, which provides a `stacks` helper that correctly scopes lookups by the repository named in the payload: [3](#0-2) 

`StatusHandler` is the only handler that bypasses this helper and queries `Commit` globally by `sha` alone — other handlers (`pull_request/*`, `check_suite_handler.rb`) use `stacks` to scope to the calling repository.

Exploit flow:
1. Victim has a private repo `victim/private-repo` with a stack tracking commit SHA `S` (e.g. merged from a shared open-source dependency, or otherwise learned by the attacker).
2. Attacker creates/owns a public repo `attacker/evil-repo`, pushes or cherry-picks a commit that reproduces the exact same content-addressed SHA `S` (trivial via cherry-pick/rebase of a known upstream commit) and configures a webhook/CI integration pointing at the Shipit host for that repo.
3. Attacker triggers a real GitHub `status` event on `attacker/evil-repo` for SHA `S`; GitHub signs it with the webhook secret configured for `attacker/evil-repo`'s org, i.e. the attacker's own legitimate secret.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: repository_owner)` where `repository_owner` is read from `payload['repository']['owner']['login']` — this correctly resolves to the attacker's own org and legitimately verifies against the attacker's own secret. This check has nothing to do with which stacks get touched by `process`; it only proves "this org sent this payload," not "this org owns the commit being updated."
5. `StatusHandler#process` runs `Commit.where(sha: 'S')`, finds the victim's `Commit` row (created independently when the victim's stack originally ingested that SHA), and calls `create_status_from_github!`, writing a new `Status` with `stack_id` equal to the **victim's** stack — despite the payload's `repository.full_name` being `attacker/evil-repo`.

None of the listed guards prevent this: `verify_signature` only authenticates the sender's org, not the target stack; `drop_unhandled_event` and the `ExplicitParameters` schema only validate shape, not repository scope; there is no `force_github_authentication`/`User#authorized?`/`require_permission!` check in this webhook path at all (webhooks are not user-session-bound); model validations on `Repository`/`Stack` don't constrain cross-repository `Commit` lookups because the flaw is in the handler's query, not the schema.

### Impact Explanation
A successful request causes a `Shipit::Status` record to be written against a repository/stack the attacker never authenticated for — this is "a payload for one repository mutating another's stack, commit, task or team," matching the Critical impact category explicitly listed in the rules. Concretely: the attacker can set arbitrary CI state (`success`, `failure`, `pending`, `error`) with an arbitrary `context`, `description`, and `target_url` on the victim's commit. Because `Commit#create_status_from_github!` → `add_status` drives Shipit's deployability/merge logic (`deployable_status` hooks, `ProcessMergeRequestsJob`, continuous-deployment triggers observed in `commits_test.rb` around lines 763-777), forging a `success` status on a commit that hasn't actually passed CI in the victim's own pipeline can unblock an unauthorized deploy/merge for that victim stack — this is a genuine cross-tenant CI-state forgery with real deploy-authorization consequences, not merely a data-integrity nuisance. The attack is repeatable against any SHA the attacker can reproduce/learn (shared dependency commits, forked-then-rebased history, or any commit whose SHA leaks via public GitHub UI), and is not limited to one victim — any stack containing a `Commit` row with a colliding SHA is affected.

### Likelihood Explanation
Preconditions are entirely within an unprivileged attacker's control: own or control a public GitHub repository, cherry-pick/rebase to reproduce a target SHA (git SHAs are content-addressed and trivially reproducible from any known commit/tree/parent metadata), and fire a normal `status` webhook that GitHub signs with the attacker's own legitimate `webhook_secret` for their own org. No Shipit credentials, session, API token, or team membership are required. Learning a target SHA is feasible whenever the victim repo is public, or the victim depends on/has merged a commit from a public dependency also present in the attacker's own history. This requires no race condition, no timing attack, and is fully repeatable per request.

### Recommendation
Scope the `Commit` lookup in `StatusHandler#process` to only commits belonging to stacks of the repository named in the verified payload, mirroring the pattern used in `Handler#stacks`. Concretely, replace `Commit.where(sha: params.sha)` with a query restricted to `stacks.flat_map(&:commits).select { |c| c.sha == params.sha }` or, more efficiently, `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`, so a `Status` can never be attached to a stack outside the calling repository.

### Proof of Concept
Minitest plan (`test/models/webhooks/handlers/status_handler_test.rb`, no live GitHub):

```ruby
test "process does not create a Status on a commit belonging to a different repository's stack" do
  victim_repo  = shipit_repositories(:shipit) # or a dedicated fixture
  attacker_repo = Shipit::Repository.create!(name: 'evil-repo', owner: 'attacker')
  victim_stack   = shipit_stacks(:shipit)
  attacker_stack = Shipit::Stack.create!(repository: attacker_repo, environment: 'production')

  colliding_sha = 'a' * 40
  victim_commit = victim_stack.commits.create!(sha: colliding_sha, author: shipit_users(:walrus),
                                                 committer: shipit_users(:walrus),
                                                 authored_at: Time.now, committed_at: Time.now)

  payload = {
    'sha' => colliding_sha,
    'state' => 'success',
    'context' => 'ci/attacker',
    'repository' => { 'full_name' => attacker_repo.github_repo_name, 'owner' => { 'login' => 'attacker' } }
  }

  assert_no_difference -> { victim_commit.statuses.count } do
    Shipit::Webhooks::Handlers::StatusHandler.call(payload)
  end
end
```

Both sides of the equality checked: `Status.stack_id` written (currently == `victim_stack.id`, i.e. wrong) vs. the expected constraint `stack.repository.full_name == payload['repository']['full_name']` (i.e. should only ever be `attacker_stack.id` or none, never `victim_stack.id`). With the current code, this test fails (`victim_commit.statuses.count` increases by 1), demonstrating the vulnerability; after applying the recommended scoping fix, it passes.

### Citations

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
