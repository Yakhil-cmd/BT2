### Title
Cross-tenant status mutation via unscoped SHA lookup in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits by `Commit.where(sha: params.sha)` with no scoping to the repository/stack that the verified webhook belongs to. Since git commit SHAs are content-addressed and identical commits routinely exist across forks/shared history, a single status webhook verified for one repository can mutate `Commit`/`Status` state for every stack across every tenant repository that happens to share that SHA.

### Finding Description
The intended binding is: `webhook.repository.full_name == commit.stack.repository.full_name` for every `Commit` mutated by a single verified webhook call — i.e., a webhook signed for repository R should only ever affect commits belonging to stacks tied to R.

In practice: [1](#0-0) 
`process` runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — a bare, repository-agnostic query across the entire `commits` table.

Contrast this with the base `Handler` class, which does provide a repository-scoped helper: [2](#0-1) 
`stacks` resolves `Repository.from_github_repo_name(repository_name)&.stacks`, scoping to the webhook's own repository. `StatusHandler` does not use this helper at all, so nothing constrains the `.each` to commits whose `stack.repository` matches the webhook's `repository_owner`/`full_name`.

`WebhooksController#verify_signature` only authenticates that the payload was signed by the named repository's/org's webhook secret — it says nothing about which `Commit` rows the handler is permitted to touch: [3](#0-2) 

Exploit flow: an attacker who owns/forks a repository (or triggers a build on any repo) causes a `status` event to be delivered for a commit SHA that is also present in some other tenant's stack (e.g., a shared root commit, a rebased/cherry-picked commit that keeps the same SHA, or the well-known empty tree SHA `4b825dc642cb6eb9a060e54bf8d69288fbee4904`, which is content-identical and can appear in unrelated repos' histories with `Commit` rows if such a commit was ever ingested). The webhook is signed correctly for the attacker's own repository, passes `verify_signature`, and reaches `StatusHandler#process`. Because the SHA lookup is global, `create_status_from_github!` is invoked on every matching `Commit`, regardless of which stack/repository owns it, mutating status state (`add_status`), emitting `Hook.emit(:commit_status, ...)`, and potentially calling `stack.schedule_merges` and enqueueing `ContinuousDeliveryJob` for a stack the attacker never authenticated for.

### Impact Explanation
A single unprivileged, correctly-signed webhook for repository A can write `Status` records and flip commit/task state for stacks belonging to unrelated repository B (and C, D, ... N) whenever a `Commit.sha` collision exists across tenants. This can move a foreign stack's commit into a "success" state, trigger `stack.schedule_merges`, and schedule `ContinuousDeliveryJob`, i.e., influence an unauthorized deploy decision for a tenant that did not send or authorize that webhook. This matches the Critical category: "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy."

### Likelihood Explanation
The precondition is a shared `sha` value across `Commit` rows belonging to different stacks — plausible via shared git history (forks, common ancestor commits, or content-identical commits such as the canonical empty-tree SHA) which are commonly ingested by Shipit as part of normal commit-sync flows. No secrets, sessions, or elevated privileges are required — the attacker only needs to control (or trigger CI/status delivery for) a repository whose webhook is registered with Shipit, which is the normal, minimal configuration for any tenant repo. The attack is trivially repeatable (send another `status` webhook) and requires no interaction with the victim.

### Recommendation
Scope the lookup to the webhook's own repository, mirroring the `Handler#stacks` helper, e.g. replace `Commit.where(sha: params.sha)` with a query restricted to `stacks.commits.where(sha: params.sha)` (or join through `Stack`/`Repository` matching `payload.dig('repository', 'full_name')`), so only commits belonging to stacks of the authenticated repository can be updated.

### Proof of Concept
Minitest plan (under `test/models/shipit/webhooks/handlers/status_handler_test.rb`):
1. Create two `Repository`/`Stack` fixtures for distinct orgs, e.g. `repo_a` (`org-a/repo`) and `repo_b` (`org-b/repo`).
2. Create `Commit.create!(stack: stack_a, sha: "deadbeef...")` and `Commit.create!(stack: stack_b, sha: "deadbeef...")` with the same `sha`.
3. Build a webhook payload with `repository.full_name = "org-a/repo"` and `sha = "deadbeef..."`, `state = "success"`.
4. Call `Shipit::Webhooks::Handlers::StatusHandler.call(payload)`.
5. Assert: `commit_a.statuses.reload.last.state == "success"` (expected/intended) AND `commit_b.statuses.reload.last.state == "success"` (demonstrates the cross-tenant write that should not occur, since the webhook was only signed/verified for `org-a/repo`).
6. The equality-broken assertion: `webhook.repository.full_name ("org-a/repo") != commit_b.stack.repository.full_name ("org-b/repo")`, yet `commit_b` was mutated — proving the binding violation.

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
