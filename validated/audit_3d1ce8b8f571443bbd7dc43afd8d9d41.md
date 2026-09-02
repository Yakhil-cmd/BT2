### Title
Cross-repo SHA collision in `StatusHandler#process` lets an attacker's repository status trigger deploys on a victim's stack - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` resolves target commits with a global, repository-unscoped query `Commit.where(sha: params.sha)`, unlike every other webhook path in this engine which resolves the target stack via `Repository.from_github_repo_name(repository_name)` before touching any record. Any commit sha that exists in more than one stack (which happens whenever a repository is forked, since git commit SHA-1s are computed from tree/parent/message content and are stable across clones/forks) will receive the incoming status regardless of which repository's webhook produced it, and that write can flip `Commit#deployable?` on a completely unrelated stack, causing `Stack#trigger_continuous_delivery` to call `trigger_deploy`.

### Finding Description
Binding claimed safe: `repository_that_authenticated_the_status_webhook == repository_that_owns_the_stack_being_deployed`. Tracing the code shows this binding is **not enforced**: [1](#0-0) 

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```

This is scoped only by `sha`, globally across the `commits` table (which spans all stacks/repositories), not by the webhook's own `repository.full_name`. Compare this to the base `Handler` class, which already provides a repository-scoped helper that every other handler is expected to use: [2](#0-1) 

`StatusHandler` never calls `stacks` or filters by `repository_name`; it queries `Commit` directly by `sha` only.

Git commit SHA-1s are computed from the commit's tree, parents, author/committer, timestamps and message — they are **not** namespaced by repository. Any commit shared by ancestry between two repositories (most commonly: attacker forks victim's public repository) has an identical `sha` in both repositories. The attacker's fork is a completely separate GitHub repository with its own webhook delivery (`repository.full_name` = attacker's fork), yet its `Status` payload for a shared-ancestor sha will match `Commit.where(sha: ...)` rows belonging to the victim's stack.

Exploit flow:
1. Attacker forks the victim's public repository (or otherwise obtains a repo that shares a commit sha with the victim, e.g. via a shared common ancestor commit that is still undeployed on the victim's stack).
2. Attacker configures/uses their own repository's CI (or crafts an HTTP request that GitHub's webhook delivery for their own repo would produce) so a `status` event with `state: success` and the shared `sha` is delivered to `POST /webhooks`. This webhook is authenticated by GitHub for the attacker's own repository — no victim secret is needed.
3. `StatusHandler#process` executes `Commit.where(sha: params.sha)`, which returns the victim's `Commit` row (same sha, different stack) as well as the attacker's own, and calls `commit.create_status_from_github!(params)` on **both**, writing a `success` `Status` onto the victim's commit.
4. `Commit#deployable?` on the victim's commit flips to `true` (`!locked? && (stack.ignore_ci? || (success? && !blocked?))`), and if the victim stack has `continuous_deployment: true`, `Stack#trigger_continuous_delivery` → `next_commit_to_deploy` → `deployable_commits` selects this commit and calls `trigger_deploy(commit, Shipit.user, ...)`. [3](#0-2) [4](#0-3) 

Existing guards do not stop this: GitHub webhook signature verification only proves the payload came from GitHub for the **sending** repository (the attacker's own repo, which they legitimately control) — it says nothing about which stack's commits the payload is allowed to mutate. `ExplicitParameters` only validates payload shape (`sha`, `state`, etc.), not repository/stack ownership. There is no `require_permission!`/`stacks`-scope check in this handler, unlike the pattern used elsewhere in the same `Handlers` module.

### Impact Explanation
A payload originating from and authenticated as belonging to the attacker's own repository mutates commit/status state — and can trigger an unauthorized `Deploy` — on the victim's stack, which is a different tenant/repository entirely. This matches "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy" (Critical). Blast radius: any stack with `continuous_deployment: true` whose repository has ever been forked (or otherwise shares commit ancestry with an attacker-controlled repository) is affected; the attack is repeatable against any such commit/stack pair, and the attacker only needs to control a repository that shares git history with the target.

### Likelihood Explanation
Preconditions: (a) attacker can create/control a repository sharing a commit sha with the victim's undeployed commit — trivially achievable by forking a public repository, which is a normal unprivileged GitHub action; (b) the victim stack has `continuous_deployment: true` (a supported, commonly-used Shipit feature) and the shared commit is not yet deployed/locked/blocked. No Shipit credentials, session, API token, or GitHub org membership are required — only the ability to have GitHub deliver a `status` webhook for a repository the attacker owns, which occurs naturally via any CI hooked to their fork. This is fully repeatable and requires no timing race or privileged access.

### Recommendation
Scope `StatusHandler#process` (and any other handler resolving records purely by `sha`) to the repository identified by the webhook payload, mirroring the `stacks` helper already defined in `Handler`:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
This ensures a `Status` can only be attributed to commits that belong to a stack whose `repository.full_name` matches `payload.dig('repository', 'full_name')`, closing the cross-repo sha collision.

### Proof of Concept
Minitest plan (no live GitHub, `test/` scope only — described conceptually per rules, not to be placed under `test/` output here):

1. Create `victim_repo`/`victim_stack` (`continuous_deployment: true`) and `attacker_repo`/`attacker_stack`.
2. Create a `Commit` with the **same `sha`** in both `victim_stack` and `attacker_stack` (simulating shared git ancestry from a fork).
3. Stub `Shipit.user` to return a test user (as `trigger_deploy` requires a `user`).
4. Build a `status` webhook payload with `repository.full_name = attacker_repo.full_name`, `sha = shared_sha`, `state = "success"`.
5. Assert binding before: `victim_commit.success?` is `false`, `victim_stack.trigger_continuous_delivery` creates no `Deploy`.
6. Invoke `Shipit::Webhooks::Handlers::StatusHandler.call(payload)` (or POST to `/webhooks` with `X-GitHub-Event: status`, appropriately signed for the attacker's own secret/setup as used in existing webhook tests).
7. Reload `victim_commit`; assert `victim_commit.success?` is now `true` even though the webhook's `repository.full_name` equals `attacker_repo.full_name`, not `victim_repo.full_name` — this is the broken binding.
8. Call `victim_stack.trigger_continuous_delivery` and assert `assert_difference -> { victim_stack.deploys.count }, 1 do ... end`, proving a `Deploy` was created on the victim's stack from a status authenticated only for the attacker's repository.

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

**File:** app/models/shipit/stack.rb (L210-229)
```ruby
    def trigger_continuous_delivery
      return if cached_deploy_spec.blank?

      commit = next_commit_to_deploy

      if should_resume_continuous_delivery?(commit)
        continuous_delivery_resumed!
        return
      end

      if should_delay_continuous_delivery?(commit)
        continuous_delivery_delayed!
        return
      end

      begin
        trigger_deploy(commit, Shipit.user, env: cached_deploy_spec.default_deploy_env)
      rescue Task::ConcurrentTaskRunning
      end
    end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```
