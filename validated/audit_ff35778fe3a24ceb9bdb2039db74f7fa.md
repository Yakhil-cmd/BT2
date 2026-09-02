### Title
`status` webhook status writes are matched by bare SHA with no repository/stack scoping, allowing cross-repository status forgery on review-stack-enabled targets - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` resolves target commits with `Commit.where(sha: params.sha).each`, using only the raw SHA from the webhook payload and never the authenticated repository. Any commit row across any stack/repository sharing that SHA (e.g. because it was forked, or because a review stack was auto-provisioned for an external PR) receives the attacker-supplied `state`/`context`, even though the webhook signature only proves control over one specific GitHub repository.

### Finding Description
The broken binding: the webhook's authenticated identity is `repository_owner = payload.dig('repository','owner','login')` verified in `WebhooksController#verify_signature` [1](#0-0) , which should equal the repository that the resulting `Status` record is written against. Instead, `StatusHandler#process` ignores `repository_name`/`stacks` entirely:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [2](#0-1) 

Contrast this with the base `Handler` class, which *does* provide repository-scoped helpers (`stacks`, `repository_name`) that other handlers (e.g. `PullRequest` handlers) use, but `StatusHandler` bypasses them completely [3](#0-2) . `Commit#sha` is only indexed/scoped per `stack_id` (`index_commits_on_stack_id_and_sha`), not globally unique, so identical SHAs can legitimately exist across many stacks belonging to different repositories, most easily when a review stack for an external PR shares the exact same git history/commit objects as the target repo.

`create_status_from_github!` then calls `add_status`, which recomputes `status`/`simple_state` and, on a state change, calls `stack.schedule_merges` and emits `deployable_status` hooks [4](#0-3) . If the affected stack has `review_stacks_enabled: true` with `provisioning_behavior: allow_all`, the attacker (any external contributor able to open a PR) causes Shipit to auto-provision a review stack that executes `shipit.yml`, then sends a `status` webhook signed by their own (attacker-controlled) repository for a SHA that also exists in the victim's tracked commit set. Because `StatusHandler` performs no repository check, the forged `ci/build: success` status is applied to the victim's commit/stack, flips `simple_state`, and triggers `schedule_merges`/`deployable_status`, potentially forcing a deploy or merge decision that was never authorized by the victim repository's actual CI.

None of the existing guards intervene: `verify_signature` only proves the request came from *a* valid GitHub org/repo (the attacker's own), not that it's the correct repo for the SHA in question; `drop_unhandled_event` and the `ExplicitParameters` schema only validate payload shape (`sha`, `state`, `context`, etc.), not repository ownership; there is no `require_permission!`/`User#authorized?` check on this unauthenticated webhook path at all (by design, webhooks are repo-authenticated, not user-authenticated) — but that repo authentication is exactly what `StatusHandler` fails to verify against `Commit#stack`.

### Impact Explanation
A payload for one repository (the attacker's) mutates another repository's stack/commit state — this matches the Critical impact category "a payload for one repository mutating another's stack, commit, task or team," and can force an unauthorized deploy via `stack.schedule_merges` on a `review_stacks_enabled`/`allow_all` stack that executes `shipit.yml`. The blast radius spans any stack whose tracked commits share a SHA with a commit reachable by the attacker's own authenticated repository (most reliably via forks of the victim repo, which share identical commit objects/SHAs). This is repeatable per matching SHA and does not require any Shipit credentials, session, or GitHub App secret — only the ability to author a webhook-emitting GitHub repository (any GitHub account).

### Likelihood Explanation
Preconditions: victim stack has `review_stacks_enabled: true` and `provisioning_behavior_allow_all?` so that external PRs auto-provision review stacks and execute `shipit.yml`; a `ci/build` (or other required) status context is used for deployability gating; a commit SHA is shared between the attacker's own authenticated GitHub repo and the victim's tracked commit (trivially achievable by forking). Attacker cost is low: fork the repo, open a PR (to trigger review-stack provisioning), then send a signed `status` event from their own fork for the shared SHA. This is fully repeatable and does not depend on any race condition, rate limiting, or GitHub-side privilege.

### Recommendation
Scope `StatusHandler#process` to only touch commits belonging to the authenticated repository, e.g. restrict the lookup via `stacks` (as `Handler#stacks` already provides) or via `Commit.joins(:stack).merge(stacks).where(sha: params.sha)`, ensuring a status webhook can only affect commits/stacks belonging to `Repository.from_github_repo_name(repository_name)`.

### Proof of Concept
minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb` or `test/controllers/webhooks_controller_test.rb`):
1. Create two `Repository`/`Stack` fixtures, `victim_repo`/`victim_stack` (with `review_stacks_enabled: true`, `provisioning_behavior: allow_all`, and a required `ci/build` status) and `attacker_repo`/`attacker_stack`.
2. Create a `Commit` with `sha: "deadbeef..."` under `victim_stack`, and a second `Commit` with the **same** `sha` under `attacker_stack`.
3. Bind the equality under test: `victim_commit.stack.deployable? == false` before, and confirm `attacker_repo.full_name != victim_repo.full_name`.
4. POST to `/webhooks` with `X-Github-Event: status`, payload `{"repository": {"full_name": attacker_repo.full_name, "owner": {"login": attacker_repo.owner}}, "sha": shared_sha, "state": "success", "context": "ci/build"}`, stubbing `verify_signature` to succeed only for `attacker_repo`'s org.
5. Assert `victim_commit.reload.status.state == 'success'` and that `victim_stack.schedule_merges`/`deployable_status` hook fired — i.e., the victim stack's deployability changed as a direct result of a webhook authenticated only for the attacker's repository, proving the equality "status affects only the authenticating repository" is violated.

### Citations

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

**File:** app/models/shipit/commit.rb (L366-386)
```ruby
    def add_status
      already_deployed = deployed?

      previous_status = status
      yield
      reload # to get the statuses into the right order (since sorted :desc)
      new_status = status

      unless already_deployed
        payload = { commit: self, stack:, status: new_status.state }
        Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
      end

      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
      new_status
    end
```
