### Title
`StatusHandler#process` writes commit statuses across repositories by bare SHA, letting a status legitimately signed for an attacker-owned fork flip `deploy/production` on a victim's auto-provisioned review stack - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` looks up commits with `Commit.where(sha: params.sha)` with no repository/stack scoping, unlike sibling handlers such as `CheckSuiteHandler` which scope through the `stacks` helper derived from `payload.dig('repository', 'full_name')`. Because Git forks share commit SHAs for any commit that predates the fork point, an attacker who owns a fork of a public repository can legitimately set a commit status (`context: deploy/production`, `state: success`) on their own fork via the GitHub API, producing a webhook that is validly signed by GitHub for the attacker's own repository/organization, yet is applied by Shipit to every `Commit` row across all stacks/tenants sharing that SHA - including a victim's `review_stacks_enabled: true, allow_all` stack.

### Finding Description
The broken binding: the invariant "a `deploy/production` status affects only the repository that authenticated it" should mean `commit.stack.repository.full_name == payload.dig('repository','full_name')` for every `Commit` updated. In `StatusHandler#process`:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [1](#0-0) 

there is no filter on `repository_name`/`stacks`, so any `Commit` record in the entire Shipit database with a matching `sha` is updated, regardless of which repository's webhook secret validated the request. Compare with `CheckSuiteHandler#process`, which scopes explicitly through `stacks.where(branch: ...)` before touching commits [2](#0-1) , and the base `Handler#stacks` helper which is designed to enforce exactly this scoping via `Repository.from_github_repo_name(repository_name)` [3](#0-2) .

The signature check in `WebhooksController#verify_signature` only proves the payload was sent by GitHub for *some* organization/app installation matching `payload.dig('repository','owner','login')` [4](#0-3) ; it does not - and structurally cannot - prove that the `sha` inside the payload is unique to that repository. Git SHAs are content+history hashes; any commit on the shared history between a public upstream repo and an attacker-controlled fork of it has an identical SHA in both repositories.

Exploit flow:
1. Attacker forks the victim's public repository (`victim/repo`), which has a stack with `review_stacks_enabled: true, allow_all` requiring `deploy/production` as a blocking/required status context.
2. Attacker opens a pull request from the fork; because `allow_all` review stacks auto-provision and execute `shipit.yml` for external PRs, a review stack is created tracking a `Commit` whose `sha` is shared with the attacker's own fork (e.g., the merge-base or any pre-fork commit).
3. Attacker, as the legitimate owner/maintainer of their own fork, calls the GitHub Statuses API on their own repository to set `context: deploy/production`, `state: success` for that shared `sha`. GitHub delivers this as a real, correctly-signed webhook for the attacker's own repository.
4. Shipit's `verify_signature` succeeds (it's a real GitHub webhook for a real, attacker-owned repo).
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` with no repository filter, matches the victim's review-stack `Commit` row (same `sha`), and calls `commit.create_status_from_github!(params)` on it, injecting a `success` status for `deploy/production` into the victim's stack [5](#0-4) .
6. This flips `Commit#status`/`Commit#deployable?` and blocking-status evaluation [6](#0-5) , and can trigger `stack.schedule_merges` or continuous delivery via `add_status`'s side effects [7](#0-6) .

None of the existing guards prevent this: `verify_signature` authenticates the sender's own repo, not the target of the write; `ExplicitParameters` schema only validates payload shape, not tenancy; there is no `Repository`/`Stack` scoping applied anywhere in `StatusHandler`.

### Impact Explanation
A `success` status for a security/deploy-gating context (`deploy/production`) can be written into a victim stack that the attacker never authenticated for, via a webhook that is entirely legitimate for the attacker's own repository. This is a cross-tenant write: a payload authenticated for repository A mutates commit/status state for repository B's stack. Given `review_stacks_enabled: true, allow_all`, review stacks execute `shipit.yml`, so flipping the required status to `success` can unblock a deploy/merge path that executes attacker-uninfluenced but attacker-triggered task execution on the Shipit deploy host - matching the Critical category "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy, rollback or merge." This is repeatable against any victim repository whose commit history the attacker can fork and share a SHA with (i.e., any public repo the attacker can fork), and is not limited to a single stack - any stack/tenant tracking a shared-history commit is affected.

### Likelihood Explanation
Preconditions: the victim repository must be public/forkable (typical for `review_stacks_enabled`/`allow_all` configurations, which exist specifically to support external contributor PRs), and the attacker needs no privileges beyond owning a fork and being able to open a PR and call the GitHub Statuses API on their own repository - both are things any GitHub user can do at zero cost. No Shipit secret, session, or API token is required. The only nondeterministic factor is finding a shared SHA between fork and upstream, which is guaranteed for any commit that exists before the fork's divergence point (e.g., the merge-base), making this trivially and repeatedly achievable.

### Recommendation
Scope `StatusHandler#process` to the repository that authenticated the webhook, mirroring `CheckSuiteHandler`/`Handler#stacks`: resolve `stacks` from `payload.dig('repository', 'full_name')` and restrict the commit lookup to `Commit.where(sha: params.sha, stack_id: stacks.select(:id))` (or equivalent `stacks.flat_map(&:commits)` scoped by sha) instead of the unscoped `Commit.where(sha: params.sha)`.

### Proof of Concept
minitest plan (no live GitHub, using existing webhook test helpers):
1. Create two `Repository`/`Stack` records, `repo_a` (attacker-owned, e.g. `attacker/fork`) and `repo_b` (victim, `victim/repo`) with `review_stacks_enabled: true, allow_all`, and `required_statuses: ['deploy/production']`.
2. Create a `Commit` with the same `sha` (e.g. `"a"*40`) attached to `repo_a`'s stack and another `Commit` with the identical `sha` attached to `repo_b`'s stack, with no prior successful `deploy/production` status (assert `commit_b.deployable?` is `false` / `commit_b.status.state != 'success'` beforehand).
3. Build a `status` webhook payload with `repository.full_name = "attacker/fork"`, `sha`, `context: "deploy/production"`, `state: "success"`, and pass it through `Shipit::Webhooks::Handlers::StatusHandler.call(payload)` (bypassing controller-level signature verification, since the point being tested is the handler's lack of scoping).
4. Assert: `commit_b.reload.status.state == 'success'` and `commit_b.deployable?` (or `Stack#schedule_merges`/`deployable?`) changed to `true`, proving repo B's commit was mutated by a payload that only ever authenticated repo A.
5. Equality check before/after: before, `commit_a.stack.repository.full_name != commit_b.stack.repository.full_name` while both share `sha`; after processing, `commit_b.statuses.last.stack_id == commit_a.stack_id`'s sha match caused a write to `commit_b`, violating "a `deploy/production` status affects only the repository that authenticated it."

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
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

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
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

**File:** app/models/shipit/commit.rb (L227-237)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end

    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
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
