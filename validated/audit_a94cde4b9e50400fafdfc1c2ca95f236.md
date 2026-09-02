### Title
Cross-repository status forgery via unscoped SHA lookup in `StatusHandler#process` unblocks deploys - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves the target commit(s) for an incoming `status` webhook using a global `Commit.where(sha: params.sha)` query with no repository/stack scoping, unlike the base `Handler` class which provides a `stacks` helper scoped from `payload.dig('repository', 'full_name')`. Since GitHub webhook signatures only authenticate that a payload legitimately originated from the sending repository/organization, but never bind the *content* of that payload to only that repository's commits, a validly-signed status from attacker-controlled repository B can mutate the status of a commit belonging to victim stack A whenever their SHAs collide.

### Finding Description
The broken binding, stated as an equality that must hold but does not:
`repository that authenticated the webhook signature (B) == repository owning the stack/commit whose blocking-status gate is mutated (A)`.

Path:
- `Shipit::WebhooksController#create` (`app/controllers/shipit/webhooks_controller.rb:10-15`) verifies only that the raw payload's HMAC matches `Shipit.github(organization: repository_owner).verify_webhook_signature(...)` for the *sender's* organization (`app/controllers/shipit/webhooks_controller.rb:24-30`). This proves authenticity of the sender, not that the sender is authorized to affect a specific commit/stack. [1](#0-0) 
- The base `Handler` class provides `stacks`, explicitly scoping any lookups to `Repository.from_github_repo_name(repository_name)&.stacks`, derived from `payload.dig('repository', 'full_name')` — i.e., the sending repository. [2](#0-1) 
- `StatusHandler#process` ignores this scoping entirely and instead does a bare, unscoped lookup: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`. [3](#0-2) 
- `create_status_from_github!` → `add_status` writes a new `Status` row for the resolved commit and triggers side effects (`schedule_merges`, `deployable_status` hook) purely based on the commit found by SHA, regardless of which repository the webhook actually came from. [4](#0-3) [5](#0-4) 
- `Commit#blocked?` re-evaluates blocking status purely from DB state: `stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)`, with no check that the blocking status itself came from stack A's own repository. [6](#0-5) 
- `Commit#deployable?` and `schedule_continuous_delivery` consume `blocked?` directly to gate deploys. [7](#0-6) [8](#0-7) 

There is no global uniqueness constraint on `commits.sha` — the only index is `(stack_id, sha)` per `db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb` — so two different stacks/repositories can legitimately hold commit rows with an identical `sha` value (via constructed SHA1 collision, or any other means of producing/importing a matching sha into repo B's history that the attacker controls and can push/webhook from). None of `verify_signature`, `drop_unhandled_event`, or the `ExplicitParameters` schema for `StatusHandler` reject or scope this — they validate payload shape and sender authenticity only, never binding the payload's `sha` to the sender's own repository.

### Impact Explanation
An attacker who owns/controls repository B and can get a `status` webhook accepted for it (any GitHub user pushing a commit and having their own CI, or a script directly emitting a status event for their own repo, which GitHub will happily sign) can flip the state of an arbitrary commit belonging to any other tenant's stack A, provided a SHA match exists. This directly clears `Commit#blocked?` for newer, already-approved commits in stack A, causing `Commit#deployable?` to flip true and either `schedule_continuous_delivery` or a manual deploy trigger to proceed — an unauthorized deploy for a repository the attacker never authenticated against. This matches the "Critical: a payload for one repository mutating another's stack/commit... or an unauthorized deploy" impact category, and is repeatable against any stack/commit sharing a SHA with an attacker-controlled repo.

### Likelihood Explanation
Exploitation requires the attacker to produce a commit SHA collision with the specific blocking commit C1 in victim stack A, which is computationally very expensive for SHA-1 (feasible in principle, as demonstrated by SHAttered-style attacks, but costly, and constructing a colliding commit that is also plausible/pushable into a controlled repo adds further constraints) but requires no privileges within Shipit or GitHub App secrets — only ownership of a GitHub repository capable of emitting a `status` webhook. No Shipit session, API token, or team membership is needed. The core code defect (missing repository scoping in `StatusHandler`) is unconditional and always reachable once the SHA-collision precondition is met.

### Recommendation
Scope `StatusHandler#process` (and any other webhook handler doing raw `Commit`/`Stack` lookups by SHA) to the sending repository, mirroring the base `Handler#stacks` helper — e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or equivalent join through `Repository.from_github_repo_name(repository_name)` before touching `Commit.where(sha: ...)`, so a status can only be applied to commits belonging to stacks of the repository that authenticated the webhook.

### Proof of Concept
Minitest plan (in `test/models/shipit/webhooks/handlers/status_handler_test.rb`, not modifying anything under `test/**` further than adding assertions per rules — described conceptually):
1. Create `stack_a` bound to repository `org/repo-a` with `blocking_statuses: ['ci/blocking']`.
2. Create `commit_c1` on `stack_a` (older, currently has a `failure` status for context `ci/blocking`) and `commit_c2` on `stack_a` (newer, `success` status, otherwise deployable).
3. Assert `commit_c2.blocked?` is `true` and `commit_c2.deployable?` is `false` (bound by `equality: repo of webhook (repo-a) == repo owning blocked commit (repo-a)`, currently true).
4. Construct a forged webhook payload with `repository.full_name = 'attacker/repo-b'`, `sha: commit_c1.sha`, `state: 'success'`, `context: 'ci/blocking'` — i.e., signed/authenticated for repo B, not repo A.
5. Call `Shipit::Webhooks::Handlers::StatusHandler.call(payload)` directly (bypassing only the HTTP-layer signature check, since that check legitimately passes for repo B).
6. Assert `commit_c1.reload.blocking?` is now `false` (status flipped despite the webhook never authenticating for `org/repo-a`), and assert `commit_c2.reload.blocked?` is now `false` and `commit_c2.deployable?` is now `true` — demonstrating the equality `repo that authenticated (repo-b) != repo whose gate was cleared (repo-a)` while still succeeding, proving the vulnerability.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-30)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end

    private

    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
    end

    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/commit.rb (L231-237)
```ruby
    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
    end
```

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
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
