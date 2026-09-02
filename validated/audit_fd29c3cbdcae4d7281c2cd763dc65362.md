### Title
Cross-repository status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` matches incoming `status` webhooks by bare SHA across the entire `commits` table with no repository/stack scoping, unlike every other handler (e.g. `PushHandler`) which uses the `Handler#stacks` helper that filters by `Repository.from_github_repo_name(repository_name)`. Because Shipit commits with identical SHAs can legitimately exist in multiple stacks/repositories (forks sharing history, mirrored repos), a signed webhook that GitHub sends for a status event on the attacker's own repository can write a status onto a commit belonging to a victim's stack, which — if that stack has `continuous_deployment` enabled — changes deployability and can trigger `ContinuousDeliveryJob`.

### Finding Description
The broken binding is: `status.stack_id` (the record written) should equal `webhook.repository.stack_id` (the repository that authenticated the request), but `StatusHandler#process` never enforces this:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [1](#0-0) 

Compare with `PushHandler#process`, which correctly scopes writes to stacks belonging to the repository named in the payload via the base `Handler#stacks`/`repository_name` helpers: [2](#0-1) [3](#0-2) 

`StatusHandler` never calls `stacks`/`repository_name`; it queries `Commit` globally by `sha`, so any commit row across any stack with a matching SHA receives the status.

Signature verification in `WebhooksController#verify_signature` only checks that the webhook is validly signed for the *organization* named in the payload (`Shipit.github(organization: repository_owner)`), not for a specific repository: [4](#0-3) 

This means the signature guard proves "this event genuinely happened in some repository under organization X," not "this event happened in the specific repository whose stack is being mutated." An attacker who owns/controls a repository under the same GitHub organization as a victim stack (e.g. a fork within the org, or any repo they can attach CI/status webhooks to) can cause GitHub to send a legitimately-signed `status` event for `context: buildkite/deploy`, `state: failure` on a SHA that is also present (same content, same SHA — commits are content-addressed and identical ancestor commits share SHAs across forks/mirrors) in the victim stack's `commits` table. `StatusHandler` then writes that failure status onto the victim's `Commit`, via `commit.create_status_from_github!(params)`, which calls `Commit#add_status` and re-evaluates `deployable?`/`blocked?`/`schedule_continuous_delivery`: [5](#0-4) [6](#0-5) [7](#0-6) 

None of the existing guards (`verify_signature`, `drop_unhandled_event`, `ExplicitParameters` schema) stop this because they only validate that the JSON shape is correct and that the request is a real GitHub webhook for an org Shipit knows about — none of them check that the SHA being mutated actually belongs to the repository that authenticated the webhook.

### Impact Explanation
A status webhook that is authentic for repository/organization A is applied to a `Commit` row belonging to stack/repository B, i.e. "a payload for one repository mutating another's stack, commit" — explicitly listed as a Critical impact category. On a victim stack with `continuous_deployment` enabled, flipping a required context (`buildkite/deploy`) to `failure` changes `Commit#deployable?`/`blocked?`, and flipping it to `success` can make a previously-blocked commit deployable, letting `ContinuousDeliveryJob` (scheduled from `Commit#schedule_continuous_delivery`) ship it. This is a cross-tenant integrity break: any stack sharing organization-level webhook signing with an attacker-controlled repository is affected, and the attack is repeatable per shared SHA/status update.

### Likelihood Explanation
Preconditions: (1) attacker controls a repository under the same GitHub organization as the victim's Shipit-tracked repository (common in monorepo/multi-repo orgs, or via forks that share ancestor commits and thus SHAs), (2) the victim stack has `continuous_deployment` enabled and relies on a `buildkite/deploy`-style external status context, (3) a commit SHA exists in both the attacker's and the victim's `commits` tables (trivial via forking/mirroring history). No Shipit secrets, sessions, or GitHub App keys are needed — the attacker relies on GitHub itself signing the webhook for an event that genuinely occurred on a repository they control. This is a low-cost, repeatable attack limited only by organization-level webhook secret sharing and SHA collision opportunities, which are readily achievable via forks.

### Recommendation
Scope `StatusHandler#process` to the repository that authenticated the webhook, mirroring `PushHandler`/`Handler#stacks`: resolve the `Repository` from `payload.dig('repository', 'full_name')`, restrict candidate stacks to that repository, and only update `Commit` rows (`stack_id` in that repository's stacks) matching the SHA, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` instead of the global `Commit.where(sha: params.sha)`.

### Proof of Concept
minitest plan (`test/models/webhooks/handlers/status_handler_test.rb` or controller test):
1. Create two `Repository`/`Stack` fixtures, `victim_stack` (with `continuous_deployment: true` and a deploy spec requiring `buildkite/deploy`) and `attacker_stack`, both under the same organization owner used by `Shipit.github`.
2. Create a `Commit` with `sha: "deadbeef..."` in `victim_stack`, and a `Commit` with the *same* `sha` in `attacker_stack` (simulating shared ancestor history).
3. Assert binding before: `victim_commit.deployable?` == `true` (or whatever pre-state), and `victim_commit.statuses.count` == `0`.
4. Simulate `StatusHandler.call(payload)` (or POST to `/webhooks` with `X-Github-Event: status`, payload `{ "sha" => shared_sha, "context" => "buildkite/deploy", "state" => "failure", "repository" => { "full_name" => attacker_stack.repository.full_name, "owner" => { "login" => attacker_org } } }`, stubbing `verify_webhook_signature` to return `true` as done in existing tests).
5. Assert binding after: `victim_commit.reload.statuses.count` == `1` and `victim_commit.deployable?` changed (e.g. now `false`), proving the attacker's webhook (scoped to `attacker_stack`'s repository) mutated `victim_commit` belonging to a different repository/stack — the equality `status.stack_id == authenticating_repository.stack_id` is violated.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```
