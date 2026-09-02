### Title
`status` webhook (`buildkite/deploy`, `success`) writes commit status cross-tenant via bare-SHA lookup with no repository scoping - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves target commits with `Commit.where(sha: params.sha)` and applies the incoming status to every matching row, regardless of which repository the webhook was authenticated for. Since the `status` payload schema never requires or checks a `repository` field, a `success` status legitimately signed for one repository can flip the state of a `Commit` row belonging to a different stack/repository whenever the SHA values collide (e.g., via forked history), producing an unintended deploy/merge/block decision on a victim stack.

### Finding Description
The broken binding is: the webhook's *authenticated* repository (used to select `Shipit.github(organization: repository_owner)` for signature verification in `WebhooksController#verify_signature`) should equal the repository whose `Commit` rows are mutated by the event. In `StatusHandler`, that equality is never enforced.

- `StatusHandler`'s param schema only requires `sha`, `state`, and optional `context`/`description`/`target_url`/`created_at`/`branches` — it does **not** require or read `repository`: [1](#0-0) 
- `process` looks up commits by bare SHA across the entire `commits` table and mutates every match: [2](#0-1) 
- This is inconsistent with the base `Handler` class, which provides a `stacks`/`repository_name` scoping helper derived from `payload.dig('repository', 'full_name')`: [3](#0-2)  — and with every `PullRequest` handler, which explicitly resolves `Shipit::Repository.from_github_repo_name(params.repository.full_name)` before touching any stack-scoped record: [4](#0-3) 
- `Commit#create_status_from_github!` → `#add_status` writes the `Status`, fires `Hook.emit(:commit_status/:deployable_status, ...)`, and calls `stack.schedule_merges` when the new state is `pending` or `success`: [5](#0-4) . `Commit#deployable?` and `#schedule_continuous_delivery` directly gate ship/block behavior on `status.success?`/`blocked?`: [6](#0-5) , [7](#0-6) .
- Signature verification in `WebhooksController` is scoped per-organization (`Shipit.github(organization: repository_owner)`), not per-repository, and only proves the request came from *some* org/app installation known to Shipit — it does not prove the `sha` in the body belongs to that org's repository: [8](#0-7) .

**Attacker request:** An attacker who controls (or forks) a repository that shares git history with the victim's tracked repository sends (via GitHub, by setting a commit status on their own repo/fork, or directly to the webhook endpoint if they can produce a validly signed payload for their own org) a `status` event: `{"sha": "<shared-ancestor-sha>", "state": "success", "context": "buildkite/deploy", "repository": {"full_name": "attacker/fork", ...}}`. Because forks share ancestor commit SHAs by construction (content-addressed hashing), a commit that is old/shared history in the victim's tracked stack can be the exact SHA the attacker legitimately controls status for in their own fork.

**Why guards fail:** `verify_signature` only checks the HMAC signature against the webhook secret configured for the *sender's own organization* — it succeeds because the attacker's own org/app installation is legitimately configured, not because of anything about the victim's repo. `drop_unhandled_event` and `ExplicitParameters` schema checks pass because `status` is a handled event and the schema doesn't require `repository`. No code path in `StatusHandler` or `Commit.where(sha:)` restricts the update to the commit whose stack's repository matches `params.repository.full_name`.

### Impact Explanation
An attacker can force a `Commit` record in an arbitrary victim stack to transition state (e.g., to `success`) for a required context (`buildkite/deploy`) without ever authenticating against the victim's repository, causing `stack.schedule_merges`/`ContinuousDeliveryJob` to fire and potentially ship/unblock a deploy that the victim's real CI never approved, or conversely inject a `failure`/`error` state to block a legitimate deploy. This is a cross-repository state mutation: one repository's authenticated payload writes another repository's `Commit`/`Status` records, matching the Critical "payload for one repository mutating another's stack, commit, task or team" / "unauthorized deploy" category. Blast radius is any stack whose commit history overlaps (via fork ancestry or copy-pasted commits) with a repository the attacker controls.

### Likelihood Explanation
Preconditions: the victim stack must contain a `Commit` row whose `sha` is identical to a commit the attacker can trigger a status for from their own controlled repository (trivially achievable by forking a public repo tracked by Shipit — shared ancestor commits retain identical SHAs) — no brute-forcing of SHA1 is required. The attacker needs only ordinary GitHub permissions on their own fork/repo (to set a commit status) and no Shipit credentials, session, or secrets. This is fully repeatable against any victim stack sharing ancestry with an attacker-controlled repo.

### Recommendation
Scope `StatusHandler#process` to the repository that authenticated the webhook: require `repository.full_name` in the params schema, resolve `Repository.from_github_repo_name(params.repository.full_name)`, and restrict the `Commit` lookup to `commit.stack.repository_id == repository.id` (or join through `stacks: :repository`) before calling `create_status_from_github!`, mirroring the pattern already used in the `PullRequest` handlers.

### Proof of Concept
minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`):
```ruby
test "success status for shared SHA from an unrelated repository flips a victim commit's status" do
  victim_stack = shipit_stacks(:shipit)              # tracks repo "shopify/shipit-engine"
  victim_stack.update!(required_statuses: ["buildkite/deploy"])
  victim_commit = victim_stack.commits.create!(sha: "cafef00d" * 5, message: "shared ancestor")

  # Baseline: victim commit is not deployable (no successful buildkite/deploy status yet)
  refute victim_commit.deployable?

  # Attacker-authenticated payload references an *unrelated* repository but the *same* sha
  payload = {
    "sha" => victim_commit.sha,
    "state" => "success",
    "context" => "buildkite/deploy",
    "repository" => { "full_name" => "attacker/unrelated-fork" }
  }

  StatusHandler.new(payload).process

  victim_commit.reload
  assert_equal "success", victim_commit.state
  assert victim_commit.deployable?   # victim stack's deploy gating flipped by a payload never authenticated for its repo
end
```
This demonstrates the equality `authenticated_repository == mutated_commit.stack.repository` does not hold, and that `StatusHandler` mutates the victim's `Commit` regardless.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L7-18)
```ruby
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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

**File:** app/models/shipit/commit.rb (L365-386)
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
