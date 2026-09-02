### Title
Cross-repository status forgery bypasses CI gating via unscoped `Commit.where(sha:)` lookup - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves the target commit purely by `sha`, with no verification that the webhook's originating repository (`payload['repository']['full_name']`) is actually the repository that owns that commit/stack. Because GitHub webhook signatures are verified per-organization using the payload's own `repository.owner.login` [1](#0-0) , an attacker who owns any repository configured in Shipit (with its own valid `webhook_secret`) can sign a `status` event naming their own repo but containing the victim's HEAD sha, and it will be accepted and applied to the victim's commit.

### Finding Description
The broken binding: the question expects `authority_verifying_signature(payload.repository) == authority_owning(commit.sha, commit.stack)`. In practice, `verify_signature` only checks `authority_verifying_signature(payload.repository) == webhook_secret_of(payload.repository.owner.login)` [1](#0-0) , which is a legitimate check that the payload was signed by whoever configured that organization in Shipit — but it says nothing about whether that organization actually owns the `sha` being reported on.

`StatusHandler#process` never consults `payload['repository']` to scope the commit lookup:
```
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [2](#0-1) 

Note that the base `Handler` class actually provides a repo-scoped `stacks` helper (`Repository.from_github_repo_name(repository_name)&.stacks`) [3](#0-2) , but `StatusHandler` does not use it — it queries `Commit` globally by `sha` alone, across all stacks/repositories in the database.

Once the forged status is attached, `Commit#add_status` recomputes `status`, and `Commit#deployable?` is re-evaluated:
```
def deployable?
  !locked? && (stack.ignore_ci? || (success? && !blocked?))
end
``` [4](#0-3) 

If the attacker's forged status is `success` and matches the required context, `success?` becomes true, and provided no other blocking statuses exist, `deployable?` flips to true even though `stack.ignore_ci?` is false — i.e., real CI was never satisfied by the victim's actual CI provider. `schedule_continuous_delivery` then enqueues `ContinuousDeliveryJob` [5](#0-4) , which drives the victim's stack toward an unauthorized deploy.

Exploit flow:
1. Attacker registers/owns a repository+organization already configured in Shipit (or any org for which `Shipit.github(organization:)` resolves without raising `GithubOrganizationUnknown`), giving them a valid `webhook_secret` for that org.
2. Attacker observes the victim's public HEAD sha (no credentials needed).
3. Attacker POSTs `POST /webhooks` with `X-Github-Event: status`, a body naming their own repository but `sha` = victim's HEAD sha, `state: success`, `context` = the victim's required status context, signed with their own `webhook_secret`.
4. `verify_signature` passes (correctly verifies the attacker's own signature for their own org).
5. `StatusHandler#process` finds the victim's `Commit` record purely by matching `sha`, and calls `create_status_from_github!` on it, injecting the attacker's forged "success" status into the victim's commit/stack.
6. `Commit#deployable?` becomes true; continuous delivery is scheduled for the victim's stack.

None of the existing guards prevent this: `verify_signature` validates signer identity but not sha ownership; `ExplicitParameters` schema only validates types/presence, not sha-repository consistency; `drop_unhandled_event` only screens event names.

### Impact Explanation
An unrelated, unprivileged GitHub organization can inject arbitrary commit statuses (including forged "success" CI results) onto any other tenant's commit whose sha it can guess/observe, purely by controlling any repository already configured in the same Shipit instance. This satisfies `Commit#deployable?` and can trigger `Stack#trigger_continuous_delivery`, resulting in an unauthorized deploy of code for a repository the attacker never authenticated for. This is a cross-tenant authentication-bypass class issue: "a payload for one repository mutating another's stack/commit" and "an unauthorized deploy" — matching the Critical severity category.

### Likelihood Explanation
Preconditions: victim stack has `continuous_deployment`/CD enabled and CI required (`ignore_ci? == false`); the HEAD commit is currently pending/unknown; the attacker must control at least one repository/org already configured in the hosting Shipit instance (any tenant onboarded to the same Shipit deployment, not necessarily related to the victim) to obtain a valid `webhook_secret` for signing; the victim's HEAD sha must be observable (trivial for public repos, and Shipit itself exposes stack state per the audit's own High-severity category for unauthenticated read of stack state). Given a shared/multi-tenant Shipit installation, this is highly feasible and repeatable against any stack/sha at will.

### Recommendation
In `StatusHandler#process` (and analogous handlers such as check-run handlers), scope the `Commit` lookup to the stacks belonging to the webhook's own repository, e.g. reuse the base `Handler#stacks` helper: `stacks.flat_map(&:commits).where(sha: params.sha)` or equivalently join through `Repository.from_github_repo_name(payload.dig('repository','full_name'))`, and reject/ignore statuses for shas that don't belong to that repository's commits.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`, hypothetical addition):
```ruby
test "a status signed by a different repository's webhook secret cannot satisfy another stack's deployability" do
  victim_stack = shipit_stacks(:shipit) # ignore_ci: false, continuous_deployment: true
  victim_commit = victim_stack.commits.create!(sha: 'a' * 40, state: 'pending')
  attacker_repo_full_name = 'attacker-org/attacker-repo'

  assert_not victim_commit.deployable?

  payload = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'context' => victim_stack.required_statuses.first,
    'repository' => { 'full_name' => attacker_repo_full_name, 'owner' => { 'login' => 'attacker-org' } }
  }

  # Signed with attacker-org's own configured webhook_secret, not the victim's.
  Shipit::Webhooks::Handlers::StatusHandler.call(payload)

  victim_commit.reload
  assert victim_commit.deployable?, "victim commit became deployable via an unrelated repository's signed webhook"
end
```
Assertion binding: before, `authority(victim_commit) == webhook_secret(victim_stack.repository.owner)`; after the forged call, `victim_commit.deployable?` flips to `true` using `webhook_secret(attacker-org)`, proving the equality is broken.

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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
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
