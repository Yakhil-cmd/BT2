### Title
Cross-repository status forgery leads to unauthorized `ContinuousDeliveryJob` scheduling on victim stack - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits by `sha` alone, with no scoping to the repository the webhook was actually signed for, unlike the base `Handler#stacks`/`repository_name` helpers used by other handlers. An attacker who owns a repository whose commit history shares a sha with a victim's continuously-deployed stack (trivially achieved by forking the victim's public repo) can send a genuinely signed status webhook for their own repository and have it applied to the victim's `Commit`/`Stack`, triggering `ContinuousDeliveryJob` against the victim's infrastructure.

### Finding Description
The broken binding, stated explicitly: for every `stack` enqueued into `ContinuousDeliveryJob`, `stack.repository` MUST equal the repository verified by `WebhooksController#verify_signature` (i.e. `params.dig('repository','full_name')`). It does not.

`WebhooksController#verify_signature` correctly authenticates the payload only for `repository_owner` (`params.dig('repository', 'owner', 'login')`) [1](#0-0)  — this proves the webhook genuinely originates from that owner/org's installation, nothing more.

The generic `Webhooks::Handlers::Handler` base class exposes a correctly-scoped `stacks` helper that restricts to `Repository.from_github_repo_name(repository_name)` [2](#0-1) , but `StatusHandler#process` does not use it:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [3](#0-2) 

This queries `Commit` table-wide by `sha` with no repository filter at all. If any `Commit` row belonging to another stack (the victim's) happens to have the same `sha` as the sha in the attacker-signed payload, it is mutated too.

`create_status_from_github!` -> `add_status` creates a `Status` scoped to `commit.stack_id` (the victim's stack) [4](#0-3) , and its side effects run against that victim stack: `stack.schedule_merges if new_status.pending? || new_status.success?` [5](#0-4) . `Status` also has `after_commit :schedule_continuous_delivery, on: :create` calling `commit.schedule_continuous_delivery` [6](#0-5) , which enqueues the job on the victim's stack:

```ruby
def schedule_continuous_delivery
  return unless deployable? && stack.continuous_deployment? && stack.deployable?
  ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
end
``` [7](#0-6) 

Exploit flow: attacker forks the victim's public repository into `attacker/repo` (git commit shas are content hashes, preserved verbatim across forks/history-sharing). Attacker installs/enables the same GitHub App/webhook integration on their own account for `attacker/repo` (a normal, unprivileged action for a publicly installable app) and sets a commit status on a shared sha via the GitHub Status API on their own repo — fully within their control, requiring no victim credentials. GitHub signs and delivers this status webhook with `repository.full_name = attacker/repo`, `repository.owner.login = attacker`. `verify_signature` passes because it is validated against `attacker`'s legitimately configured secret. `StatusHandler#process`, however, ignores `repository_name`/`repository_owner` entirely and matches by `sha` against the whole `Commit` table, hitting the victim's `Commit` row and mutating the victim's `Stack`.

Existing guards do not prevent this: `verify_signature` only proves who signed the payload, not which `Commit`/`Stack` the handler should touch; `ExplicitParameters` schema only validates the shape of `sha`/`state`, not scope; there is no `Repository`/`Stack` filter anywhere in `StatusHandler`.

### Impact Explanation
An attacker-controlled repository's CI status events can create `Status` rows on and trigger `Hook.emit`/`stack.schedule_merges`/`ContinuousDeliveryJob.perform_later(stack)` for a victim's stack that the attacker has no relationship to and never authenticated for. Repeated toggling of `state` between `failure`/`success` on the shared sha repeatedly flips `previous_status.simple_state != new_status.simple_state`, repeatedly re-triggering `schedule_merges` and `schedule_continuous_delivery`, forcing repeated unauthorized deploy attempts on the victim's infrastructure. This is a payload for one repository mutating another's commit/stack and forcing an unauthorized deploy trigger — Critical severity per the stated impact categories.

### Likelihood Explanation
Preconditions: victim stack has `continuous_deployment: true` (stated precondition) and the victim repository is public (or otherwise forkable) so commit shas are shared with an attacker-controlled fork; the attacker must have a repository wired into Shipit's webhook pipeline with its own genuinely signed webhook events (a normal, low-cost setup for any public GitHub App integration). No Shipit secrets, sessions, tokens, or org membership are required. This is fully repeatable and does not depend on guessing any secret — only on possessing a repo whose commit history overlaps with the victim's (trivial via fork).

### Recommendation
Scope `StatusHandler#process` (and audit all other handlers) to only touch commits belonging to stacks of the repository that was actually verified in the webhook, e.g. restrict via the existing `stacks`/`repository_name` helper (`stacks.flat_map(&:commits).where(sha: params.sha)` or equivalent join through `Repository.from_github_repo_name(repository_name)`) instead of an unscoped `Commit.where(sha: params.sha)`.

### Proof of Concept
Minitest plan (webhook/model level, no live GitHub):
1. Create `victim_stack` with `continuous_deployment: true`, `repository` for `victim/repo`, and a `Commit` with `sha: "deadbeef..."` that is `deployable?`/passes preconditions for `schedule_continuous_delivery`.
2. Create a second `Repository`/`Stack` for `attacker/repo` (not related to victim) — or none at all, since `StatusHandler` never needs a matching stack for the attacker's repo.
3. Build a status webhook payload with `repository.full_name = "attacker/repo"`, `repository.owner.login = "attacker"`, `sha` identical to the victim commit's sha, `state: "success"`.
4. Call `Shipit::Webhooks::Handlers::StatusHandler.call(payload)` directly (bypassing signature verification, as in existing handler tests) twice, toggling `state` between `"failure"` and `"success"`.
5. Assert `ContinuousDeliveryJob` was enqueued with `victim_stack` as the argument (`assert_enqueued_with(job: ContinuousDeliveryJob, args: [victim_stack])`) after each toggle, proving the equality `repository verified by webhook (attacker/repo) == repository of stack enqueued (victim/repo)` fails to hold as required.

### Citations

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

**File:** app/models/shipit/status.rb (L18-44)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

    delegate :broadcast_update, to: :commit

    class << self
      def replicate_from_github!(stack_id, github_status)
        find_or_create_by!(
          stack_id:,
          state: github_status.state,
          description: github_status.description,
          target_url: github_status.target_url,
          context: github_status.context,
          created_at: github_status.created_at
        )
      end
    end

    private

    def enable_ci_on_stack
      commit.stack.enable_ci!
    end

    def schedule_continuous_delivery
      commit.schedule_continuous_delivery
    end
```
