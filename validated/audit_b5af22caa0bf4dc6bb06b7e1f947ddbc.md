### Title
Cross-repository status webhooks trigger continuous delivery / merge processing for any stack sharing a commit SHA - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits purely `Commit.where(sha: params.sha)`, with no scoping to the repository named in the verified webhook payload, unlike every other handler in the codebase. A signature-verified `status` webhook for an attacker-controlled repository therefore creates a `Status` on, and can trigger continuous delivery / merge-queue processing for, any stack whose stored commit happens to share that SHA — most plausibly a stack tracking a repository the attacker has forked.

### Finding Description
The claimed binding — "the stack for which continuous delivery is scheduled == the stack of the repository named in the verified webhook payload" — does **not** hold in this code path.

`WebhooksController#verify_signature` only verifies that the request was legitimately signed by GitHub *for the organization named in `repository.owner.login`* [1](#0-0) . It never restricts which `Commit`/`Stack` records the handler is allowed to touch — that responsibility is left entirely to each `Handler` subclass.

Every pull-request-oriented handler correctly narrows its scope by resolving `Repository.from_github_repo_name(params.repository.full_name)` before touching any stack, e.g. `OpenedHandler#repository`, `ClosedHandler#repository`, `LabeledHandler`/`UnlabeledHandler` [2](#0-1) [3](#0-2) . The base `Handler` class even exposes a `stacks` helper for exactly this purpose, scoped via `Repository.from_github_repo_name(repository_name)` [4](#0-3) .

`StatusHandler`, however, ignores `params.repository`/`repository_name`/`stacks` entirely:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [5](#0-4) 

Its `params` schema doesn't even require a `repository` field — only `sha`, `state`, and optional metadata [6](#0-5) . `Commit.where(sha:)` is a global, unscoped query across every `Stack` in the installation.

`create_status_from_github!` creates a `Status` row on that commit [7](#0-6) , whose `after_commit :schedule_continuous_delivery` calls `commit.schedule_continuous_delivery` [8](#0-7) , which — if the affected commit is `deployable?` and its stack has `continuous_deployment?` enabled — enqueues `ContinuousDeliveryJob.perform_later(stack)` for **that commit's own stack**, regardless of which repository the webhook named [9](#0-8) . Separately, `add_status` (invoked from `create_status_from_github!`) also calls `stack.schedule_merges` (→ `ProcessMergeRequestsJob.perform_later(self)`) whenever the commit transitions to `pending`/`success` [10](#0-9) [11](#0-10) .

**Exploit path:** commit SHAs are content-addressed and identical across a repository and any fork of it. If a victim's Shipit stack tracks `victim/repo`, and the attacker forks that repository to `attacker/repo`, every commit shared with upstream keeps the exact same SHA in the fork. The attacker can trigger (or directly POST, since this is a public unauthenticated webhook endpoint requiring only a valid GitHub HMAC signature for *their own* repo, which GitHub will legitimately produce for real events on `attacker/repo`) a `status` event referencing that shared SHA, naming `repository.full_name = "attacker/repo"`. `verify_signature` passes because the signature is valid for the attacker's own org/repo. `StatusHandler` then matches the shared-SHA `Commit` row belonging to the victim's stack and creates a `Status` on it, scheduling `ContinuousDeliveryJob`/`ProcessMergeRequestsJob` for the victim's stack — a stack never named in the authenticated payload.

None of the listed guards prevent this: `verify_signature` only checks the payload's own repository owner, not correlation between `repository.full_name` and the matched commit's stack; the `ExplicitParameters` schema for `StatusHandler` doesn't require/validate `repository` at all; there is no `stacks`/`Repository.from_github_repo_name` scoping check in this handler as there is in every sibling PR handler.

### Impact Explanation
An attacker who owns/forks any repository whose commit history overlaps a victim's tracked repository can write a `Status` record to, and unconditionally trigger `ContinuousDeliveryJob` and `ProcessMergeRequestsJob` for, the victim's stack — a record/action for a repository that never authenticated in the payload. This can cause an unauthorized deploy or merge-queue processing to be scheduled for the victim's stack. This matches the Critical category: "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy, rollback or merge." It is repeatable against any stack whose repository has been forked (extremely common on GitHub) and requires no privileged Shipit role, session, or secret.

### Likelihood Explanation
Preconditions: the victim stack must have `continuous_deployment: true` (for the CD path) or simply active merge-queue usage (for the `ProcessMergeRequestsJob` path, which fires on any pending/success transition regardless of CD setting); the attacker needs only a public/forkable copy of the victim's repository containing at least one shared commit SHA (trivial via `git fork`/`git clone` + push). Sending a real `status` webhook for that SHA from the fork requires no special access — GitHub sends `status` webhooks automatically for CI integrations, or the attacker can configure any CI/webhook on their own fork to fire one, or directly craft and sign the payload since it's their own repository's secret. This is inexpensive, fully repeatable, and requires no Shipit secrets, tokens, or team membership.

### Recommendation
Scope `StatusHandler#process` to the repository named in the verified payload, matching the pattern used by the other handlers, e.g. constrain the commit lookup to `stacks.flat_map(&:commits).where(sha: params.sha)` or `Commit.joins(:stack).merge(stacks).where(sha: params.sha)`, using the inherited `stacks`/`repository_name` helpers from `Shipit::Webhooks::Handlers::Handler`. Require `repository.full_name` in the `StatusHandler` params schema so it cannot be omitted.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "status webhook naming attacker repo must not schedule CD/merge jobs for a victim stack sharing the sha" do
  victim_stack = shipit_stacks(:shipit)
  victim_stack.update!(continuous_deployment: true)
  shared_sha = shipit_commits(:first).sha
  shipit_commits(:first).update!(stack: victim_stack)

  payload = {
    "sha" => shared_sha,
    "state" => "success",
    "context" => "ci/attacker",
    "repository" => { "full_name" => "attacker/decoy" }
  }

  assert_no_enqueued_jobs(only: [ContinuousDeliveryJob, ProcessMergeRequestsJob]) do
    Shipit::Webhooks::Handlers::StatusHandler.call(payload)
  end
end
```
Expected (buggy) behavior today: `ContinuousDeliveryJob`/`ProcessMergeRequestsJob` **are** enqueued for `victim_stack` even though `payload["repository"]["full_name"]` names `attacker/decoy`, proving `stack_of(payload.repository) != stack_receiving_CD_trigger`.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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

**File:** app/models/shipit/commit.rb (L379-384)
```ruby
      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
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

**File:** app/models/shipit/stack.rb (L231-233)
```ruby
    def schedule_merges
      ProcessMergeRequestsJob.perform_later(self)
    end
```
