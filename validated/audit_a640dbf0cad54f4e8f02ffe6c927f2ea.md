### Title
Cross-repository status webhook forges CI success on another stack's commit, triggering an unauthorized continuous-delivery deploy - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits purely `by sha`, with no check that the webhook's `repository.full_name` matches the repository owning the commit/stack it updates. An attacker who controls any repository B in a GitHub organization already configured in Shipit (owner-level webhook signing) can craft a `sha` collision against a pending commit in victim stack A and push a forged `success` status, which cascades into `Commit#schedule_continuous_delivery` → `ContinuousDeliveryJob` → `Stack#trigger_continuous_delivery`, causing a real deploy of A's commit.

### Finding Description
The binding that should hold is:
`payload.dig('repository','full_name') == commit.stack.repository.full_name` for any Status created from a webhook.

`StatusHandler#process` breaks this binding: [1](#0-0) 
It does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` with no join/filter on the payload's `repository.full_name`, unlike every other GitHub webhook handler in the codebase (e.g. `PullRequest::OpenedHandler`, `LabeledHandler`, `AssignedHandler`), which resolve `Repository.from_github_repo_name(params.repository.full_name)` before touching any stack-scoped record: [2](#0-1) 
The base `Handler#stacks` helper even implements this correct scoping pattern, but `StatusHandler` never uses it: [3](#0-2) 

Signature verification in `WebhooksController#verify_signature` keys the GitHub App/secret lookup by `repository_owner` (the org/owner login from the payload), not by the specific repository: [4](#0-3) 
So any repository under an organization Shipit already has a GitHub App/webhook secret for produces a validly-signed webhook — including a repository the attacker owns/controls within that org (fork, personal repo, etc.), consistent with the stated threat model of "emit webhooks from a repository they own."

Because git commit SHAs are content+parent-chain addressed, an attacker who forks or clones the history of victim repo A's branch (a normal, unprivileged GitHub action) reproduces identical commit SHAs for existing commits, including one still pending CI in stack A. The attacker then sets a `success` status on that SHA via the GitHub API on their own repo B; GitHub delivers a validly-signed `status` webhook to Shipit with `repository.full_name = B` and `sha = <victim's sha>`.

`StatusHandler#process` finds the matching `Commit` row that belongs to stack A (already synced because it's a real, pending commit on A's tracked branch) and calls `create_status_from_github!`, creating a `Status` record scoped to stack A. `after_commit :schedule_continuous_delivery` fires: [5](#0-4) 
which calls `Commit#schedule_continuous_delivery`: [6](#0-5) 
`deployable?` only checks `success?`/`locked?`/`blocked?`, derived from `status` built via `statuses_and_check_runs` — it has no notion of which repository actually produced the status: [7](#0-6) 
`ContinuousDeliveryJob` then invokes `Stack#trigger_continuous_delivery`, which — if stack A has `continuous_deployment?` enabled and is otherwise deployable — calls `trigger_deploy` on the forged-success commit: [8](#0-7) 

Existing guards do not stop this: `verify_signature` validates per-organization, not per-repository, so it does not bind the webhook to the specific repo it claims to be from; `drop_unhandled_event` and `ExplicitParameters` only validate payload shape, not repository identity; there is no `require_permission!`/`stacks`-scope check in `StatusHandler` at all.

### Impact Explanation
An attacker forges GitHub CI success for a real pending commit belonging to a victim's stack from a repository they control, and that forged status is sufficient — combined with `continuous_deployment?` — to trigger an autonomous, real deploy (`Command`/`PTY.spawn` execution) of that commit to the victim's deploy host. This is a cross-tenant mutation: "a payload for one repository [B] mutating another's stack, commit, task [A]" resulting in "an unauthorized deploy," matching the Critical category. It is repeatable against any stack in the same GitHub organization that has continuous deployment enabled and a pending commit, and scales to every such stack under that organization/app installation.

### Likelihood Explanation
Preconditions: (1) attacker controls a repository under an organization/owner for which Shipit already has GitHub App credentials configured (a normal situation for engineers inside a company's GitHub org, or for any org allowing public app installs); (2) victim stack A has `continuous_deployment?` enabled and a commit currently pending CI on its tracked branch; (3) attacker can reproduce an identical SHA (trivial via fork/clone of A's history) and issue a `POST` status via the GitHub API on their own repo, which GitHub relays as a signed webhook. No Shipit secret, session, or API token is required — this matches the permitted "emit webhooks from a repository they own" capability. This is low-cost and fully repeatable.

### Recommendation
Scope `StatusHandler#process` to only update commits whose stack's repository matches `params.repository.full_name` (mirroring the `Handler#stacks`/`Repository.from_github_repo_name` pattern used by the pull-request handlers), e.g. restrict `Commit.where(sha: params.sha)` to `stacks` returned by `Repository.from_github_repo_name(repository_name).stacks` before creating any `Status`.

### Proof of Concept
Minitest plan (models/webhooks, no live GitHub):
1. Create `stack_a` (repository "victim/repo") with `continuous_deployment: true`, `ignore_ci: false`; create `commit` under `stack_a` with a known `sha` and no statuses (pending).
2. Stub `Command`/`PTY.spawn` to a no-op fake executor (as other deploy tests do) so `run_now!`/`enqueue` don't shell out for real, but capture that `Deploy.create` happened.
3. Build a `status` webhook payload with `repository.full_name = "attacker/repo-b"`, `sha = commit.sha`, `state = "success"`.
4. Call `Shipit::Webhooks::Handlers::StatusHandler.call(payload)` directly (bypassing controller signature check, since the security question is about `StatusHandler` scoping, not signature verification).
5. Assert both sides of the binding:
   - Before: `payload.dig('repository','full_name') != commit.stack.repository.full_name` ("attacker/repo-b" vs "victim/repo").
   - After: `commit.statuses.last.present?` is true and `commit.reload.success?` is true, i.e., stack_a's commit now has a success status despite the mismatch.
6. `assert_enqueued_with(job: ContinuousDeliveryJob, args: [stack_a])` after the webhook call.
7. `perform_enqueued_jobs` and `assert_difference('Deploy.count', 1) { ... }`, confirming `stack_a.trigger_continuous_delivery` created/ran a `Deploy` for the attacker-forged-success commit — proving the cross-repository forgery reached a real deploy trigger.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-54)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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
