### Title
Unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` lets a status webhook from any GitHub org cross-apply to another repository's stack, enabling an unauthorized deploy under the bot identity - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves the target commit purely by `Commit.where(sha: params.sha)` with no repository/stack scoping, so a `status` webhook whose signature is validated only against the *sending* repository's org secret can write a `Status` onto a commit belonging to an unrelated stack whenever the SHA value collides (index on `commits` is `(stack_id, sha)`, not a global uniqueness constraint on `sha` alone, so multiple stacks can hold rows with the same `sha`). If the affected stack has `continuous_deployment` enabled, this write can flip `Commit#deployable?` to true and `Stack#trigger_continuous_delivery` will then run `trigger_deploy(commit, Shipit.user, ...)` [1](#0-0) , i.e. a deploy executed under the configured bot identity (`Shipit.user`) rather than any identity tied to the attacker's own authenticated repository.

### Finding Description
The broken binding the invariant assumes is: `status.stack_id == repository_that_authenticated(payload)`. In the actual code this equality does not hold.

- `WebhooksController#verify_signature` only checks that the payload was signed by the secret of `Shipit.github(organization: repository_owner)`, i.e. it authenticates *who sent the payload*, not *which commit/stack the payload is allowed to mutate* [2](#0-1) .
- `StatusHandler#process` then does:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [3](#0-2) 
This query is global across all stacks/repositories in the Shipit instance — it is not filtered by `repository_owner`, `repository.full_name`, or any stack scope. Compare with `CheckSuiteHandler#process`, which correctly scopes by `stacks.where(branch: ...)` before touching commits [4](#0-3) ; `StatusHandler` has no equivalent scoping.
- `Commit#create_status_from_github!` creates a `Status` row tied to `commit.stack` and, through `add_status`, can trigger `stack.schedule_merges` and `commit.schedule_continuous_delivery` [5](#0-4) [6](#0-5) .
- `Commit#schedule_continuous_delivery` enqueues `ContinuousDeliveryJob` when `deployable? && stack.continuous_deployment? && stack.deployable?` [7](#0-6) .
- `Stack#trigger_continuous_delivery` performs the deploy as `Shipit.user` — the configured bot identity (`bot_login`) — not any identity derived from the webhook sender [1](#0-0) .

Exploit flow: an attacker owns/controls a GitHub repository that is registered with a Shipit `GithubHook` (any repo they can push to and configure a webhook for, or any repo already onboarded to the Shipit instance under an org the attacker can trigger events from). They cause GitHub to fire a `status` event for a commit SHA that is identical to a SHA present in a victim stack's `commits` table (SHA identity is content-addressed, so this is achievable when histories are shared — e.g., a forked repo, a cherry-picked/rebase-preserved commit, or any case producing colliding blobs across repos onboarded to the same Shipit instance). The webhook is legitimately signed by the attacker's own repo secret, so `verify_signature` passes. `StatusHandler#process` then finds the victim's `Commit` row (because the lookup has no stack scope) and writes a `context: "sonarqube"`, `state: "success"` status onto it. If the victim stack requires `sonarqube` and has `continuous_deployment` enabled with a bot user configured, this status completes `deployable?` and a deploy is auto-triggered as `Shipit.user`.

None of the existing guards catch this: `verify_signature` authenticates the sender but not the SHA-to-stack binding; `drop_unhandled_event` only filters unknown event types; the `ExplicitParameters` schema on `StatusHandler` only validates presence/types of `sha`/`state`/`context`, not ownership [8](#0-7) ; there is no `Repository`-level check anywhere in the handler.

### Impact Explanation
A payload authenticated for one repository can write a `Status` record — and, given `continuous_deployment` + bot_login configuration, trigger a real deploy executed as the bot identity — against a stack/commit belonging to a completely different repository. This is a cross-tenant write and can lead to an unauthorized deploy, matching the "Critical: a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy" category. The blast radius is any stack in the same Shipit instance whose commit history can produce a SHA collision with a repo the attacker controls, and is repeatable per request (attacker can keep sending `status` events for known-shared SHAs).

### Likelihood Explanation
Requires: (1) the victim stack configured with `bot_login` (`Shipit.user`) and `continuous_deployment: true`, requiring a `sonarqube` (or similar) status; (2) a real or contrived SHA collision — trivially achievable if the attacker forks the victim's repo (fork commits share identical SHAs with upstream) and gets that fork onboarded/hooked in the same Shipit instance, or if the same commit is shared/cherry-picked across repos already onboarded. Given fork-based SHA sharing is very common in GitHub workflows, likelihood is non-trivial once both repos are present in the same Shipit deployment. No secrets or elevated privileges are needed beyond controlling a repository with its own valid webhook secret.

### Recommendation
Scope the commit lookup in `StatusHandler#process` (and any comparable handler) by the repository that authenticated the request, e.g. join through `Stack -> Repository` and filter `Commit.joins(:stack => :repository).where(sha: params.sha, shipit_repositories: { owner: repository_owner, name: repository_name })` before creating the status, mirroring the scoping already done in `CheckSuiteHandler`.

### Proof of Concept
minitest plan (`test/controllers/webhooks_controller_test.rb` or `test/models/webhooks/handlers/status_handler_test.rb`):
1. Seed two stacks in different repositories/orgs: `stack_a` (attacker-controlled, org `attacker-org`) and `stack_v` (victim, org `victim-org`) with `bot_login` configured (`Shipit.user`), `continuous_deployment: true`, and deploy spec requiring status context `sonarqube`.
2. Create `Commit` rows in both stacks sharing the identical `sha` value (simulating a fork/shared history collision): `commit_a = stack_a.commits.create!(sha: shared_sha, ...)`, `commit_v = stack_v.commits.create!(sha: shared_sha, ...)`.
3. Stub `GithubHook`/`verify_webhook_signature` to succeed for `attacker-org` only (as in existing tests, `GithubHook.any_instance.stubs(:verify_signature).returns(true)`).
4. POST to `/webhooks` with `X-Github-Event: status`, payload `{ "sha" => shared_sha, "state" => "success", "context" => "sonarqube", "repository" => { "full_name" => "attacker-org/attacker-repo", "owner" => { "login" => "attacker-org" } } }`.
5. Assert both sides of the equality: before the request, `commit_v.statuses.count == 0` and `stack_v.deployable? == false`(missing status); after the request, assert `commit_v.reload.statuses.count == 1` and the status's `stack_id == stack_v.id` even though the payload's `repository.full_name` was `attacker-org/attacker-repo`, proving the write crossed the repository boundary. Optionally assert `ContinuousDeliveryJob` enqueued for `stack_v` / `Task` created with `user_id == Shipit.user.id`.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
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
