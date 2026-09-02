### Title
`ci/lint` status write is not repository-scoped, letting one repo's webhook flip another stack's required status - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` matches `Commit.where(sha: params.sha)` with no repository filter, while every other handler (e.g. `PullRequest::OpenedHandler`) resolves and scopes work through `Repository.from_github_repo_name(params.repository.full_name)`. Because the base `Handler` class exposes `repository_name`/`stacks` scoping helpers but `StatusHandler` does not use them, a correctly-signed `status` webhook from one GitHub repository can write a `Shipit::Status` row onto a `Commit` belonging to an entirely different `Shipit::Stack`, as long as the two commits share a SHA (e.g. a fork sharing history with the upstream/victim repo).

### Finding Description
The broken binding, stated as an equality that should hold but doesn't:

`commit.stack.repository.full_name == payload.repository.full_name` is **never checked** in `StatusHandler#process`: [1](#0-0) 

`process` iterates `Commit.where(sha: params.sha)` and calls `commit.create_status_from_github!(params)` on every match, regardless of which repository authenticated the webhook. Contrast this with `Handler#stacks`, which resolves the acting repository from the payload before touching any records: [2](#0-1) 

and with `PullRequest::OpenedHandler#repository`, which does the same: [3](#0-2) 

`create_status_from_github!` then recomputes the commit's aggregated `status` and, on a state transition, calls `stack.schedule_merges` when the new status is `success`: [4](#0-3) [5](#0-4) 

`Commit#deployable?` also depends directly on this status: [6](#0-5) 

**Signature verification does not close this gap.** `WebhooksController#verify_signature` authenticates the webhook against `Shipit.github(organization: repository_owner)`, i.e. it proves the payload came from *some* legitimate GitHub organization/app installation known to Shipit - it proves nothing about which *commit*/*stack* the SHA is allowed to affect: [7](#0-6) 

**Attacker's exact request:** the attacker owns (or controls a fork of) a repository whose organization is already onboarded to the Shipit instance (so a real, validly-signed `status` webhook can be emitted from GitHub). Because the fork shares commit history with the victim repository, a commit that exists in the victim's `Shipit::Stack` has an identical SHA in the attacker's own repo. The attacker (or GitHub CI acting on their behalf) posts a `status` event with `context: ci/lint`, `state: success`, `sha: <shared sha>`. GitHub signs and delivers this webhook legitimately for the attacker's own repo. `StatusHandler#process` then finds the `Commit` row belonging to the **victim** stack (matched purely on `sha`) and writes a `success` status for `ci/lint` there, exactly as if the victim repo's CI had reported it.

**Regarding the "provision precedence" reference in the prompt:** that logic lives in `PullRequest::OpenedHandler#provision?` / `ReopenedHandler#unarchive?`, not in `StatusHandler`. It is a real, separate defect - `review_stacks_enabled && allow_all? || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)` fails to gate the `allow_with_label?`/`prevent_with_label?` branches on `review_stacks_enabled` at all, due to Ruby's `&&`/`||` precedence: [8](#0-7) 

but this only controls whether a *review stack gets provisioned/unarchived* from a `pull_request` event; it has no code path into `StatusHandler`, `Commit#create_status_from_github!`, or `Commit#deployable?`. The scenario described (`review_stacks_enabled: false` "yet provisioning still occurs" driving the `ci/lint` success into a ship/block decision) requires chaining two unrelated handlers and unrelated state machines that don't share a call path in this codebase, and I found no code connecting the provisioning precedence bug to the status-write scoping bug.

### Impact Explanation
This is a genuine cross-tenant write: a `status` payload authenticated for repository A mutates `Shipit::Status` state for a `Commit`/`Stack` belonging to repository B, purely because the SHAs coincide. Since `ci/lint` can be configured as a required/blocking status, flipping it to `success` can make `Commit#deployable?` true and trigger `stack.schedule_merges`, i.e. an unauthorized deploy/merge decision on a stack the attacker never authenticated against - matching the Critical class "a payload for one repository mutating another's stack, commit ... or an unauthorized deploy/merge." [9](#0-8) 

### Likelihood Explanation
Exploitability is gated by a strict precondition: the attacker's authenticated repository and the victim's stack must share an identical commit SHA, which in Git only happens for genuinely shared history (a fork/mirror of the victim repo, or an upstream commit later merged into both). The attacker also needs their own repository/organization already onboarded to the target Shipit instance so `verify_signature` will accept their webhook. This is realistic in the common "fork-based contribution" workflow (public/OSS repos on Shipit) but not a trivial "any internet user" attack against an arbitrary target - it requires the attacker's repo and the victim stack to be commit-history-linked and both configured in the same Shipit instance.

### Recommendation
Scope `StatusHandler#process` (and `Commit`/`CheckRun` webhook ingestion generally) by the webhook's `repository.full_name`, not by bare SHA - e.g. resolve `Repository.from_github_repo_name(params.repository.full_name)` first, then only update commits belonging to that repository's stacks (mirroring the pattern already used in `Handler#stacks` and the `PullRequest` handlers). Separately, fix the `provision?`/`unarchive?` boolean-precedence bug in `PullRequest::OpenedHandler`/`ReopenedHandler` so `review_stacks_enabled` gates *all* provisioning behaviors, not just `allow_all?`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "status webhook for repo A does not affect a commit belonging to repo B's stack" do
  victim_repo = shipit_repositories(:shipit) # owns victim_stack, review_stacks_enabled: false
  victim_stack = victim_repo.stacks.create!(environment: "production", branch: "main")
  shared_sha = "a" * 40
  commit = victim_stack.commits.create!(sha: shared_sha, message: "shared commit")

  # attacker's repository B shares the same sha (e.g. fork), and sends a validly-signed
  # status payload naming repository B, not repository A/victim.
  payload = payload_parsed(:status)
  payload["sha"] = shared_sha
  payload["context"] = "ci/lint"
  payload["state"] = "success"
  payload["repository"]["full_name"] = "attacker/other-repo"

  before = commit.reload.status.state

  Shipit::Webhooks::Handlers::StatusHandler.new(payload).process

  assert_equal before, commit.reload.status.state,
    "status for repo=#{payload['repository']['full_name']} must not mutate commit owned by #{victim_repo.full_name}"
end
```
Running this against current `StatusHandler#process` fails the assertion: the commit's aggregate status changes to `success` even though the webhook's `repository.full_name` never matches `victim_repo`, proving the SHA-only, repository-unscoped write.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L65-70)
```ruby
          def provision?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
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
