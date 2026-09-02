### Title
`StatusHandler#process` writes GitHub commit statuses to every stack sharing a commit SHA, not just the authenticated repository - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves target commits with `Commit.where(sha: params.sha)`, a query with no repository/stack scoping. Any repository that can produce a validly-signed `status` webhook for a SHA that also exists in another tenant's stack (e.g. a public fork that preserves upstream commit SHAs) will have its status written onto every `Commit` row across the installation that shares that SHA, mutating other tenants' deployability state.

### Finding Description
The invariant that should hold is: `commit.stack_id == repository_that_authenticated_the_webhook.stack_id` for every `Status` created by `StatusHandler`. That binding is never enforced.

Path: `POST /webhooks` → `Shipit::WebhooksController#create` (`app/controllers/shipit/webhooks_controller.rb:10-15`) validates only the HMAC signature via `verify_signature`, keyed off `Shipit.github(organization: repository_owner)` [1](#0-0) . It never checks that `params['repository']['full_name']` matches the repository owning the commit(s) being mutated. It then dispatches to `StatusHandler.call(params)` [2](#0-1) .

`StatusHandler#process` then does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [3](#0-2) 

Unlike the pull-request handlers, which explicitly resolve `repository = Shipit::Repository.from_github_repo_name(params.repository.full_name)` before acting [4](#0-3) , `StatusHandler` never consults `params.repository` at all. `Commit#sha` is a global column with no uniqueness scoping enforced here, so `Commit.where(sha:)` can return rows belonging to *any* stack in the installation whose commit history happens to contain that exact SHA — which is the normal case for forks, since git commit hashes are preserved verbatim across forks/clones of the same content and parents.

`create_status_from_github!` → `add_status` then persists a `Status` row against `stack_id: commit.stack_id` (the victim's stack), recomputes `Commit#status`, and if the simple state changes, fires `Hook.emit(:deployable_status, ...)` and `stack.schedule_merges` [5](#0-4) . `Commit#deployable?` is `!locked? && (stack.ignore_ci? || (success? && !blocked?))` [6](#0-5) , so flipping a required context to `success` can make an otherwise-blocked victim commit deployable, or a `failure`/`error` status can block it.

Exploit flow: attacker owns/forks a public repository that shares commit history (and thus SHAs) with a victim's tracked repository, and has the same GitHub App installed (a normal, unprivileged action for any GitHub user). Attacker uses GitHub's own Status API on their fork to set `context: ci/integration, state: success` for a SHA that is also present in the victim's stack. GitHub delivers a genuinely-signed `status` webhook (signed with the app's webhook secret, which is not per-repository) to the shared Shipit instance. `verify_signature` passes because the signature is valid for the installation, `drop_unhandled_event`/`ExplicitParameters` schema pass because the payload is well-formed, and `StatusHandler` writes the status onto the victim's `Commit` because it never checks which repository authenticated the request.

The `review_stacks_enabled` "provisioning precedence bug" cited in the question is unrelated to this path: that flag and the `provision?` predicate operator-precedence issue live only in `PullRequest::OpenedHandler`/`ReopenedHandler`/`LabeledHandler` and govern whether a new review stack gets provisioned/archived [7](#0-6) . It has no bearing on `Commit#deployable?`, `Status`, or `StatusHandler`, so the framing that "review stacks disabled yet still provisions, forcing ship/block" does not hold — `review_stacks_enabled` does not gate status processing at all. This part of the question's premise is incorrect and should be disregarded; the real, demonstrable bug is solely the unscoped `Commit.where(sha:)` lookup in `StatusHandler`.

### Impact Explanation
A status delivered by one repository's authenticated webhook mutates `Status`/deployability state for a commit belonging to a different stack/tenant, matching the Critical category "a payload for one repository mutating another's stack, commit." This can force a previously-blocked commit into `deployable?` (enabling an unauthorized deploy/continuous-delivery trigger via `schedule_continuous_delivery`/`ContinuousDeliveryJob`) or conversely block/lock out a legitimately passing commit in the victim's stack. It is repeatable against any stack whose commit history overlaps (via forks or shared upstream) with a repository the attacker controls.

### Likelihood Explanation
Preconditions: the attacker needs a repository (e.g. a fork) that shares at least one commit SHA with a victim's tracked stack and has the same GitHub App/webhook integration installed — both are ordinary, unprivileged GitHub actions (forking a public repo and installing a public app preserves commit SHAs and produces genuinely signed webhooks). No Shipit secrets, sessions, or API tokens are required. This is a low-cost, cheaply repeatable attack once a shared-SHA repository relationship exists.

### Recommendation
Scope `StatusHandler#process` to the repository that authenticated the webhook: resolve the repository from `params.repository.full_name`, and only touch commits under stacks belonging to that repository (e.g. `Commit.where(sha: params.sha, stack_id: repository.stacks.select(:id))` instead of a bare `Commit.where(sha:)`), mirroring the scoping already done in the `PullRequest::*` handlers.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "status for a SHA shared across stacks only updates the authenticated repository's commit" do
  attacker_repo  = create_repository(github_repo_name: "attacker/repo")
  victim_stack   = shipit_stacks(:shipit) # tracked by a different repository
  shared_sha     = "deadbeef" * 5

  attacker_commit = attacker_repo.stacks.first.commits.create!(sha: shared_sha, ...)
  victim_commit    = victim_stack.commits.create!(sha: shared_sha, ...)

  payload = {
    "sha" => shared_sha, "state" => "success", "context" => "ci/integration",
    "repository" => { "full_name" => "attacker/repo", "owner" => { "login" => "attacker" } }
  }

  Shipit::Webhooks::Handlers::StatusHandler.new(payload).process

  assert_equal "success", attacker_commit.reload.state
  # Binding under test: victim_commit.state must be unaffected by attacker's webhook
  assert_not_equal "success", victim_commit.reload.state, "victim stack's commit state changed from an unrelated repository's webhook"
end
```
This currently fails: `victim_commit.reload.state` becomes `"success"` because `StatusHandler` matches on bare SHA without repository scoping.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
