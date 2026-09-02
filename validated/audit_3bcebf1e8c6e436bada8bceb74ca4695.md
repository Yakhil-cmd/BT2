### Title
Unscoped commit lookup by bare SHA in `StatusHandler#process` lets a status from one repository flip deploy/block state for a commit shared with another stack - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits by `Commit.where(sha: params.sha)` with no repository/stack filter, so a validly-signed `status` webhook from repository A will update the status of *any* `Commit` row in the database sharing that SHA, including one belonging to a completely different stack/repository B. This breaks the invariant "a status affects only the repository that authenticated it," but exploitation requires the attacker's repository and the victim's stack to actually share an identical commit SHA (e.g., via a fork of the victim's repo), not an arbitrary SHA of the attacker's choosing.

### Finding Description
The broken binding: the invariant claims `status.repository == webhook.authenticated_repository`, but the code enforces only `status.sha == webhook.sha`.

`Shipit::Webhooks::Handlers::Handler` exposes a `stacks`/`repository_name` helper scoped to the payload's `repository.full_name` [1](#0-0) , but `StatusHandler#process` never uses it:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [2](#0-1) 

Signature verification (`WebhooksController#verify_signature`) authenticates only that the payload came from a GitHub App/organization that owns *some* repository named in the payload - it uses `Shipit.github(organization: repository_owner)` where `repository_owner` is read straight from `params.dig('repository', 'owner', 'login')` [3](#0-2) . It does not constrain which `Commit` rows the handler is allowed to touch. `StatusHandler` then writes the status onto every `Commit` with a matching `sha`, regardless of which stack/repository it belongs to, and `Commit#create_status_from_github!` recomputes `status`/`deployable?`/`blocked?` for that commit via `Status::Group` and `stack.blocking_statuses` [4](#0-3) [5](#0-4) .

Exploit flow: an attacker forks a victim's public repository (an ordinary, unprivileged GitHub action) so a range of historical commits share byte-identical SHA-1 hashes with the upstream (git's content-addressing guarantees this - no hash collision is required, just shared history). If the attacker's fork/account is itself onboarded to Shipit with a valid `GithubHook`, GitHub will legitimately sign and deliver a `status` event when the attacker sets `state: failure`, `context: codecov/project` on that shared commit via the GitHub API on their own repo. `WebhooksController#verify_signature` validates this correctly, since it is a genuinely GitHub-signed event for the attacker's own org. `StatusHandler#process` then matches the shared SHA against `Commit.where(sha: ...)` and writes the failing status onto the row belonging to the *victim's* stack as well, changing that commit's `blocked?`/`deployable?` state.

The precedence bug in `Repository::provisioning_behavior`/`review_stacks_enabled` cited in the question (`OpenedHandler#provision?`, `ReopenedHandler#unarchive?`) is a real, separate logic issue [6](#0-5) , but it only governs whether a *review stack* gets auto-provisioned/archived from PR events. It has no bearing on the `codecov/project` status-flip scenario, which targets an already-existing Stack; the "review_stacks_enabled false" detail in the question does not add or remove any guard along the `StatusHandler` path.

### Impact Explanation
A commit `Status` row is written for a repository/stack that did not authenticate the payload, changing `Commit#deployable?`/`blocked?` and therefore Shipit's ship/block decision and continuous-delivery scheduling (`stack.schedule_merges`, `ContinuousDeliveryJob`) for the victim stack [7](#0-6) . This matches the "payload for one repository mutating another's stack/commit" Critical category, but only for commits whose SHA is genuinely shared (fork/shared-history scenario), not for arbitrary victim commits chosen by the attacker.

### Likelihood Explanation
Requires: (1) the attacker's own repository/account already onboarded to Shipit with a working `GithubHook`/App installation, so their own status events are validly signed; (2) a commit SHA shared between the attacker's repo and the victim's stack, realistically achievable only via forks or repos with common ancestry, not for arbitrary victim commits. Preconditions are non-trivial and situational, but attacker cost per successful attempt is a single API call once the fork/onboarding precondition is met, and it is repeatable against any stack sharing history with an onboarded attacker repository.

### Recommendation
Scope `StatusHandler#process` to the repository that authenticated the webhook, e.g. filter `Commit.joins(stack: :repository).where(sha: params.sha, shipit_repositories: { id: repository.id })` using the same `repository_name`/`Repository.from_github_repo_name` resolution already available via the base `Handler#stacks` helper, instead of a bare `Commit.where(sha: ...)`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "status for a SHA shared with another repository's stack must not affect that stack" do
  victim_stack = shipit_stacks(:shipit) # review_stacks_enabled: false, requires codecov/project
  shared_sha = "a" * 40
  victim_commit = victim_stack.commits.create!(sha: shared_sha, message: "shared commit")

  attacker_repo = Shipit::Repository.create!(owner: "attacker", name: "fork")
  attacker_stack = Shipit::Stack.create!(repository: attacker_repo, environment: "production")
  attacker_commit = attacker_stack.commits.create!(sha: shared_sha, message: "shared commit")

  payload = {
    "sha" => shared_sha,
    "state" => "failure",
    "context" => "codecov/project",
    "repository" => { "full_name" => attacker_repo.github_repo_name }
  }

  before = victim_commit.reload.deployable?
  Shipit::Webhooks::Handlers::StatusHandler.call(payload)
  after = victim_commit.reload.deployable?

  # Binding under test: victim_commit.deployable? before == victim_commit.deployable? after
  assert_equal before, after, "status from attacker_repo must not alter victim_stack's commit state"
end
```
This currently fails: the unscoped `Commit.where(sha: params.sha)` in `StatusHandler#process` updates both `attacker_commit` and `victim_commit`, flipping `victim_commit.deployable?` even though the webhook only authenticated `attacker_repo`.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L65-70)
```ruby
          def provision?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end
```
