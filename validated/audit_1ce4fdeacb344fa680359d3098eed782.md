### Title
Unscoped SHA lookup in `StatusHandler#process` lets a webhook authenticated for one repository flip commit status for another repository's stack - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves target commits with `Commit.where(sha: params.sha)` [1](#0-0)  without any repository/stack scoping, unlike sibling handlers (e.g. `PushHandler`) which restrict effects to `Repository.from_github_repo_name(repository_name).stacks` via the base `Handler#stacks` helper [2](#0-1) . Because the `commits` table is global across all stacks/repositories, a genuinely-signed status webhook for one repository will update the `Status` (and downstream `deployable?`/`blocked?`/merge-scheduling logic) of any other stack's `Commit` row that happens to share the same SHA.

### Finding Description
The broken binding: `status.repository.full_name == commit.stack.repository.full_name` is expected to hold for every `Status` row written from a webhook, but `StatusHandler#process` never checks it.

Trace:
1. `Shipit::WebhooksController#create` parses the raw JSON and dispatches to `Shipit::Webhooks.for_event(event)` handlers after `verify_signature`, which resolves the GitHub App/secret purely from `payload.dig('repository','owner','login')` (i.e. `repository_owner`) [3](#0-2) [4](#0-3) . This only proves the request came from GitHub for *some* repository under that owner/organization's installation — it proves nothing about which specific repository's commit history the SHA belongs to.
2. `StatusHandler#process` then does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [1](#0-0) , iterating over *every* `Commit` record in the database with that SHA regardless of which stack/repository it belongs to. The `payload['repository']['full_name']` field is read by the base `Handler` class for other handlers (`Handler#stacks`/`#repository_name`) [2](#0-1)  but is never consulted by `StatusHandler`.
3. `Commit#create_status_from_github!` → `add_status` writes the new `Status`, recomputes `status`, and — if the simple state flips to `success` — calls `stack.schedule_merges` and can flip `deployable?`/`blocked?` for that stack [5](#0-4) , [6](#0-5) .

Given the stated precondition (a commit SHA shared between the victim's stack and a repository the attacker controls/authenticates for — realistic e.g. via a fork sharing identical git history/SHAs with the upstream victim repo), the attacker can send (or legitimately trigger, via GitHub's real status API on their own repo) a `status` event with `context: ci/jenkins`, `state: success` for that shared SHA. `verify_signature` passes because it is a real webhook for the attacker's own repository/organization; `StatusHandler` then writes the `success` status onto the *victim's* `Commit` row too, because the lookup is bare-SHA and repository-agnostic. No other guard (`ExplicitParameters` schema, `drop_unhandled_event`, `force_github_authentication`, `User#authorized?`) checks repository identity for this handler; those guards address authentication/schema shape, not cross-repository scoping of the DB write.

### Impact Explanation
A `success` status written this way can immediately satisfy `Commit#deployable?`'s `success? && !blocked?` condition and un-block/allow merges or deploys on the *victim's* stack (`stack.schedule_merges`, continuous-delivery scheduling) [7](#0-6) , i.e. a payload authenticated for one repository mutates another repository's stack/commit state — a cross-tenant state manipulation matching the "Critical" impact category (payload for one repo mutating another repo's stack/commit). This is repeatable against any commit SHA collision the attacker can produce or observe (most straightforwardly via forks that share upstream history), and requires no privilege beyond controlling a repository/webhook source under the same GitHub App/organization configuration Shipit trusts.

### Likelihood Explanation
Preconditions: (1) attacker's repository is authenticated by the same `Shipit.github(organization: repository_owner)` config the victim stack's owner uses (e.g. shared GitHub App installation/org), and (2) a commit SHA exists in both the attacker-authenticated repository and the victim's Shipit `commits` table — trivially achievable by forking a public victim repository (fork preserves identical SHAs for shared history) or by any other means producing SHA collision across the two repos tracked in Shipit. Given those two conditions (both plausible in real, multi-repo/multi-team Shipit deployments), the attack costs a single real GitHub status webhook delivery (or a directly crafted `POST /webhooks` if the attacker can also forge/obtain a valid signature) and is fully repeatable against any repository sharing the trust boundary.

### Recommendation
Scope `StatusHandler#process` (and equivalently `CheckSuiteHandler` if it has the same pattern) to only the commits/stacks belonging to the repository named in `payload['repository']['full_name']`, mirroring the `Handler#stacks` helper used by `PushHandler`, e.g. `Commit.where(sha: params.sha, stack_id: stacks.select(:id))` instead of a bare `Commit.where(sha: params.sha)`.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`):
```ruby
test "process does not update a commit belonging to a different repository sharing the same SHA" do
  victim_stack = shipit_stacks(:shipit) # repository e.g. "shopify/shipit-engine"
  attacker_repository_full_name = "attacker/other-repo"
  shared_sha = "a" * 40

  victim_commit = victim_stack.commits.create!(sha: shared_sha, message: "shared ancestor commit")
  assert_not victim_commit.reload.deployable? # before: not success

  payload = {
    "sha" => shared_sha,
    "state" => "success",
    "context" => "ci/jenkins",
    "repository" => { "full_name" => attacker_repository_full_name },
  }

  Shipit::Webhooks::Handlers::StatusHandler.call(payload)

  refute_equal "success", victim_commit.reload.status.state,
    "status for victim commit changed after a webhook authenticated only for the attacker's repository"
end
```
Both sides of the equality (`status.repository.full_name` vs `commit.stack.repository.full_name`) should be asserted distinct before the call, and the test should show the victim commit's status was nonetheless mutated by the attacker-scoped payload, proving the invariant "a `ci/jenkins` status affects only the repository that authenticated it" is violated.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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
