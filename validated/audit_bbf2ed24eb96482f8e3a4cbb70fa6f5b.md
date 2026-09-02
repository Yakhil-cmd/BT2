### Title
Cross-repository Status webhook confusion sets CI state on unrelated stacks' commits by sha alone, enabling unauthorized `continuous_deployment` deploys - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` resolves the target commit(s) to update purely by `Commit.where(sha: params.sha)`, with no repository/stack scoping, unlike other handlers that use the `Handler#stacks` helper (`Repository.from_github_repo_name(repository_name)&.stacks`). Any GitHub `status` event whose payload contains a `sha` that happens to also exist as a `Commit` row belonging to an unrelated stack will overwrite that unrelated commit's CI status, potentially unblocking `Stack#trigger_continuous_delivery` for a stack that never had CI run against its own repository for that commit.

### Finding Description
Binding claimed by the question, stated as an equality:

`CI result consumed by Stack#trigger_continuous_delivery for S2's commit C2` == `status write produced by a webhook whose payload.repository.full_name == S2's tracked repository (R2)`

Traced code:
- `WebhooksController#create` dispatches the parsed JSON payload to `Shipit::Webhooks.for_event(event)` handlers after `verify_signature`, which only checks that the HMAC signature is valid for `Shipit.github(organization: repository_owner)` — i.e., it authenticates that the payload really came from GitHub *for that organization*, not that the sha belongs to a specific repository [1](#0-0) .
- `Handler` base class exposes a `stacks` helper that scopes by `payload.dig('repository', 'full_name')` via `Repository.from_github_repo_name` [2](#0-1) .
- `StatusHandler#process`, however, never calls `stacks`. It runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`, matching **only** on the raw `sha` string, globally across every stack in the installation [3](#0-2) .
- `Commit#create_status_from_github!` unconditionally writes the new status via `statuses.replicate_from_github!` and touches the commit's cached status [4](#0-3) .
- `Commit#blocked?`/`#deployable?` and `Stack#trigger_continuous_delivery` (via `ContinuousDeliveryJob`) consume this cached `status`/`state` with no re-validation that the status originated from the stack's own tracked repository [5](#0-4) .

Root cause: two independent commits (C1 in attacker-controlled repository R1, C2 in victim repository R2 tracked by stack S2) can legitimately share the same git `sha` when R1 is a fork of R2 (git commit hashes are content-addressed and identical across forks for shared history). If the attacker's repository R1 remains under a GitHub organization/App installation that Shipit already trusts (`Shipit.github(organization: repository_owner)` resolves successfully — the common case for a single-org, multi-repo Shipit deployment), a genuine GitHub `status` webhook fired by the attacker's own CI against their fork (R1) for that shared sha will pass `verify_signature` (it's a real GitHub-signed event for a trusted org) and then be dispatched to `StatusHandler`, which updates the status of **any** `Commit` row with that sha — including C2 belonging to victim stack S2 — without ever checking `payload.repository.full_name` against S2's repository.

This bypasses `deployable?`/`blocked?`'s intended guarantee that a commit's CI state reflects that commit's own repository, letting `Stack#trigger_continuous_delivery` deploy S2 up through C2 with no legitimate CI run against R2.

### Impact Explanation
A write intended for repository R1 mutates the CI status of a commit belonging to victim stack S2/repository R2 — this is exactly "a payload for one repository mutating another's stack/commit." If S2 has `continuous_deployment: true`, `ContinuousDeliveryJob`/`Stack#trigger_continuous_delivery` will deploy code up to and including C2 that never had a real CI run in R2. This is an unauthorized deploy driven entirely by cross-tenant status confusion — Critical impact. Blast radius is bounded to stacks/repositories that share commit history (sha collisions) with a repository the attacker can push to and that remains within a Shipit-trusted GitHub organization; it is repeatable for every shared/forked sha and for every stack tracking that repository.

### Likelihood Explanation
Preconditions: (1) attacker needs a repository (fork or shared-history repo) whose owner/org is one that Shipit already has GitHub App/webhook trust for (`Shipit.github(organization: repository_owner)` must succeed) — plausible in single-org deployments where many repos/forks live under one trusted org; (2) the target commit sha must exist verbatim in both the attacker's repo and the victim stack's repo, which happens automatically for forked repositories sharing history; (3) victim stack S2 must have `continuous_deployment: true` and a blocking/required status context matching the one the attacker sets. Cost to the attacker is low (fork + push/CI trigger, or a legitimate status webhook from their own tooling) and requires no secrets, sessions, or privileged roles — signature verification passes because the event is a genuine GitHub webhook for a trusted org, just for the wrong repository.

### Recommendation
In `StatusHandler#process`, scope the commit lookup by the webhook's own repository, e.g. filter `Commit.where(sha: params.sha)` to commits whose `stack_id` is in `stacks.pluck(:id)` (using the existing `Handler#stacks` helper, resolved from `payload.dig('repository', 'full_name')`), mirroring how other handlers (e.g. `PushHandler`, `CheckSuiteHandler`) already scope by repository. This ensures a status write can only ever affect commits that belong to the same repository the webhook was actually sent for.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "status webhook does not update commits belonging to a different repository sharing the same sha" do
  victim_stack = shipit_stacks(:shipit) # tracks repo "shopify/shipit-engine", continuous_deployment: true
  shared_sha = "deadbeef" * 5
  c2 = victim_stack.commits.create!(sha: shared_sha, author: shipit_users(:shipit),
                                     committer: shipit_users(:shipit), authored_at: Time.now,
                                     committed_at: Time.now, message: "victim commit")

  # attacker's own repo shares history/sha with victim repo (e.g. a fork), payload targets R1 not R2
  attacker_payload = {
    'sha' => shared_sha,
    'state' => 'success',
    'context' => 'ci/required',
    'repository' => { 'full_name' => 'attacker/fork-of-victim', 'owner' => { 'login' => 'trusted-org' } }
  }

  assert_no_difference -> { c2.reload.statuses.count } do
    Shipit::Webhooks::Handlers::StatusHandler.call(attacker_payload)
  end

  refute c2.reload.success?
end
```
Both sides of the equality are checked here: `payload.repository.full_name` ("attacker/fork-of-victim") is asserted to be != C2's stack repository ("shopify/shipit-engine"), and the assertion confirms `create_status_from_github!` must not fire for C2 — currently, with the unscoped `Commit.where(sha: params.sha)` lookup, this test fails because C2's status is updated and `ContinuousDeliveryJob` would subsequently deploy S2 up to C2.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-49)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end

    private

    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
    end

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
