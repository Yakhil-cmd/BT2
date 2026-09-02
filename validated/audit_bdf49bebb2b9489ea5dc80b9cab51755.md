### Title
Cross-repository status writes via unscoped `Commit.where(sha:)` in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits solely by SHA (`Commit.where(sha: params.sha)`) with no repository or stack scoping, then calls `commit.create_status_from_github!(params)` on every match [1](#0-0) . Since Git SHAs are content-addressed and identical commits can legitimately exist in multiple repositories (forks, shared history, cherry-picks with identical tree/parent/author data), a webhook signed for one repository can flip the CI status of a commit belonging to a completely different stack/repository, and that flip feeds directly into `blocked?`/`deployable?` gating in `Shipit::Commit` [2](#0-1) .

### Finding Description
The broken binding is: `status.repository == commit.stack.repository` is assumed but never checked; the actual invariant enforced by the code is only `status.sha == commit.sha`, evaluated globally across all stacks: [3](#0-2) .

Trace:
1. `WebhooksController#create` parses JSON and dispatches to handlers for the `status` event after `verify_signature` passes [4](#0-3) .
2. `verify_signature` resolves the GitHub App / HMAC secret keyed only by `repository_owner` (i.e., organization/account login extracted from the payload), not by the specific repository: [5](#0-4) . The secret comparison itself is a standard HMAC-SHA1 check in `GitHubApp#verify_webhook_signature` [6](#0-5) . This means the same webhook secret is valid for **any** repository under that organization/App installation — signature verification proves the payload came from GitHub for *some* repo owned by that org, not that it came from the specific repo whose commit is being mutated.
3. `StatusHandler#process` then updates **every** `Commit` row across the whole database that shares the reported SHA, regardless of which repository/stack it belongs to [1](#0-0) .
4. `Commit#create_status_from_github!` records the status and `add_status` recomputes `status`, potentially emitting `deployable_status`/`commit_status` hooks and triggering `stack.schedule_merges` [7](#0-6) [8](#0-7) .
5. `Commit#blocked?` iterates `stack.commits.reachable` between the last deployed commit and the current one and returns true if **any** is `blocking?` [9](#0-8) ; `deployable?` gates directly on `success?` and `!blocked?` [10](#0-9) . A forged/duplicate-SHA `failure` status for `continuous-integration/travis-ci` therefore can set or clear the blocking condition for a victim stack that never received that webhook from its own configured repository.

Root cause: `StatusHandler` (and `Commit`) trust the SHA alone as a global primary key for status attribution, when in reality SHAs are only unique within, at best, a shared history graph — not unique across unrelated repositories/organizations, and identical commits can and do exist across forked or mirrored repositories that may be tracked as separate Shipit stacks.

None of the listed guards prevent this: `verify_signature` authenticates "an org's webhook", not "this repository's webhook" for the specific commit being touched; there is no `ExplicitParameters` field or model validation tying the status payload's `repository` to the target `Commit#stack`; `require_permission!`/`User#authorized?` do not apply to the unauthenticated webhook path at all.

### Impact Explanation
A correctly-signed webhook for one repository/organization can mutate CI status, and therefore `blocked?`/`deployable?`, for a `Commit` belonging to an unrelated stack that happens to share the same SHA. This falls under "a payload for one repository mutating another's stack/commit" — Critical per the rubric, since it can force or block a deploy without the victim repository ever having sent that status. The blast radius is bounded by SHA-sharing conditions (fork relationships, shared history, or coincidental identical commit content) rather than being universally exploitable against arbitrary unrelated repositories with no shared history, since real SHA collisions between fully unrelated commits are computationally infeasible (SHA-1 collision).

### Likelihood Explanation
Exploitation requires: (a) the attacker's own repository be onboarded to the same GitHub organization/App installation as the victim's stack (since `verify_signature` keys the webhook secret by `repository_owner`), and (b) a commit with an identical SHA exist in both the attacker's repo and the victim's tracked repo/stack (realistic for forks sharing history, template repos, or migrated/split repos, but not for arbitrary unrelated public repositories). Given those preconditions, the attack is cheap and repeatable — the attacker only needs to produce a CI status (or forge one directly if they can reach the org's webhook endpoint with a valid signature) referencing the shared SHA with `state: failure` and `context: continuous-integration/travis-ci`.

### Recommendation
Scope `StatusHandler#process` to the repository that authenticated the webhook: resolve the target `Stack`/`Repository` from `params.repository` (`full_name`/`owner`+`name`) and restrict `Commit.where(sha: ...)` to `commits.joins(:stack).merge(Stack.where(repository: repo))` (or equivalent), rather than matching bare SHA across all stacks. Additionally, consider making webhook signature verification repository-scoped rather than organization-scoped where GitHub configuration allows it.

### Proof of Concept
```ruby
# test/models/webhooks/status_handler_test.rb (conceptual)
test "status webhook does not affect commits from a different stack sharing the same sha" do
  victim_stack = shipit_stacks(:shipit)
  victim_stack.update!(deploy_spec_hash_override... blocking_statuses: ['continuous-integration/travis-ci'])
  shared_sha = 'a' * 40

  victim_commit = victim_stack.commits.create!(sha: shared_sha, ...)
  attacker_stack = create_stack_for_different_repo # unrelated repository/owner
  attacker_commit = attacker_stack.commits.create!(sha: shared_sha, ...) # collision/shared-history scenario

  before_blocked = victim_commit.blocked?

  Shipit::Webhooks::Handlers::StatusHandler.new.call(
    'sha' => shared_sha,
    'state' => 'failure',
    'context' => 'continuous-integration/travis-ci',
    'repository' => { 'full_name' => attacker_stack.repository.full_name }
  )

  victim_commit.reload
  assert_equal before_blocked, victim_commit.blocked?, "victim stack's blocked? must not change from another repository's status webhook"
end
```
This test currently fails against the shown implementation because `StatusHandler#process` applies the status to every `Commit` matching the SHA regardless of `params['repository']`.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L7-24)
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```
