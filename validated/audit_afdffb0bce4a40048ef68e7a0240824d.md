### Title
Global SHA-based commit lookup in `StatusHandler#process` lets any repository's CI status poison another repository's commit and trigger continuous deployment - ([File: app/models/shipit/webhooks/handlers/status_handler.rb], [File: app/models/shipit/commit.rb])

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` resolves the target commit(s) for an incoming `status` webhook by a **global, repository-agnostic** `Commit.where(sha: params.sha)` lookup, then calls `commit.create_status_from_github!(params)` on every match. Because git commit SHAs are content-addressed, an attacker who forks a victim's public repository shares identical commit SHAs with the victim, and can get GitHub to deliver a legitimately-signed `status` webhook from *their own* fork/org that is applied to the *victim's* `Shipit::Commit` row, poisoning `Commit#deployable?` and causing `Stack#next_expected_commit_to_deploy` to select a commit that was never validated by the victim's own CI.

### Finding Description
The broken binding is:
`status.stack_id (Status created) == commit.stack.repository.full_name's own CI provider report`
should always hold as
`payload.repository.full_name == commit.stack.repository.full_name`,
but the code never checks this equality.

Path:
1. `WebhooksController#create` dispatches based only on `X-Github-Event` and validates the signature against `Shipit.github(organization: repository_owner)`, i.e. against **whichever org/repo the payload claims to be from** [1](#0-0) . This proves the payload came from GitHub for the *sender's own* repository/org — it says nothing about which `Shipit::Stack` the status should apply to.
2. `Shipit::Webhooks.default_handlers` routes `status` events to `Handlers::StatusHandler` [2](#0-1) .
3. `StatusHandler#process` looks up commits **purely by SHA, globally across the entire Shipit installation**, ignoring `params.repository` entirely: [3](#0-2) 
4. For every matching `Commit` (regardless of which `Stack`/repository it belongs to), `create_status_from_github!` is invoked, which creates a `Status` scoped to `commit.stack_id` (the victim's own stack) via `add_status` [4](#0-3)  and [5](#0-4) .
5. `Commit#deployable?` then trusts this forged status: `!locked? && (stack.ignore_ci? || (success? && !blocked?))` [6](#0-5) .
6. `Stack#next_expected_commit_to_deploy` / `next_commit_to_deploy` select the poisoned commit for continuous deployment based solely on `deployable?` [7](#0-6) [8](#0-7) .

Exploit flow: the attacker forks the victim's public GitHub repository (any unprivileged GitHub user can fork). Shared history commits retain identical SHA-1 hashes between fork and upstream (git objects are content-addressed). The attacker (owner of the fork) posts a commit status of `state: success` on their own fork for that shared SHA using their own GitHub credentials — this is a fully legitimate action on their own repository, requiring no Shipit secret. GitHub delivers a `status` webhook to Shipit, signed for the attacker's own org, which passes `verify_signature` because that check only validates the sender's own org key, not that the org matches the target stack. `StatusHandler#process` then finds the victim's `Commit` row (same SHA, different stack_id) and writes a `success` `Status` onto it.

Existing guards don't stop this: `verify_signature` verifies webhook authenticity for the sending org only [9](#0-8) ; `ExplicitParameters` schema in `StatusHandler` only validates types/shape of `sha`/`state`/etc, not repository ownership [10](#0-9) ; there is no `Repository`/stack scoping anywhere in the handler.

### Impact Explanation
An unprivileged attacker who owns any fork of a victim's public repository can, using only actions on their own fork (no victim secrets, no Shipit session), fabricate a "green" CI signal on a commit belonging to a completely different tenant/repository/stack. If that victim stack has `continuous_deployment: true` and was previously blocked pending real CI, the forged status flips `deployable?` to true and causes `Stack#next_expected_commit_to_deploy`/`trigger_continuous_delivery` to select and deploy that commit — an unauthorized deploy of code that the victim's own CI never validated. This is a cross-tenant write (one repository's webhook mutating another repository's commit/stack state) and results in an unauthorized deploy, matching the Critical impact category.

### Likelihood Explanation
Preconditions are modest and attacker cost is low: the victim repository must be public (or otherwise forkable by the attacker) and its stack configured with `continuous_deployment: true`, with a commit currently blocked awaiting real CI. The attacker needs only to fork the repo and post a commit status via the standard GitHub UI/API on their own fork for a SHA that is shared with the victim (any commit predating the fork, which is guaranteed to exist for a freshly created fork). This is fully repeatable against any repository configured in the Shipit instance, without needing to guess or brute-force any secret — the attack is deterministic once the fork exists.

### Recommendation
`StatusHandler#process` (and `PullRequest`/other SHA/branch based handlers if similarly affected) must scope the `Commit` lookup to the repository identified in the webhook payload, not globally by SHA alone. Resolve the target `Stack`/`Repository` via `params.repository.full_name` (or the same `repository_owner`/`repository` resolution used by `WebhooksController`) and constrain `Commit.where(sha: params.sha, stack_id: stack.id)` (or join through `Stack -> Repository` and filter), so a status can only ever be applied to commits belonging to the stack whose repository actually emitted the event.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb` or extending `test/models/undeployed_commits_test.rb`):

```ruby
test "status webhook from unrelated repository poisons a commit belonging to a different stack" do
  victim_stack = shipit_stacks(:shipit) # continuous_deployment: true, repo "shopify/shipit-engine"
  attacker_stack = shipit_stacks(:cyclimse) # unrelated repo, "attacker/fork"

  shared_sha = "deadbeef1234"
  victim_commit = victim_stack.commits.create!(sha: shared_sha, message: "shared history", author: shipit_users(:walrus), committer: shipit_users(:walrus), authored_at: Time.now, committed_at: Time.now)

  # BEFORE: no CI ever ran for victim's own repo/CI provider
  refute_predicate victim_commit, :deployable?
  assert_nil victim_stack.next_expected_commit_to_deploy

  # Simulate a `status` webhook whose signature verifies for the ATTACKER's org
  # (payload.repository.full_name == "attacker/fork"), but whose sha matches
  # the victim's commit.
  payload = OpenStruct.new(sha: shared_sha, state: 'success', context: 'ci/attacker', description: nil, target_url: nil, created_at: Time.now.to_s)
  Shipit::Webhooks::Handlers::StatusHandler.new.process_params(payload) rescue nil
  Shipit::Commit.where(sha: shared_sha).each { |c| c.create_status_from_github!(payload) }

  victim_commit.reload

  # AFTER: victim commit is now deployable and selected for CD though victim's
  # own repository/CI provider never ran against it — binding
  # payload.repository.full_name == victim_stack.repository.full_name is false.
  assert_predicate victim_commit, :deployable?
  assert_equal victim_commit, victim_stack.next_expected_commit_to_deploy
end
```

This demonstrates: before the forged webhook, `deployable?` is false and no commit is selected; after applying a status keyed only by SHA (simulating a signed webhook from an unrelated repository), the victim commit becomes `deployable?` and is returned by `next_expected_commit_to_deploy`, with no equality check ever performed between the webhook's originating repository and the victim stack's repository.

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

**File:** app/models/shipit/webhooks.rb (L6-23)
```ruby
      def default_handlers
        {
          'push' => [Handlers::PushHandler],
          'pull_request' => [
            Handlers::PullRequest::OpenedHandler,
            Handlers::PullRequest::ClosedHandler,
            Handlers::PullRequest::ReopenedHandler,
            Handlers::PullRequest::EditedHandler,
            Handlers::PullRequest::AssignedHandler,
            Handlers::PullRequest::LabeledHandler,
            Handlers::PullRequest::UnlabeledHandler,
            Handlers::PullRequest::LabelCapturingHandler
          ],
          'status' => [Handlers::StatusHandler],
          'membership' => [Handlers::MembershipHandler],
          'check_suite' => [Handlers::CheckSuiteHandler]
        }
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

**File:** app/models/shipit/stack.rb (L235-243)
```ruby
    def next_commit_to_deploy
      commits_to_deploy = commits.order(id: :asc).newer_than(last_deployed_commit).reachable.preload(:statuses)
      if maximum_commits_per_deploy
        commits_with_max_applied = commits_to_deploy.limit(maximum_commits_per_deploy)
        deployable_commits(commits_with_max_applied) || deployable_commits(commits_to_deploy)
      else
        deployable_commits(commits_to_deploy)
      end
    end
```

**File:** app/models/shipit/stack.rb (L332-342)
```ruby
    def next_expected_commit_to_deploy(commits: nil)
      commits ||= undeployed_commits do |scope|
        scope.preload(:statuses, :check_runs)
      end

      commits_to_deploy = commits.reject(&:active?)
      if maximum_commits_per_deploy
        commits_to_deploy = commits_to_deploy.reverse.slice(0, maximum_commits_per_deploy).reverse
      end
      commits_to_deploy.find(&:deployable?)
    end
```
