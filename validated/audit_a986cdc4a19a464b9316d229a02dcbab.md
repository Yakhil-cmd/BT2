### Title
Cross-repository status forgery via unscoped SHA lookup enables blocking_statuses bypass/forced block - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits by bare SHA with no repository scoping, so a `status` webhook that is validly signed for one repository/organization can attach a GitHub status to `Commit` rows belonging to a completely different stack whenever the SHA matches. When the victim stack has `blocking_statuses` configured, this lets an attacker force `Commit#blocked?` to flip true/false and thereby gate or unblock deploys on a stack they never authenticated for.

### Finding Description
The broken invariant, stated as an equality that should hold but does not:
`Commit.where(sha: params.sha)` should equal `Commit.where(sha: params.sha, stack_id: stack_belonging_to(repository_owner_that_signed_the_webhook))`, but the code only implements the former: [1](#0-0) 

`Commit` rows are per-stack (each stack imports its own commits, `belongs_to :stack`), but the SHA column is not unique across stacks — a git commit with the same SHA can legitimately exist in more than one repository/stack (e.g. an attacker computing/reproducing a commit with identical tree/parents/metadata in a repository they control, or any repo mirroring/forking/sharing history with the victim). `WebhooksController#verify_signature` only proves that the payload's `repository.owner.login` matches a known GitHub organization's webhook secret — it authenticates *which org sent the request*, not *which commit/stack the payload is allowed to mutate*: [2](#0-1) 

Once `StatusHandler#process` iterates every `Commit` with that SHA regardless of stack, it calls `commit.create_status_from_github!(params)`, which writes into that commit's own `statuses` association: [3](#0-2) 

`Commit#blocked?` then evaluates purely from `stack.blocking_statuses` and the statuses attached to commits in that stack's range: [4](#0-3) 

and `deployable?`/`schedule_continuous_delivery` depend directly on that: [5](#0-4) [6](#0-5) 

Exploit flow: attacker owns/controls a GitHub repository R that is (or can be) registered as a Shipit stack, so a signature for R's organization is obtainable through a normal GitHub webhook delivery. Attacker crafts or discovers a commit whose SHA collides with a commit already imported into victim stack V's `commits` table (feasible in practice via forks/shared history/subtree merges/mirrors, or by locally constructing a commit with identical parent, tree, author/committer and timestamps to reproduce an existing public SHA). Attacker triggers (or has GitHub deliver) a `status` event for context `deploy/production`/`state` of their choosing on that SHA from repo R. `WebhooksController#verify_signature` passes because it only checks R's organization secret. `StatusHandler#process` then finds and mutates the `Commit` row belonging to stack V, adding a status that satisfies/violates V's `blocking_statuses`, forcing `blocked?` to flip and gating or releasing V's deploy pipeline — a payload authenticated for repository R mutating stack V's state.

None of the existing guards prevent this: `verify_signature` is org-scoped, not stack/commit-scoped; the `ExplicitParameters` schema in `StatusHandler` only validates types, not repo ownership; and `Commit.where(sha:)` performs no stack/repository filtering.

### Impact Explanation
An attacker who controls any repository onboarded to the same Shipit instance can write CI-status state for another tenant's commit records purely by SHA collision, without any credential belonging to the victim. Because `blocking_statuses` gates `deployable?`/`blocked?`, this can force or block deploys, rollbacks, or continuous delivery on a stack the attacker never authenticated against — matching "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy, rollback or merge" (Critical). The write is repeatable for any SHA collision the attacker can produce and is not limited to a single victim stack — any stack whose `commits` table contains a matching SHA is affected in the same request.

### Likelihood Explanation
Preconditions: the attacker needs (a) their own repository onboarded as a Shipit stack (or any repository whose org is registered with a valid webhook secret) so they can obtain a validly signed `status` webhook, and (b) a SHA collision with a commit already present in the victim stack's `commits` table. SHA collision at scale is not trivial for arbitrary content, but is realistic for repositories sharing history (forks, subtree/mirror setups, monorepo splits into multiple Shipit stacks) or for an attacker deliberately reproducing a known public commit's exact metadata in a repo they control. Attacker cost is low (one webhook payload); the action is fully repeatable once a colliding SHA is found.

### Recommendation
Scope the commit lookup in `StatusHandler#process` (and any other by-SHA-only lookups reachable from webhooks) to the repository that authenticated the webhook, e.g. filter `Commit.joins(:stack).merge(Stack.where(repository: repository_from_payload))` instead of a bare `Commit.where(sha: params.sha)`, so a status can only be applied to commits belonging to stacks whose repository matches the webhook's authenticated repository/organization.

### Proof of Concept
```ruby
# test/models/webhooks/status_handler_test.rb (illustrative)
test "status webhook does not affect commits belonging to a different repository/stack" do
  victim_stack = shipit_stacks(:shipit)
  victim_stack.update!(cached_deploy_spec: { "ci" => { "blocking" => ["deploy/production"] } })
  colliding_sha = "a" * 40

  victim_commit = victim_stack.commits.create!(sha: colliding_sha, message: "victim commit")

  attacker_repo_stack = create_stack(repository_owner: "attacker-org", repository_name: "attacker-repo")
  attacker_commit = attacker_repo_stack.commits.create!(sha: colliding_sha, message: "attacker's own commit, same sha")

  # Simulate a status webhook validly signed for attacker-org, referencing the shared SHA
  Shipit::Webhooks::Handlers::StatusHandler.new.call(
    "sha" => colliding_sha,
    "state" => "success",
    "context" => "deploy/production",
    "repository" => { "owner" => { "login" => "attacker-org" }, "full_name" => "attacker-org/attacker-repo" }
  )

  victim_commit.reload
  # INVARIANT (must hold, currently broken): a status authenticated for attacker-org/attacker-repo
  # must not appear on victim_stack's commit / must not change victim_commit.blocked?
  assert_empty victim_commit.statuses.where(context: "deploy/production"),
    "status webhook for attacker repo incorrectly wrote to victim stack's commit"
end
```
This demonstrates `victim_commit.statuses` receiving an entry from a webhook payload authenticated only for `attacker-org/attacker-repo`, proving the cross-repository write and consequent `blocked?`/`deployable?` manipulation on the victim stack.

### Citations

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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/commit.rb (L231-237)
```ruby
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
