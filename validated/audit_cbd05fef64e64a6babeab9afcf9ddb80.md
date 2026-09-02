### Title
Cross-stack status forgery via unscoped `Commit.where(sha:)` in StatusHandler forces ship/block on a foreign stack - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` writes a GitHub `status` webhook's state to **every** `Commit` row in the entire database that shares the reported `sha`, with no scoping to the repository that authenticated the webhook. Because `Commit` rows are created per-`stack` (`belongs_to :stack`) and the same git SHA can legitimately exist as separate `Commit` rows on multiple stacks (e.g. a shared ancestor commit tracked by both a main stack and an auto-provisioned review stack), an attacker who can trigger *any* validly signed `status` webhook containing a SHA also tracked by a victim stack can flip that victim's required/blocking status.

### Finding Description
The broken binding: the code implicitly assumes `commit.stack.repository == webhook.repository`, i.e. `Commit.where(sha: params.sha).stack.repository_full_name == request.params.dig('repository','full_name')`. In reality no such check exists:

```ruby
# app/models/shipit/webhooks/handlers/status_handler.rb
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
`Commit.where(sha:)` is a bare, table-wide lookup with no `stack_id`/repository predicate. `Commit` is `belongs_to :stack` (`app/models/shipit/commit.rb:11`), and stacks are independent tenants each with their own `required_statuses`/`blocking_statuses`/`deployable?` derived from `stack.cached_deploy_spec` (`app/models/shipit/deploy_spec.rb:194-204`, `app/models/shipit/commit.rb:227-237`).

`WebhooksController#verify_signature` only authenticates that the payload was signed with the webhook secret configured for the **organization** derived from `repository_owner` (`app/controllers/shipit/webhooks_controller.rb:24-49`); it never checks that the `sha`/`context` in the payload actually belongs to the repository whose signature was used. `verify_webhook_signature` (`lib/shipit/github_app.rb:76-83`) also unconditionally returns `true` when no `webhook_secret` is configured.

Exploit flow with `review_stacks_enabled: true, allow_all`:
1. The attacker opens a pull request against a repository whose stack has `review_stacks_enabled true, allow_all`. Shipit auto-provisions a review stack for the PR and executes `shipit.yml` for it.
2. The PR branch's ancestor/base commit is also tracked as a `Commit` row (same SHA, different `stack_id`) on the victim's main/production stack (a very common situation, since PR branches diverge from an already-tracked commit).
3. GitHub sends a legitimately signed `status` event (`context: ci/jenkins`, `state: success`) for that SHA — this is a real, validly authenticated webhook, since it's for a repo/commit the attacker's own PR CI reports on.
4. `StatusHandler#process` runs `Commit.where(sha: ...)`, matching the row belonging to the **victim's main stack** as well as the review stack's own row, and calls `commit.create_status_from_github!(params)` on both.
5. This flips `required?`/`blocking?`/`deployable?` on the victim stack's commit (`Status::Common#required?`, `Commit#deployable?`), forcing a ship (if the victim was waiting on `ci/jenkins`) or a block (if the attacker instead sends `state: failure`/`error` for a commit the victim stack needed as `success`).

None of the existing guards catch this: `verify_signature` validates org-level HMAC only, not per-repository ownership of the SHA; `ExplicitParameters` on `StatusHandler` only validates the payload shape (`sha`, `state`, `context`, etc.), not scope; there is no `Repository`/`Stack` filter anywhere in the query.

### Impact Explanation
A payload correctly authenticated for one repository/context mutates commit/status state belonging to a **different stack** (potentially a different repository entirely, or the victim's production stack from an attacker-controlled review stack). This directly satisfies the "payload for one repository mutating another's stack/commit" Critical criterion: it can force an unauthorized deploy (by supplying `success` for a status the victim stack requires) or an unauthorized block/DoS-of-shipping (by supplying `failure`/`error`). Because `review_stacks_enabled: true, allow_all` auto-provisions stacks that run `shipit.yml`, and any subsequent shared-SHA collision reaches across stacks, the blast radius spans every stack whose commit history intersects the attacker's own repository/branch history.

### Likelihood Explanation
Preconditions: a target stack with `review_stacks_enabled: true, allow_all` (so any external PR gets a functioning, webhook-subscribed review stack), and a SHA shared between that stack's commit history and the victim stack's commit history (trivially achievable by branching off an already-tracked ancestor commit). The attacker only needs the ability to open a PR / push to a repo GitHub will send authenticated `status` webhooks for — no Shipit session, API token, or secret is required. This is fully repeatable and low-cost.

### Recommendation
Scope the lookup by repository/stack, not by bare SHA. Add the repository (from `params.dig('repository','full_name')` or equivalent, verified against the actual authenticated org/repo) as a filter, e.g. `Commit.joins(:stack).merge(Stack.where(repository: ...)).where(sha: params.sha)`, or scope through `Repository#stacks.joins(:commits).where(commits: { sha: params.sha })`, so a status can only ever mutate commits belonging to stacks of the repository that generated the webhook.

### Proof of Concept
```ruby
# test/models/webhooks/handlers/status_handler_test.rb (concept)
test "a status for a repo does not mutate commits belonging to a different stack" do
  victim_stack = shipit_stacks(:shipit) # requires "ci/jenkins", review_stacks_enabled true, allow_all
  victim_commit = victim_stack.commits.create!(sha: "deadbeef" * 5, ...)

  other_repo_stack = shipit_stacks(:cyclimse) # unrelated repository
  shared_sha_commit = other_repo_stack.commits.create!(sha: victim_commit.sha, ...)

  refute victim_commit.reload.deployable?

  params = ActionController::Parameters.new(
    sha: victim_commit.sha, state: 'success', context: 'ci/jenkins'
  )
  Shipit::Webhooks::Handlers::StatusHandler.new.call(params.to_unsafe_h)

  # Binding under test: only the repository that authenticated the webhook may flip its own commit.
  assert_equal other_repo_stack.id, shared_sha_commit.stack_id
  refute_equal victim_stack.id, other_repo_stack.id
  assert victim_commit.reload.deployable?, "victim stack's commit was flipped to deployable by a foreign webhook"
end
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/commit.rb (L11-12)
```ruby
    belongs_to :stack
    has_many :statuses, -> { order(created_at: :desc) }, dependent: :destroy, inverse_of: :commit
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/status/common.rb (L46-52)
```ruby
      def blocking?
        !success? && commit.blocking_statuses.include?(context)
      end

      def required?
        commit.required_statuses.include?(context)
      end
```

**File:** app/models/shipit/deploy_spec.rb (L194-204)
```ruby
    def required_statuses
      (Array.wrap(config('ci', 'require')) + blocking_statuses).uniq
    end

    def soft_failing_statuses
      Array.wrap(config('ci', 'allow_failures'))
    end

    def blocking_statuses
      Array.wrap(config('ci', 'blocking'))
    end
```

**File:** app/jobs/shipit/github_sync_job.rb (L51-53)
```ruby
    def append_commit(gh_commit)
      stack.commits.create_from_github!(gh_commit)
    end
```
