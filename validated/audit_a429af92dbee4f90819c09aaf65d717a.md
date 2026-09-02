This confirms the vulnerability. The base `Handler` class provides a `stacks` helper that scopes lookups by `Repository.from_github_repo_name(repository_name)` [1](#0-0) , and `PushHandler` correctly uses this repository-scoped `stacks` relation [2](#0-1) . `StatusHandler`, however, ignores this scoping entirely and queries `Commit.where(sha: params.sha)` directly, with no reference to `payload['repository']` at all [3](#0-2) . Since the `commits` table has a unique index on `(sha, stack_id)` rather than a globally-unique `sha`, the same SHA can legitimately exist as separate `Commit` rows belonging to different stacks/repositories [4](#0-3) , and `StatusHandler#process` will write a status to all of them.

`verify_signature` only checks that the payload's claimed `repository.owner.login`/`organization.login` matches a webhook secret configured for that organization in Shipit [5](#0-4) , via `GitHubApp#verify_webhook_signature` which HMACs the raw body with that org's `webhook_secret` [6](#0-5) . It never checks that the specific repository in the payload is the one that owns the commit being updated. So any repository properly onboarded to the same Shipit instance (any organization with a configured GitHub App/webhook secret) can emit a validly-signed `status` event, and `StatusHandler` will apply it to every `Commit` row sharing that SHA across all stacks, including ones from unrelated repositories/organizations.

`Commit#create_status_from_github!` → `add_status` re-evaluates `deployable?`/`state` and, if the transition is favorable, calls `stack.schedule_merges` and, through `schedule_continuous_delivery`, enqueues `ContinuousDeliveryJob.perform_later(stack)` whenever `deployable? && stack.continuous_deployment? && stack.deployable?` [7](#0-6) [8](#0-7) . This is exactly the amplification the question describes: a forged/cross-repo `deploy/production` status can flip the victim stack's commit to deployable and trigger an actual auto-deploy via continuous deployment, or conversely force a block by injecting a `failure`/`error` state.

### Title
Cross-repository status forgery via unscoped `Commit.where(sha:)` in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits by bare SHA across the entire `commits` table instead of scoping to the repository that authenticated the webhook, unlike `PushHandler` which correctly uses the `Handler#stacks` repository-scoped helper. Combined with the `(sha, stack_id)` non-unique-SHA schema and `continuous_deployment` auto-shipping green commits, this lets a status legitimately signed for repository A silently mutate CI state for an unrelated stack B whenever a commit with an identical SHA also exists in B's history.

### Finding Description
The broken invariant: `payload['repository'].full_name == commit.stack.repository.full_name` is assumed but never enforced. `verify_signature` only validates that the HMAC matches the *organization's* webhook secret named in the payload [9](#0-8) ; it does not tie the signature to a specific repository or stack. `StatusHandler#process` then does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [3](#0-2)  with no repository filter at all, whereas the base `Handler` class exposes a `stacks` method precisely for this purpose, scoping to `Repository.from_github_repo_name(repository_name)` [1](#0-0) , which `PushHandler` uses [2](#0-1)  but `StatusHandler` does not.

Because the `commits` table's uniqueness constraint is `(sha, stack_id)`, not `sha` alone [4](#0-3) , distinct stacks (potentially backed by entirely different GitHub repositories/organizations) can each hold a `Commit` row with the same `sha` value. An attacker who has push access to any repository already onboarded to the same shared Shipit instance (any organization with a registered GitHub App/webhook secret) can craft a commit object byte-identical to a real commit that already exists in the victim's repo (git commit objects are content-addressed and public; reproducing the tree, parent, author, committer and timestamp yields the same SHA1) and push it into their own repository. GitHub will then send a genuinely, validly signed `status` webhook for the attacker's own repository/org with `context: deploy/production`, `sha: <shared-sha>`, `state: success` (or `failure`). `verify_signature` passes because the signature genuinely matches the attacker's own org's secret. `StatusHandler#process` then matches this SHA against *all* `Commit` rows sharing it, including the victim stack's row, and applies the forged status there.

### Impact Explanation
This is a payload for one repository mutating another repository's stack/commit state, which is explicitly listed as Critical impact. If the victim stack has `continuous_deployment` enabled and requires the `deploy/production` context, forging a `success` state can make an unreviewed/CI-failing commit `deployable?` and trigger `ContinuousDeliveryJob` via `Commit#schedule_continuous_delivery` [7](#0-6) , causing an unauthorized deploy of attacker-influenced state. Conversely, forging `failure`/`error` blocks legitimate deploys on the victim stack. The attack is repeatable against any stack/repository sharing the same Shipit instance, as long as the attacker can produce a colliding SHA and controls at least one onboarded repository.

### Likelihood Explanation
Preconditions: the attacker needs push access to some repository already onboarded to the target Shipit instance (own org/repo is sufficient — no special privilege on the victim's repo or org), and needs to reproduce an existing victim commit's SHA in their own repo (feasible because git commit objects are public/content-addressed). The victim stack must have `continuous_deployment` enabled for the deploy amplification, but blocking works even without it. Cost is low: no secrets, sessions, or GitHub App keys are required, only ordinary push/webhook capability on an owned repository.

### Recommendation
Scope `StatusHandler#process` to the repository that authenticated the webhook, e.g. restrict the commit lookup to `stacks.map(&:commits)` (using the `Handler#stacks` helper already used by `PushHandler`) or add an explicit `stack.repository.full_name == payload['repository']['full_name']` check before calling `create_status_from_github!`, and add a DB-level or application-level uniqueness guarantee that ties statuses to the reporting repository rather than a bare SHA.

### Proof of Concept
```ruby
# test/models/webhooks/handlers/status_handler_test.rb
test "status handler does not leak cross-repository/stack" do
  attacker_stack = shipit_stacks(:cyclimse) # different repository/org
  victim_stack = shipit_stacks(:shipit)
  victim_stack.update!(continuous_deployment: true)

  shared_sha = "deadbeef" * 5
  victim_commit = victim_stack.commits.create!(sha: shared_sha, ...)
  attacker_commit = attacker_stack.commits.create!(sha: shared_sha, ...) # same sha, different stack

  payload = {
    "sha" => shared_sha,
    "state" => "success",
    "context" => "deploy/production",
    "repository" => { "full_name" => attacker_stack.repository.full_name, "owner" => { "login" => attacker_stack.repository.owner } }
  }

  assert_no_enqueued_jobs only: ContinuousDeliveryJob do
    Shipit::Webhooks::Handlers::StatusHandler.call(payload)
  end
  refute_equal "success", victim_commit.reload.state # currently FAILS: victim_commit gets the forged status
end
```

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb (L1-5)
```ruby
class IndexCommitsOnStackIdAndSha < ActiveRecord::Migration[5.1]
  def change
    add_index :commits, %i(sha stack_id), unique: true
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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
