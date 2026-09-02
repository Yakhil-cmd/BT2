### Title
`StatusHandler#process` applies GitHub status webhooks to commits by SHA with no repository scoping, allowing a webhook verified for one repository to unblock a completely different stack's commits - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` only proves that the request was signed with the GitHub App's organization-level `webhook_secret` derived from the payload's own `repository.owner.login`, it never proves the payload's `repository` matches the repository that owns the commit being mutated. `StatusHandler#process` compounds this by resolving the target commit(s) purely via `Commit.where(sha: params.sha)`, with no join through `repository_name`/`stacks`, unlike the sibling `CheckSuiteHandler` which correctly scopes through `stacks`. This lets a request that is legitimately signed for repository A silently mutate a `Commit` row that belongs to repository B's stack, as long as the attacker supplies B's already-public commit SHA.

### Finding Description
The broken binding, stated explicitly: the request is authenticated as `repository_owner == organization_of(webhook_secret_used)` [1](#0-0) , but the mutation actually performed is `Commit.where(sha: params.sha)` with **no** constraint that `commit.stack.repository == payload['repository']`. These are not the same repository in general, yet the code proceeds as if they were.

Trace:
1. `WebhooksController#create` dispatches the parsed JSON payload to `Shipit::Webhooks.for_event('status')`, i.e. `StatusHandler.call(params)` [2](#0-1) .
2. `verify_signature` resolves `Shipit.github(organization: repository_owner)` from `params.dig('repository','owner','login')` and checks the HMAC signature against that organization's configured `webhook_secret` [1](#0-0) [3](#0-2) . This proves only "the sender knows organization X's shared App webhook secret" - it says nothing about which specific repo under X the status refers to.
3. `StatusHandler#process` ignores `repository_name`/`stacks` entirely and does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [4](#0-3) . Contrast with `CheckSuiteHandler`, which correctly resolves through `stacks.where(branch: ...)` derived from `repository_name` before touching commits [5](#0-4) . The base `Handler` class even provides this exact scoping helper (`stacks`, built from `Repository.from_github_repo_name(repository_name)`) [6](#0-5) , but `StatusHandler` doesn't use it.
4. `create_status_from_github!` writes a `Status` row tied to `stack_id` taken from the commit itself (`add_status { statuses.replicate_from_github!(stack_id, github_status) }`) [7](#0-6) , so the write always lands on the victim commit's real stack regardless of which repository the webhook was actually for.
5. `Status::Common#blocking?` is `!success? && commit.blocking_statuses.include?(context)` [8](#0-7) . Once state flips to `success`, the commit stops being `blocking?`.
6. `Commit#blocked?` re-evaluates `stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)` [9](#0-8) , so later commits' `blocked?` flips to `false`, and `deployable?` (`!locked? && (stack.ignore_ci? || (success? && !blocked?))`) flips to `true` [10](#0-9) , enabling continuous delivery to ship the later commit.

Attacker request: from a repository they legitimately own/control under the same GitHub App organization installation (or any organization whose `webhook_secret` is `nil`/blank, since `verify_webhook_signature` returns `true` unconditionally when no secret is configured [11](#0-10) ), the attacker triggers (or directly calls) GitHub's Create Commit Status API with `sha` set to the victim's known, public blocking-commit SHA and `state: success`. GitHub's status API does not require the SHA to belong to the calling repository, so this webhook is delivered, correctly signed, and passes `verify_signature`. `Commit.where(sha:)` then matches the victim's row in a different stack and applies the attacker-controlled `success` state to it.

Existing guards that fail to stop this: `verify_signature` (validates sender/org, not per-repo binding), `drop_unhandled_event` (status events are handled), the `ExplicitParameters` schema on `StatusHandler` (only requires `sha`/`state`, never validates/authorizes `repository`) [12](#0-11) . No model-level validation enforces SHA uniqueness across stacks in `Commit` [13](#0-12) , so nothing prevents the cross-stack write once the code fails to scope the query.

### Impact Explanation
An attacker who legitimately controls any single repository sharing the same GitHub App/org webhook configuration as a victim stack (or targets an org with no `webhook_secret` configured) can force a `success` status onto an arbitrary victim commit purely by knowing its public SHA. This directly unblocks `Commit#blocked?`/`deployable?` chains in a stack the attacker has no relationship to, enabling `Stack#trigger_continuous_delivery` to ship a commit the victim never intended to release - "a payload for one repository mutating another's stack/commit," matching the Critical category (unauthorized deploy). The attack is repeatable against any commit in any stack for which the attacker can produce a validly-signed webhook, and is not limited to a single victim - blast radius spans every stack sharing that GitHub App/org config.

### Likelihood Explanation
Preconditions: victim stack has `blocking_statuses` configured with an earlier undeployed commit currently `blocking?` [9](#0-8) ; attacker needs only a repository under the same GitHub App installation/org (a very common Shipit deployment where one App/org secret covers many repos) or an org whose `webhook_secret` is unset. Attacker cost is low: know the victim's public commit SHA (visible on GitHub) and trigger/emit one status webhook. No Shipit credentials, sessions, or GitHub tokens for the victim repo are required. This is feasible and repeatable per victim commit.

### Recommendation
In `StatusHandler#process`, scope commit lookup through the verified repository, mirroring `CheckSuiteHandler`: resolve `stacks` from `repository_name` (payload `repository.full_name`) and only update commits within `stack.commits.where(sha: params.sha)` for those stacks, rejecting/ignoring statuses whose payload repository does not own the commit. Additionally, consider enforcing signature verification/authorization at the level of the specific repository rather than solely at the organization level where multiple repositories share one secret.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb
test ":status webhook for one repository must not update a commit belonging to a different stack" do
  victim_stack = shipit_stacks(:shipit) # repo victim/repo
  attacker_repo_stack = Shipit::Stack.create!(repository: Shipit::Repository.create!(owner: 'attacker', name: 'repo'), environment: 'production')

  blocking_commit = victim_stack.commits.create!(sha: 'a' * 40, message: 'blocking')
  victim_stack.update!(cached_deploy_spec: DeploySpec.new('ci' => { 'blocking' => ['ci/important'] }))
  blocking_commit.statuses.create!(stack: victim_stack, state: 'pending', context: 'ci/important')

  later_commit = victim_stack.commits.create!(sha: 'b' * 40, message: 'later')
  later_commit.statuses.create!(stack: victim_stack, state: 'success', context: 'ci/important')

  assert_predicate blocking_commit, :blocking?
  refute_predicate later_commit, :deployable? # blocked before attack

  # Attacker sends a status webhook whose "repository" is their own, but "sha" equals the victim's blocking commit sha
  request.headers['X-Github-Event'] = 'status'
  GithubHook.any_instance.stubs(:verify_signature).returns(true) # simulates attacker's own valid signature for attacker_repo_stack's org

  body = {
    'sha' => blocking_commit.sha,
    'state' => 'success',
    'context' => 'ci/important',
    'repository' => { 'full_name' => 'attacker/repo', 'owner' => { 'login' => 'attacker' } }
  }.to_json

  post :create, body:, as: :json

  blocking_commit.reload
  later_commit.reload

  refute_predicate blocking_commit, :blocking?          # flipped by attacker's cross-repo webhook
  assert_predicate later_commit, :deployable?           # victim stack incorrectly unblocked
end
```
Both sides of the binding to assert explicitly: `payload['repository']['full_name'] == 'attacker/repo'` while `blocking_commit.stack.repository.full_name == 'victim/repo'` - they differ, yet the status write and resulting `deployable?` flip still occur, proving the missing repository check.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
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

**File:** app/models/shipit/commit.rb (L1-30)
```ruby
# frozen_string_literal: true

module Shipit
  class Commit < Record
    include DeferredTouch

    RECENT_COMMIT_THRESHOLD = 10.seconds

    AmbiguousRevision = Class.new(StandardError)

    belongs_to :stack
    has_many :statuses, -> { order(created_at: :desc) }, dependent: :destroy, inverse_of: :commit
    has_many :check_runs, -> { order(created_at: :desc) }, dependent: :destroy, inverse_of: :commit
    has_many :commit_deployments, dependent: :destroy
    has_many :release_statuses, dependent: :destroy
    belongs_to :merge_request, inverse_of: :merge_commit, optional: true

    deferred_touch stack: :updated_at

    before_create :identify_merge_request
    after_commit { broadcast_update }
    after_create { stack.update_undeployed_commits_count }

    after_commit :schedule_refresh_statuses!, :schedule_refresh_check_runs!, :schedule_fetch_stats!,
                 :schedule_continuous_delivery, on: :create

    belongs_to :author, class_name: 'User', optional: true, inverse_of: :authored_commits
    belongs_to :committer, class_name: 'User', optional: true, inverse_of: :commits
    belongs_to :lock_author, class_name: 'User', optional: true, inverse_of: false

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

**File:** app/models/shipit/status/common.rb (L46-48)
```ruby
      def blocking?
        !success? && commit.blocking_statuses.include?(context)
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
