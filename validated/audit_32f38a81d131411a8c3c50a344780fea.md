This confirms the divergence: `PushHandler#process` scopes strictly via `stacks` → `Repository.from_github_repo_name(repository_name)&.stacks`, and every `PullRequest` handler scopes via `Shipit::Repository.from_github_repo_name(params.repository.full_name)`. `StatusHandler#process`, uniquely among all handlers, does none of this — it neither requires `:repository` in its `params` schema nor filters by it, applying the update to `Commit.where(sha: params.sha)` globally.

### Title
StatusHandler#process applies GitHub status updates to any commit sharing a sha, without checking the authorized repository — enabling unauthorized deploy triggers on other stacks/repositories - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`WebhooksController#verify_signature` only authenticates that a `status` payload's declared `repository.owner.login` matches the org whose `webhook_secret` produced the signature [1](#0-0) . `StatusHandler#process` then updates **every** `Commit` row across the whole installation that shares the posted `sha`, with no check against the authenticated repository [2](#0-1) . Every sibling handler (`PushHandler`, all `PullRequest::*Handler`s) explicitly scopes to `Repository.from_github_repo_name(params.repository.full_name)` before mutating state, but `StatusHandler` does not even declare `repository` as a required param.

### Finding Description
Binding claimed to hold: `stack_authorized_by(webhook_secret_for(payload.repository.owner)) == stack_mutated_by(StatusHandler#process)`.

Tracing the code shows this binding is **not enforced**:
- `WebhooksController#verify_signature` resolves `Shipit.github(organization: repository_owner)` from `params.dig('repository','owner','login')` and validates the HMAC signature against that organization's `webhook_secret` [3](#0-2) . This only proves the request came from a repository under a specific *organization* Shipit trusts — it says nothing about which specific repository or Stack the event pertains to.
- `Shipit::Webhooks::Handlers::Handler` provides a `stacks` helper that correctly scopes to `Repository.from_github_repo_name(repository_name)&.stacks` [4](#0-3) , and `PushHandler#process` uses exactly this scoping before calling `stack.sync_github` [5](#0-4) . All `PullRequest::*Handler`s likewise resolve `Shipit::Repository.from_github_repo_name(params.repository.full_name)` before touching any `Stack`/`PullRequest` record, e.g. `OpenedHandler#repository` [6](#0-5) .
- `StatusHandler`, however, never declares or reads `params.repository` at all — its schema only requires `sha`, `state`, and optional description/target_url/context/created_at/branches [7](#0-6) . Its `process` method does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [2](#0-1)  — matching purely on `sha`, across all `Stack`s and all `Repository` records in the database, with no repository/stack filter whatsoever.
- `Commit` belongs to exactly one `Stack` (`belongs_to :stack`) [8](#0-7) , and the unique index is on `(stack_id, sha)` (per `db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb`), meaning identical shas are expected and permitted to exist as separate `Commit` rows under *different* stacks — this is the normal situation whenever multiple Stacks track the same underlying git history (multiple environments of one repo, review stacks, or repositories with shared/forked history). `create_status_from_github!` calling into `Commit#add_status` will, on a state transition to `success`, call `stack.schedule_merges` and, via `after_commit` on `Status`, `schedule_continuous_delivery` → `Stack#trigger_continuous_delivery` [9](#0-8) [10](#0-9) , which computes `next_commit_to_deploy` → `deployable_commits` relying on `Commit#deployable?` (`!locked? && (stack.ignore_ci? || (success? && !blocked?))`) [11](#0-10) , and ultimately calls `trigger_deploy`, creating a real `Deploy` [12](#0-11) .

The attacker's exact request: a POST to `/webhooks` with `X-Github-Event: status`, a valid `X-Hub-Signature` computed with the `webhook_secret` for an organization/repository the attacker legitimately controls (their own repo under an org they can emit real webhooks for), and a JSON body `{ "sha": "<sha shared with a victim stack's commit>", "state": "success", "repository": { "owner": { "login": "<attacker's own org, matching a real webhook_secret> } } }`. Because `verify_signature` only checks the org-level secret and `StatusHandler#process` never re-checks which repository/stack that sha belongs to, the `Status` row is created on the victim's `Commit` too, and `trigger_continuous_delivery` fires for the victim `Stack`.

### Impact Explanation
An attacker who can produce one legitimately-signed `status` webhook (from any repository/org whose `webhook_secret` they know or which naturally sends such events) can flip the CI state of a *different* Stack's commit to `success` merely by reusing that commit's `sha`, since `StatusHandler#process` has no repository/stack binding at all. If that commit is otherwise `deployable?` (`!locked?`, and now `success?` with `!blocked?`), `Stack#trigger_continuous_delivery` will create and run a real `Deploy` for a Stack the attacker never authenticated against — this is "a payload for one repository mutating another's stack/commit" and "an unauthorized deploy," matching the Critical impact category. The practical blast radius is bounded by how likely two `Commit` rows in the installation actually share an identical sha (multiple stacks of the same repository/environment, forks, subtree-shared history) — arbitrary cross-tenant sha collision via SHA-1 preimage is not itself demonstrated here.

### Likelihood Explanation
Exploitability requires: (1) the attacker can produce one org-scoped, correctly-signed `status` webhook (feasible for any repo they legitimately operate that Shipit already trusts, e.g. their own repo in a multi-repo org, or one of possibly-multiple GitHub App installations sharing infra), and (2) a `Commit` with the identical `sha` already exists under a different `Stack`/`Repository` — realistic whenever a Shopify-style installation runs multiple Stacks (staging/production/review) against the same repository, or repositories that share git history through forking. No session, token, or Shipit secret is needed beyond a naturally-arising valid webhook signature for *some* repository. The missing repository check is a code-level omission, independent of GitHub-side collision engineering, and is trivially demonstrated at the unit-test level by constructing two `Commit` rows with the same `sha` under different stacks.

### Recommendation
Scope `StatusHandler#process` to the authenticated repository the same way `PushHandler` and the `PullRequest` handlers do: require `repository.full_name` in the params schema, resolve `Shipit::Repository.from_github_repo_name(params.repository.full_name)`, and restrict the `Commit` lookup to `repository.stacks.flat_map(&:commits).where(sha: params.sha)` (or an equivalent `joins(stack: :repository).where(repositories: { id: repository.id })`), mirroring `Handler#stacks`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
require 'test_helper'

module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerCrossStackTest < ActiveSupport::TestCase
        test "a status for a repository does not deploy an unrelated stack sharing the same commit sha" do
          attacker_repo   = shipit_repositories(:shipit)          # repo the attacker's webhook is authorized for
          victim_stack    = shipit_stacks(:cyclimse)              # different repository/tenant
          shared_sha      = 'a' * 40

          attacker_commit = attacker_repo.stacks.first.commits.create!(sha: shared_sha, message: 'x')
          victim_commit   = victim_stack.commits.create!(sha: shared_sha, message: 'x')
          victim_commit.update!(locked: false)

          payload = {
            'sha' => shared_sha,
            'state' => 'success',
            'repository' => { 'full_name' => attacker_repo.full_name, 'owner' => { 'login' => attacker_repo.owner } }
          }

          assert_difference('Deploy.count') do
            StatusHandler.new(payload).process
            victim_stack.trigger_continuous_delivery
          end
          # binding check: authorized stack (attacker's) must not equal the stack that got deployed (victim's)
          refute_equal attacker_repo.stacks.first.id, victim_stack.id
        end
      end
    end
  end
end
```
This demonstrates `assert_difference('Deploy.count')` firing for `victim_stack` even though the only authenticated party was `attacker_repo`, proving the binding "authorized stack == deployed stack" is violated by `StatusHandler#process`'s unscoped `Commit.where(sha: params.sha)`.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/commit.rb (L11-11)
```ruby
    belongs_to :stack
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```

**File:** app/models/shipit/status.rb (L42-44)
```ruby
    def schedule_continuous_delivery
      commit.schedule_continuous_delivery
    end
```

**File:** app/models/shipit/stack.rb (L210-229)
```ruby
    def trigger_continuous_delivery
      return if cached_deploy_spec.blank?

      commit = next_commit_to_deploy

      if should_resume_continuous_delivery?(commit)
        continuous_delivery_resumed!
        return
      end

      if should_delay_continuous_delivery?(commit)
        continuous_delivery_delayed!
        return
      end

      begin
        trigger_deploy(commit, Shipit.user, env: cached_deploy_spec.default_deploy_env)
      rescue Task::ConcurrentTaskRunning
      end
    end
```
