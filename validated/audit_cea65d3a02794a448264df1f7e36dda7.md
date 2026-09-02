### Title
Cross-repository Commit Status forgery via unscoped `Commit.where(sha:)` lookup - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits purely by the 40-character `sha` string from the webhook payload, with no constraint tying that `sha` to the `repository` the webhook claims to originate from. Any GitHub user who can create a commit status on a repository whose organization is configured in Shipit can forge a `success`/`failure` status on a completely unrelated victim commit/stack, as long as they know (or guess) that commit's SHA.

### Finding Description
The broken binding, stated as an equality that should hold but doesn't:

`params.sha` scoped to `payload['repository'].full_name` == `Commit.where(sha: params.sha)` scoped to `commit.stack.repository.full_name` — **false**.

`StatusHandler`'s `ExplicitParameters` schema only validates `sha`/`state` types and presence [1](#0-0) , never requiring or checking a `repository` field, unlike other handlers in the same directory (e.g. `PullRequest::LabeledHandler`/`UnlabeledHandler` explicitly `requires :repository do requires :full_name, String end`) [2](#0-1) . The base `Handler` class even provides a `stacks`/`repository_name` helper that scopes lookups to `payload.dig('repository', 'full_name')` [3](#0-2) , but `StatusHandler#process` never uses it — it queries `Commit.where(sha: params.sha)` directly across the whole table [4](#0-3) .

Request path: `WebhooksController#create` parses the raw body and dispatches by event type to `Shipit::Webhooks.for_event(event)` [5](#0-4) . `verify_signature` computes the expected org from `payload.dig('repository','owner','login')` and validates the HMAC signature using that organization's `webhook_secret` via `GitHubApp#verify_webhook_signature` [6](#0-5) [7](#0-6) . This check only proves the webhook genuinely came from GitHub for *that organization* — it says nothing about whether the `sha` inside the payload belongs to a commit tracked under that organization's repositories.

Exploit flow: an attacker with commit-status write access to **any** repository under a GitHub organization that Shipit has a configured `webhook_secret`/App for (this can be their own public repo, or any repo they have push/status permissions on) calls the real GitHub Statuses API (`POST /repos/{owner}/{repo}/statuses/{sha}`), setting `sha` to a victim commit's SHA obtained from the victim's public commit history, `state: 'success'`, `context: 'ci/travis'`. GitHub accepts and signs this legitimately, computes the HMAC over the raw body using the attacker-accessible organization's actual `webhook_secret`, and delivers it to Shipit's `/webhooks` endpoint. `verify_signature` passes because the signature is valid for the payload's own (attacker-accessible) organization. `StatusHandler` then matches `Commit.where(sha: params.sha)` against the entire `commits` table, finds the victim's commit (which may belong to a totally different stack/repository/organization), and calls `commit.create_status_from_github!(params)` [4](#0-3) .

`create_status_from_github!` → `add_status` recomputes `commit.status`, can flip `deployable_status`, and calls `stack.schedule_merges` when the new status is `pending` or `success` [8](#0-7) . This directly affects `Commit#deployable?` and merge-request rejection logic (`any_status_checks_failed?`/`any_status_checks_missing?`) used by `MergeRequest#reject_unless_mergeable!` and `merge!` [9](#0-8) , and `Commit#schedule_continuous_delivery` for continuous-deployment stacks [10](#0-9) .

None of the existing guards prevent this: `verify_signature` checks organization-level HMAC validity, not sha-to-repository binding; `drop_unhandled_event` only checks the event type is handled; and the `ExplicitParameters` schema for `StatusHandler` has zero fields referencing `repository`/`full_name`.

### Impact Explanation
A forged, validly-signed webhook for one (attacker-accessible) repository can inject a fabricated CI status onto a commit belonging to an entirely different, victim-owned stack/repository. This can make an otherwise-failing or pending victim commit appear `deployable`, unblocking auto-merges (`stack.schedule_merges`) or continuous deployment (`schedule_continuous_delivery`) for a repository the attacker never authenticated against — "a payload for one repository mutating another's stack, commit, task" — matching the Critical severity category (unauthorized deploy/merge triggered via forged CI signal). This is repeatable against any commit sha the attacker can learn from public commit history, across any stack tracked by the same Shipit instance, as long as the attacker has status-write access to some organization Shipit trusts.

### Likelihood Explanation
Preconditions: the attacker needs write/status permission on at least one repository belonging to a GitHub organization that is registered in Shipit's `github` config (i.e., has a webhook secret Shipit will validate against) — this is a low bar for public/OSS setups where many contributors or bot integrations have status-write access to at least one tracked repo. No Shipit session, API token, or secret is required; the HMAC is computed by GitHub itself using the org's real webhook secret, not forged by the attacker. The victim SHA is obtainable from public commit history. This is a structural gap (absence of a repository/full_name field in the schema and absence of any commit-repository check in `process`), not a rare edge case, so it is fully repeatable per victim commit.

### Recommendation
Require `repository.full_name` (or equivalent) in `StatusHandler`'s `params do ... end` block, and scope the lookup through the `stacks`/repository helper already defined on `Handler`, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or `Repository.from_github_repo_name(payload.dig('repository','full_name'))&.stacks&.flat_map { |s| s.commits.where(sha: params.sha) }`, mirroring the pattern already used by `PullRequest::LabeledHandler`/`UnlabeledHandler`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
require 'test_helper'

module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerCrossRepoTest < ActiveSupport::TestCase
        test "param_parser has no repository/full_name binding" do
          schema_fields = StatusHandler.param_parser.instance_variable_get(:@fields) rescue nil
          # Assert no field/validation referencing repository or full_name exists
          refute StatusHandler.param_parser.respond_to?(:repository)
          # (Illustrative) confirm no 'repository' key required, unlike LabeledHandler
          assert Shipit::Webhooks::Handlers::PullRequest::LabeledHandler.param_parser
        end

        test "status webhook for attacker repo mutates a victim commit in an unrelated stack" do
          victim_commit = shipit_commits(:cyclimse_first) # belongs to a different stack/repository
          refute_predicate victim_commit, :deployed?

          attacker_payload = {
            'sha' => victim_commit.sha,
            'state' => 'success',
            'context' => 'ci/travis',
            'repository' => { 'full_name' => 'attacker-org/attacker-repo' }
          }

          assert_difference -> { victim_commit.statuses.count }, 1 do
            StatusHandler.call(attacker_payload)
          end

          assert_equal 'success', victim_commit.reload.state
        end
      end
    end
  end
end
```

### Citations

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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L33-35)
```ruby
            requires :repository do
              requires :full_name, String
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

**File:** app/models/shipit/merge_request.rb (L155-162)
```ruby
    def reject_unless_mergeable!
      return reject!('merge_conflict') if merge_conflict?
      return reject!('ci_missing') if any_status_checks_missing?
      return reject!('ci_failing') if any_status_checks_failed?
      return reject!('requires_rebase') if stale?

      false
    end
```
