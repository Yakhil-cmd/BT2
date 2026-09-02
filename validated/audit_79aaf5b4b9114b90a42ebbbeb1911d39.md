### Title
Unscoped SHA lookup in `StatusHandler#process` lets any authenticated repository forge CI status on another repository's commit - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves the target `Commit` purely by `params.sha`, with no join or check against the repository that authenticated the incoming webhook. Any account controlling a repository already registered with Shipit (and thus able to sign a valid `status` webhook with its own GitHub App/organization secret) can post an arbitrary `sha`/`context`/`state`, and if that literal SHA string matches a `Commit` row belonging to a completely different stack/repository, that victim commit receives the forged status - triggering `stack.schedule_merges` and downstream deploy/merge/block decisions.

### Finding Description
The broken binding is: `commit.stack.repository == webhook.repository` should hold for every `Status` created from a `status` webhook, but the code never establishes or checks this equality.

- `WebhooksController#verify_signature` only proves the request was signed by *some* org (`repository_owner` from `params.dig('repository','owner','login')`) known to Shipit; it does not bind the payload's `sha` to that org's repositories. [1](#0-0) 
- `StatusHandler`'s `ExplicitParameters` schema requires only `sha`, `state`, and optional `description`/`target_url`/`context`/`created_at`/`branches` - it never requires or reads `repository.full_name`. [2](#0-1) 
- `process` then does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`, matching every `Commit` row across the entire installation that happens to share that literal SHA string, regardless of which stack/repository it belongs to. [3](#0-2) 
- `Commit#create_status_from_github!` writes the status using the *commit's own* `stack_id` (not the attacker's), via `statuses.replicate_from_github!(stack_id, github_status)` inside `add_status`. [4](#0-3) 
- `add_status` then reacts to the new status: it emits `deployable_status`/`commit_status` hooks and calls `stack.schedule_merges if new_status.pending? || new_status.success?`, i.e. it can trigger merge/deploy processing on the **victim's** stack. [5](#0-4) 

Exploit flow: The attacker owns/administers a repository already onboarded to the same Shipit instance (a legitimate, low-privilege capability - they only need their own valid webhook secret, not the victim's). They learn (or already know, since commit SHAs are frequently public) the SHA of a commit tracked by the victim's stack. They POST to `/webhooks` with header `X-Github-Event: status`, body `{"sha": "<victim-sha>", "state": "success", "context": "ci/kubernetes", "repository": {"owner": {"login": "<attacker-org>"}}}`, signed with the attacker's own organization's webhook secret. `verify_signature` passes because it only checks that *an* org's secret matches - it never checks that the `sha` actually belongs to that org's repo. `StatusHandler#process` then finds the victim's `Commit` (matched purely by SHA text) and writes the forged status onto it under the victim's `stack_id`, potentially unblocking a required `ci/kubernetes` check and causing `schedule_merges`/deploy eligibility to fire.

Existing guards do not stop this: `verify_signature` authenticates the *sender org*, not the *sha ownership*; the `ExplicitParameters` schema for `StatusHandler` has no repository field to validate against; there is no `Repository`/`Stack` scoping join in the `Commit.where(sha:)` query. The `review_stacks_enabled`/provisioning-precedence angle raised in the question (a real, separate Ruby operator-precedence bug in `provision?` in `opened_handler.rb`/`reopened_handler.rb`, where `review_stacks_enabled && allow_all? || (allow_with_label? && has_label?) || ...` lets `allow_with_label`/`prevent_with_label` behaviors provision even when `review_stacks_enabled` is `false`) is not required to trigger this vulnerability - regular, non-review stacks are equally exposed, since the SHA-lookup scoping defect in `StatusHandler` is independent of provisioning state.

### Impact Explanation
A successful request writes a `Shipit::Status` record for a repository/stack that never authenticated the webhook, and can flip the effective CI state (`ci/kubernetes` or any required context) of a victim's commit from failing/unknown to `success`, or vice versa to `failure`/blocked. Because `add_status` calls `stack.schedule_merges` on success/pending transitions, this can unblock an otherwise-gated merge or deploy on the victim stack - an unauthorized state change crossing tenant boundaries ("a payload for one repository mutating another's stack/commit"). This is repeatable against any commit SHA the attacker can discover, across arbitrarily many victim stacks/repositories hosted on the same Shipit instance, matching the Critical impact category (cross-tenant mutation / unauthorized deploy-path trigger).

### Likelihood Explanation
Preconditions: the attacker needs a repository/org already registered with Shipit with its own valid webhook secret (a legitimate, unprivileged onboarding action, not a victim secret), and knowledge of a target commit SHA in the victim's stack (trivially available for public repos, or otherwise discoverable). No GitHub App private key, no `webhook_secret` of the victim, no session, and no API token are required. The attacker can repeat this at will for any known SHA, making it low-cost and highly feasible whenever multi-tenant repositories share a Shipit deployment.

### Recommendation
Scope `StatusHandler#process` (and the `Commit.where(sha:)` lookup) to commits belonging to stacks/repositories whose `full_name` matches the webhook's authenticated `repository.full_name`/`repository_owner`. Require and validate the `repository` field in `StatusHandler`'s `ExplicitParameters` schema and join through `Stack`/`Repository` when resolving commits, e.g. `Commit.joins(stack: :repository).where(sha: params.sha, shipit_repositories: { full_name: params.repository.full_name })`. Separately, fix the operator-precedence bug in `provision?` in `opened_handler.rb`/`reopened_handler.rb` by parenthesizing `(repository.review_stacks_enabled && repository.provisioning_behavior_allow_all?) || ...` and ensure `review_stacks_enabled` gates all three provisioning behaviors, not only `allow_all`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
require 'test_helper'

module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerTest < ActiveSupport::TestCase
        test "a status shared SHA leaks across unrelated stacks/repositories" do
          attacker_repo = shipit_repositories(:shipit) # attacker-controlled, legitimately onboarded
          victim_stack = Shipit::Stack.create!(
            repository: Shipit::Repository.create!(name: 'victim-app', owner: 'victim-org'),
            environment: 'production'
          )
          shared_sha = 'deadbeef' * 5
          victim_commit = victim_stack.commits.create!(
            sha: shared_sha, author: shipit_users(:walrus), committer: shipit_users(:walrus),
            authored_at: Time.now, committed_at: Time.now
          )

          # Binding under test: commit.stack.repository == webhook repository
          assert_not_equal attacker_repo, victim_stack.repository

          params = ActionController::Parameters.new(
            sha: shared_sha, state: 'success', context: 'ci/kubernetes'
          )
          StatusHandler.new(params).process

          # If the invariant held, victim_commit should NOT receive a status from this webhook
          assert_equal 0, victim_commit.statuses.count,
            "expected no cross-repository status write, but victim commit was mutated"
        end
      end
    end
  end
end
```
This test seeds a `victim_stack`/`Commit` unrelated to the calling handler's authenticated repository, invokes `StatusHandler#process` with only a shared `sha`, and asserts the victim's `Commit#statuses` remains empty - demonstrating that the current implementation fails this assertion because `Commit.where(sha:)` is unscoped by repository.

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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
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
