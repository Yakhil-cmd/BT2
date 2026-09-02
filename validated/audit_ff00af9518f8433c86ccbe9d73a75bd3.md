### Title
Cross-repository status forgery via unscoped `Commit.where(sha:)` lookup lets any org's valid webhook mark a victim's commit `success` and get it auto-selected by `next_commit_to_deploy` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves the target `Commit` purely by `sha`, with no scoping to the repository/stack that the verified webhook signature actually belongs to. An attacker who owns any GitHub repository connected to Shipit can trigger a legitimately-signed `status` webhook from their own org and, as long as the same commit SHA also exists as a row on a victim's stack (e.g. via a fork or shared upstream history), force a `success` `Status` to be attached to the victim's `Commit`. This can make `Commit#deployable?` return true and cause `Stack#next_commit_to_deploy` to select that commit for deployment on the victim's stack.

### Finding Description
The claimed binding is: `org whose webhook_secret verified the request == org owning the Stack whose next_commit_to_deploy is affected`. This is never enforced.

`WebhooksController#verify_signature` only checks that the raw payload is validly signed for the organization named in the payload's own `repository.owner.login` field (`repository_owner`): [1](#0-0) 
That organization is fully attacker-controlled content of the JSON body (as long as the signature matches an org/app installation the attacker legitimately controls, e.g. their own repo/org connected to Shipit). Nothing ties this "verified org" to the commit that will actually be mutated.

`StatusHandler#process` then looks up the target commit(s) globally by `sha`, with no filter on stack, repository, or the verified `repository_owner`: [2](#0-1) 

`Commit#create_status_from_github!` writes the status using the commit's own `stack_id` (the victim's stack), not anything derived from the webhook payload: [3](#0-2) [4](#0-3) 

Exploit flow:
1. Attacker connects their own GitHub repository/org to Shipit (permitted: "emit webhooks from a repository they own"), obtaining a real, Shipit-verified webhook installation for that org.
2. Attacker identifies a commit SHA that is also tracked in a victim's Shipit stack — trivially achievable by forking the victim's repository (git preserves identical commit SHAs across forks) or via any shared upstream history.
3. Attacker sends (or has GitHub send, e.g. by pushing/tagging in their own repo) a `status` webhook whose body sets `sha` to that shared SHA and `state: "success"`, with `repository.owner.login` equal to the attacker's own org.
4. `verify_signature` passes — the signature is genuinely valid for the attacker's own org/app installation.
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, which matches the row belonging to the victim's stack (in addition to/instead of the attacker's own stack), and calls `create_status_from_github!` on it, creating a `success` `Status` scoped to the victim's `stack_id`.
6. If this makes `Commit#deployable?` true (`!locked? && (stack.ignore_ci? || (success? && !blocked?))`) [5](#0-4) , the victim stack's `Stack#next_commit_to_deploy` → `deployable_commits(commits_to_deploy)` → `commits.to_a.reverse.find(&:deployable?)` [6](#0-5) [7](#0-6)  will select that commit, and if `stack.continuous_deployment?` is on, `schedule_continuous_delivery`/`trigger_continuous_delivery` will deploy it [8](#0-7) .

None of the existing guards prevent this: `verify_signature` validates a signature against an org name taken from the same untrusted payload, `drop_unhandled_event` only checks the event type is registered, and the `ExplicitParameters` schema for `StatusHandler` only requires `sha`/`state` types, not that they correspond to a commit under the authenticated org's repository.

### Impact Explanation
A payload authenticated for repository A can write a `Status` record — and therefore flip `deployable?`/`success?` — for a `Commit` belonging to repository B's stack, with no relationship between the two required beyond a coincidentally shared commit SHA (which forking guarantees). This is a "payload for one repository mutating another's commit/stack" scenario matching the Critical impact category (unauthorized deploy selection), because it can drive `next_commit_to_deploy` and subsequently an actual deploy/rollback trigger on a tenant the attacker never authenticated against.

### Likelihood Explanation
Preconditions are attacker-cost-cheap and match the stated unprivileged threat model exactly: own/connect one GitHub repository to Shipit, fork or otherwise obtain a shared-SHA commit with the victim, then send one authentic `status` webhook naming that SHA. No victim secrets, sessions, or elevated GitHub roles are needed. The attack is repeatable against any stack whose repository has ever shared commit history (forks, template repos, monorepo splits) with a repository the attacker controls.

### Recommendation
Scope the `StatusHandler#process` lookup (and any other sha-based handler, e.g. check-suite equivalents) to commits belonging to the repository authenticated by `verify_signature`, e.g. join through `stack.repository` and only update commits where `stack.repository.owner/name` matches the verified `repository_owner`/`repository.full_name` from the payload, instead of a bare `Commit.where(sha: params.sha)`.

### Proof of Concept
```ruby
# test/models/webhooks/handlers/status_handler_test.rb (new)
require 'test_helper'

module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerCrossRepoTest < ActiveSupport::TestCase
        test "a status verified for org A cannot flip deployable? for a commit owned by org B's stack" do
          victim_stack = shipit_stacks(:shipit) # continuous_deployment enabled stack owned by 'shopify' org
          shared_sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
          victim_commit = victim_stack.commits.create!(sha: shared_sha, message: "shared", author: shipit_users(:shipit), committer: shipit_users(:shipit), authored_at: Time.now, committed_at: Time.now)

          # Before: no status, commit not deployable, not selected
          assert_not victim_commit.deployable?
          assert_not_equal victim_commit, victim_stack.reload.next_commit_to_deploy

          # Attacker owns 'cyclimse' org/repo, and has a commit with the SAME sha (e.g. forked history)
          attacker_payload = {
            'sha' => shared_sha,
            'state' => 'success',
            'context' => 'ci/attacker',
            'repository' => { 'owner' => { 'login' => 'cyclimse' }, 'full_name' => 'cyclimse/attacker-repo' }
          }

          # Simulate a genuinely-signed webhook for the attacker's own org
          Shipit::Webhooks::Handlers::StatusHandler.new(attacker_payload).process

          victim_commit.reload
          assert victim_commit.success?
          assert victim_commit.deployable?
          assert_equal victim_commit, victim_stack.reload.next_commit_to_deploy
        end
      end
    end
  end
end
```
This demonstrates `stack.next_commit_to_deploy == commit` only after processing a status payload authenticated for a foreign org (`cyclimse`), and `nil`/different beforehand, with no legitimate `status` webhook ever verified against the victim (`shopify`) org's `webhook_secret`.

### Citations

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

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```

**File:** app/models/shipit/status.rb (L24-33)
```ruby
      def replicate_from_github!(stack_id, github_status)
        find_or_create_by!(
          stack_id:,
          state: github_status.state,
          description: github_status.description,
          target_url: github_status.target_url,
          context: github_status.context,
          created_at: github_status.created_at
        )
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

**File:** app/models/shipit/stack.rb (L645-647)
```ruby
    def deployable_commits(commits)
      commits.to_a.reverse.find(&:deployable?)
    end
```
