### Title
StatusHandler resolves GitHub status webhooks by global commit sha, not by the webhook's authenticated repository, allowing cross-tenant CI status forgery - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits to attach a forged CI status to via `Commit.where(sha: params.sha)` across the *entire* `commits` table, with no scoping to the repository/organization whose webhook signature was actually verified. Because Git commit shas are content-addressed and often identical or predictable across forks/mirrors, and because Shipit resolves the webhook's HMAC secret using the attacker-controlled `repository.owner.login` field in the payload body, an attacker who only owns an unrelated repository (org B) can forge a `status` event carrying a sha belonging to a commit in a completely different stack (org A) and flip that commit's blocking CI state.

### Finding Description
The broken binding: **the entity that resolved a blocking CI signal for stack A's repository (`commit.stack`, derived solely from `Commit.where(sha: params.sha)`) == the entity Shipit authenticated the webhook for (`Shipit.github(organization: repository_owner)` in `WebhooksController#verify_signature`, using `params.dig('repository','owner','login')` from the same forged payload)**. These are supposed to be the same tenant; they are not enforced to be.

Code path:
- `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) picks the GitHub App/webhook secret via `repository_owner`, which is read straight from the attacker-supplied JSON body (`params.dig('repository', 'owner', 'login')`, line 61). An attacker who owns org B's repo can send a payload where `repository.owner.login == "org-B"` and sign it with org B's real webhook secret (which they legitimately receive as the repo owner) — signature verification passes. [1](#0-0) [2](#0-1) 
- Other handlers correctly scope work to the authenticated repository via `Handler#stacks`, which resolves `Repository.from_github_repo_name(repository_name)` off the same payload's `repository.full_name` (e.g. `CheckSuiteHandler` at `app/models/shipit/webhooks/handlers/check_suite_handler.rb:14-16` does `stacks.where(branch: ...)`). [3](#0-2) [4](#0-3) 
- `StatusHandler#process`, however, ignores `stacks`/`repository_name` entirely and instead does a global lookup: [5](#0-4) 
  This matches **every** `Commit` row in the database with that sha, across every stack/repository/tenant, and calls `commit.create_status_from_github!(params)` on each, which writes the status using `commit`'s own `stack_id` (`app/models/shipit/commit.rb:165-169`), not the org/repo that was authenticated. [6](#0-5) 

Downstream effect: `Status::Common#blocking?` is `!success? && commit.blocking_statuses.include?(context)` (`app/models/shipit/status/common.rb:46-48`), and `Commit#blocked?` gates later commits on `stack.commits.reachable.newer_than(...).older_than(self).any?(&:blocking?)` (`app/models/shipit/commit.rb:231-237`). By forging a `state: 'success'` status with the correct `context` for a sha shared with stack A's blocking commit, the attacker flips `blocking?` to `false` for that commit, unblocking `deployable?`/`blocked?` computations and the deploy queue for stack A — despite never being authenticated by Shipit for stack A's org/repo and never touching org A's `webhook_secret`. [7](#0-6) [8](#0-7) 

Existing guards don't catch this: `verify_signature` only proves the payload was signed by *some* org's secret (the one named in the payload itself), not that the sha or repo referenced belongs to that org; `ExplicitParameters` schema (`params do requires :sha ... end`) validates types only, not repository ownership; there is no `Repository`/`Stack` membership check in `StatusHandler` at all.

### Impact Explanation
An attacker who controls any GitHub repository (fork or otherwise) that is registered with a Shipit organization can, with zero privileges on the victim's stack, mint arbitrary CI statuses (including `success`) for any commit sha that happens to exist in another tenant's `commits` table. If shas collide across repos (mirrors/forks share identical commit shas, or an attacker can read a public target repo's commit shas and the corresponding blocking-CI context name), this becomes a cross-tenant CI-status forgery that clears `blocked?` gating and enables an unauthorized deploy of stack A's queued commits — "a payload for one repository mutating another's stack/commit" and "an unauthorized deploy," matching the Critical severity bucket. The blast radius is any stack whose commit sha appears anywhere else in the shared `commits` table (which is not partitioned per tenant at the database level for this lookup), and is repeatable per sha/context pair.

### Likelihood Explanation
Preconditions: stack A must configure `ci.blocking` (matching the question's "soc_second"-style fixture where a later commit is held back solely by an earlier blocking commit), and the attacker needs (a) their own repository registered as a Shipit-tracked repo under some org B (trivial — they just need a webhook delivered from a repo they control, or any internet endpoint if they can compute a valid HMAC — but realistically they need to be the maintainer of a linked repo, which per the threat model is an "unprivileged" actor who can push/open PRs on their own fork), and (b) knowledge of a target sha + blocking context name, obtainable from public commit history/CI config. No Shipit secrets, sessions, or API tokens are required — only the ability to produce a validly-signed webhook for their own org. This is directly reachable via `POST /webhooks` with `X-Github-Event: status`.

### Recommendation
Scope `StatusHandler#process` to the repository that was actually authenticated for the webhook, mirroring `CheckSuiteHandler`: resolve candidate commits via `stacks.flat_map { |stack| stack.commits.where(sha: params.sha) }` (using the inherited `stacks` method, which is derived from `repository_name`/`Repository.from_github_repo_name`) instead of the unscoped `Commit.where(sha: params.sha)`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
require 'test_helper'

module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerTest < ActiveSupport::TestCase
        test "does not update a commit belonging to a different repository/stack" do
          stack_a = shipit_stacks(:shipit)          # org A's stack
          blocking_commit = shipit_commits(:soc_second) # belongs to stack_a, currently blocking
          gated_commit = shipit_commits(:soc_third)      # gated solely by blocking_commit

          assert_predicate blocking_commit, :blocking?
          refute_predicate gated_commit, :deployable?

          # Forge a payload whose repository/org is unrelated to stack_a (org B),
          # but whose sha matches stack_a's blocking commit.
          forged_payload = {
            'sha' => blocking_commit.sha,
            'state' => 'success',
            'context' => blocking_commit.statuses.last.context,
            'branches' => [{ 'name' => 'master' }],
            'repository' => { 'full_name' => 'attacker-org/unrelated-repo',
                               'owner' => { 'login' => 'attacker-org' } }
          }

          before_stack_a_next = stack_a.next_commit_to_deploy

          StatusHandler.call(forged_payload)

          blocking_commit.reload
          gated_commit.reload
          after_stack_a_next = stack_a.reload.next_commit_to_deploy

          # BROKEN BINDING: an entity never authenticated for stack_a's repo
          # (attacker-org) was still able to resolve stack_a's blocking status.
          refute_predicate blocking_commit, :blocking?, "status forged via unrelated org unblocked stack A's commit"
          assert_equal before_stack_a_next, after_stack_a_next, "expected no change without a properly scoped webhook for org A"
        end
      end
    end
  end
end
```
This test asserts both sides of the equality (`commit.stack` vs. the authenticated repository) diverge under current code: the forged webhook — signed and scoped only for `attacker-org` — still succeeds in clearing `blocking_commit.blocking?` for stack A and changes `stack_a.next_commit_to_deploy`, with the final `assert_equal` expected to fail against current `StatusHandler` code, proving the vulnerability.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
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
