### Title
Cross-repository `status` webhook writes to any stack's `Commit` via unscoped `sha` lookup - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves target commits with `Commit.where(sha: params.sha)`, with no scoping to the repository named in the webhook payload, unlike its sibling handlers. Any legitimately signed `status` webhook for a repository R1 the attacker owns can flip `Commit#status` (and trigger `Stack#schedule_merges`) on every other stack in the installation that happens to have a commit row with the same `sha`, which is realistic under shared git history (forks/cherry-picks) or a deliberately reproduced commit object.

### Finding Description
Binding claimed: `stack` passed to `Hook.emit`/`schedule_merges` inside `Commit#add_status` == the stack named in `payload['repository']['full_name']`.

Traced code:
- `WebhooksController#verify_signature` (app/controllers/shipit/webhooks_controller.rb:24-49) verifies the signature using `Shipit.github(organization: repository_owner)`, where `repository_owner` is read from the payload (`params.dig('repository','owner','login')`). This only proves the request came from GitHub for *some* org/repo the attacker legitimately controls (R1) — it never ties the payload to any particular Shipit stack.
- `Handler#stacks` (app/models/shipit/webhooks/handlers/handler.rb:32-38) is the standard scoping mechanism: `Repository.from_github_repo_name(repository_name)&.stacks`, built from `payload.dig('repository','full_name')`. `PushHandler` (app/models/shipit/webhooks/handlers/push_handler.rb:13-16) and `CheckSuiteHandler` (app/models/shipit/webhooks/handlers/check_suite_handler.rb:14-16) both use `stacks.where(...)`, correctly binding the effect to the payload's own repository.
- `StatusHandler#process` (app/models/shipit/webhooks/handlers/status_handler.rb:20-24) does **not** use `stacks` at all:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
This queries `Commit` globally by `sha`, with no `stack_id`/repository filter. The schema only enforces uniqueness of `sha` per `(stack_id, sha)` (`db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb`), confirming the same `sha` value is expected/allowed to exist across multiple unrelated stacks.
- `Commit#create_status_from_github!` → `add_status` (app/models/shipit/commit.rb:165-169, 366-386) calls `stack.schedule_merges if new_status.pending? || new_status.success?`, where `stack` is `commit.stack` — the stack owning the matched `Commit` row, not any stack derived from the webhook's repository field.

Exploit flow: attacker owns R1, whose Shipit stack has an empty `blocking_statuses`/`required_statuses` deploy_spec (irrelevant to this handler but establishes the attacker's own stack is trivially manipulable). The attacker gets a commit into R1 whose git SHA1 collides with a `Commit#sha` already present in victim stack S2 — achievable when R1 shares git history with S2 (a fork, or a repo seeded from the same upstream so common ancestor commits share SHAs) or by reconstructing an identical commit object (same tree, parents, author/committer metadata, message) if that metadata is known/public. The attacker then causes a `status` event to be emitted for that SHA on R1 (e.g., via their own CI, a GitHub Action, or the Statuses API on a repo they control) — this is signed correctly by GitHub for R1 and passes `verify_signature`. `StatusHandler` matches **all** `Commit` rows with that SHA, including S2's, and calls `add_status` on S2's commit, which can flip `new_status.pending?`/`success?` and invoke `stack.schedule_merges` for S2 — an unrelated, victim stack the attacker has no authorization over.

Existing guards do not stop this: `verify_signature` authenticates only the source organization/repo of the webhook, not which Shipit stacks the payload is allowed to affect; the `ExplicitParameters` schema on `StatusHandler` validates types only, not repository scope; and there is no `stacks`/repository filter anywhere in `StatusHandler#process`.

### Impact Explanation
A payload authenticated for repository R1 causes a database write (`Status` create) and a merge-queue side effect (`Stack#schedule_merges` → `MergeRequest.schedule_merges`/`ProcessMergeRequestsJob`) on victim stack S2, which never authenticated or authorized that payload. This is a payload-for-one-repository-mutating-another's-stack/commit scenario, matching the Critical category ("a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy, rollback or merge"). It is repeatable against any stack whose commits share a SHA with a commit the attacker can produce/control, and the blast radius spans every tenant stack in the same Shipit installation, not just one victim. [1](#0-0) [2](#0-1) 

### Likelihood Explanation
Preconditions: the attacker needs (a) control of a repository (R1) with a Shipit-connected stack (trivial — the attacker owns R1), and (b) a commit SHA that collides with a `Commit` row belonging to victim stack S2. Exact SHA collisions require identical commit content (tree, parents, author/committer, timestamp, message); this is realistic in shared-history scenarios (forks of the same upstream, common ancestor commits, cherry-picked/rebased commits with preserved metadata across CI pipelines) rather than a brute-force hash collision. Given fork-based OSS workflows are common, this is a practical, low-cost attack requiring no secrets, no Shipit session, and no special privileges beyond ordinary GitHub repository ownership. It is fully repeatable — the attacker can flip statuses/pending/success repeatedly on any stack sharing SHAs with their own repo.

### Recommendation
Scope `StatusHandler#process` to the payload's own repository, matching the pattern used by `PushHandler`/`CheckSuiteHandler`: resolve `stacks` via `Repository.from_github_repo_name(repository_name)` first, then query `Commit.where(sha: params.sha, stack_id: stacks.select(:id))` (or iterate `stacks.each { |stack| stack.commits.where(sha: params.sha).each { ... } }`) instead of the global `Commit.where(sha: params.sha)`.

### Proof of Concept
Minitest under `test/controllers/webhooks_controller_test.rb` or `test/models/shipit/webhooks/handlers_test.rb`:
1. Create two stacks: `stack_r1` (repository `attacker/r1`) and `stack_s2` (repository `victim/s2`), each with a `Commit` row sharing the identical `sha` value (simulating shared git history).
2. Stub/allow `GithubHook`/`verify_signature` to pass for `attacker/r1` (as done in existing tests via `GithubHook.any_instance.stubs(:verify_signature).returns(true)`).
3. POST a `status` webhook whose JSON body sets `repository.full_name` = `"attacker/r1"` and `sha` = the shared sha, `state` = `"success"`.
4. Assert on both sides of the binding:
   - `assert_equal "attacker/r1", payload['repository']['full_name']` (payload-declared repo).
   - `assert_not_equal stack_s2, stack_r1` and `assert_includes Commit.where(sha: shared_sha).map(&:stack), stack_s2` (S2 is matched despite payload naming R1).
   - `stack_s2.expects(:schedule_merges)` (or `assert_enqueued_with(job: ProcessMergeRequestsJob, args: [stack_s2])`) fired as a direct result of the R1-tagged payload, proving `Stack#schedule_merges` executes for S2 even though the authenticated payload only names R1. [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-28)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class StatusHandler < Handler
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

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
      end
    end
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb (L1-10)
```ruby
class IndexCommitsOnStackIdAndSha < ActiveRecord::Migration[5.1]
  def change
    add_index :commits, %i(sha stack_id), unique: true
  end
end
```
