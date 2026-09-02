### Title
Cross-repository status forgery via unscoped SHA lookup in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves the target `Commit` records purely by `Commit.where(sha: params.sha)`, with no constraint on the repository that the (correctly-signed) webhook payload actually belongs to. Any GitHub org that can send a valid `status` webhook (e.g. for their own repo) can therefore flip the CI status of a commit with the same SHA sitting in a completely unrelated victim stack, causing `MergeRequest#all_status_checks_passed?` to report success without the victim's CI ever running.

### Finding Description
The broken binding, stated explicitly: the equality that should hold is `payload.repository.full_name == commit.stack.repository.full_name` for every `Commit` mutated by the handler, but the code never checks it.

`StatusHandler#process` is:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [1](#0-0) 

`Commit.where(sha: ...)` queries the global `commits` table with no `stack_id`/`repository` filter, unlike `MergeRequest#find_or_create_commit_from_github_by_sha!`, which correctly scopes lookups through `stack.commits.by_sha(sha)` [2](#0-1) . Because commit SHAs are content-addressed (tree+parents+metadata), two independent repositories can produce commits with an identical SHA (e.g., an attacker rebasing/cherry-picking to reproduce the victim's tree, or simply colliding through an empty/trivial commit reused across forks). The webhook signature (`GitHubApp#verify_webhook_signature`) only authenticates that the payload was sent by the org named inside the payload itself (the attacker's own org) — it says nothing about which `Commit` rows in Shipit's database the handler is allowed to touch. Once inside `process`, the handler blindly applies the attacker's `state: success` status to every `Commit` row across every stack whose `sha` column matches, including the victim's queued `MergeRequest#head` commit.

`Commit#create_status_from_github!` → `add_status` recomputes `Commit#status`/`deployable?` and triggers `stack.schedule_merges` when the new status is `success` [3](#0-2) . `MergeRequest#all_status_checks_passed?` then evaluates `StatusChecker.new(head, head.statuses_and_check_runs, ...).success?` against exactly the poisoned status row [4](#0-3) , and `ProcessMergeRequestsJob`/merge-queue processing consumes that result to proceed with the merge queue as if the victim's own CI had passed.

None of the existing guards catch this: `verify_signature`/`verify_webhook_signature` only prove the payload's *authenticity for the sender's own org*, not that the `sha` belongs to that org's repositories; the `params` schema (`requires :sha, String`) only validates shape, not ownership; `drop_unhandled_event`, `ExplicitParameters`, `force_github_authentication`, and model validations on `Repository`/`Stack` are irrelevant to this write path since it never inspects `params.repository` at all before the `Commit.where(sha:)` lookup.

### Impact Explanation
An attacker who controls any GitHub repository can, per request, write a fabricated `success` (or `failure`) `Status` row onto any `Commit` record in the Shipit database that happens to share a SHA with one of their own commits, across tenant/repository boundaries. This lets them force a queued `MergeRequest` in a victim stack to be treated as CI-green (`all_status_checks_passed? == true`), letting `ProcessMergeRequestsJob`/merge-queue logic proceed to merge/deploy code that never passed the victim's own CI — a payload for one repository mutating another's commit/stack state, matching the Critical category ("a payload for one repository mutating another's stack, commit, task or team... an unauthorized deploy, rollback or merge"). The same primitive also lets an attacker mark a victim's commit as `failure`/`error` to grief/block their merge queue. This is repeatable against any repository configured in the shared Shipit instance and requires no privileges beyond controlling a GitHub repo that can emit a signed status webhook for a colliding SHA.

### Likelihood Explanation
Preconditions are non-trivial but realistic: the victim stack must have a queued `MergeRequest` whose `head` commit SHA is reproducible by the attacker. Because git commit SHAs are deterministic hashes over tree + parent + author/committer metadata + timestamps, an attacker who can observe the victim's public PR (branch name, commit message, tree, parent, and author/committer timestamps — all visible on GitHub) can, in principle, reconstruct an identical commit object in their own repo and obtain the exact same SHA, then have their own status webhook fire for it. This requires attacker effort to engineer a SHA collision (not a hash break, but a metadata reproduction), and is easiest against forks/rebases of public branches rather than truly independent code. This is squarely a defense-in-depth failure: regardless of how hard SHA reproduction is, the code should never allow status webhooks to affect commits outside the authenticated repository.

### Recommendation
Scope the `Commit` lookup in `StatusHandler#process` (and analogous handlers) to the repository named in the verified webhook payload, e.g. join through `Stack`/`Repository` and filter `Commit.joins(stack: :repository).where(sha: params.sha, shipit_repositories: { name: params.repository.name, owner: params.repository.owner })` (or equivalent using the `repository` context already available on `Webhooks::Handlers::Handler`), so a commit is only updated when its owning stack's repository matches the authenticated payload's repository.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb (new test)
test "status webhook for attacker repo cannot flip CI state of a same-sha commit in a victim stack" do
  victim_stack = shipit_stacks(:shipit)
  attacker_stack = shipit_stacks(:cyclimse) # a different repository/stack fixture

  shared_sha = "a" * 40
  victim_commit = victim_stack.commits.create!(sha: shared_sha, message: "victim work", author: shipit_users(:bob))
  merge_request = victim_stack.merge_requests.create!(number: 42, head: victim_commit, merge_status: 'pending')

  attacker_commit = attacker_stack.commits.create!(sha: shared_sha, message: "attacker work", author: shipit_users(:bob))

  # Sanity: binding should hold before the attack
  assert_not_equal victim_stack.repository.full_name, attacker_stack.repository.full_name
  assert_not merge_request.reload.all_status_checks_passed?

  payload = {
    sha: shared_sha,
    state: 'success',
    context: 'ci/attacker',
    repository: { full_name: attacker_stack.repository.full_name } # signed & valid for attacker org
  }

  Shipit::Webhooks::Handlers::StatusHandler.new(payload:, delivery_id: SecureRandom.uuid).call

  # Broken binding: attacker's payload flips the victim's unrelated commit/merge_request
  assert merge_request.reload.all_status_checks_passed?,
    "victim MergeRequest should NOT be affected by attacker's own repo webhook"
end
```
This demonstrates that `payload.repository.full_name` (attacker's) diverges from `victim_commit.stack.repository.full_name` yet still mutates the victim's `Commit#status` and flips `MergeRequest#all_status_checks_passed?`, confirming the missing repository-scoping check in `StatusHandler#process`.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/merge_request.rb (L193-197)
```ruby
    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end
```

**File:** app/models/shipit/merge_request.rb (L303-309)
```ruby
    def find_or_create_commit_from_github_by_sha!(sha, attributes)
      if commit = stack.commits.by_sha(sha)
        commit
      else
        github_commit = stack.github_api.commit(stack.github_repo_name, sha)
        stack.commits.create_from_github!(github_commit, attributes)
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
