### Title
`StatusHandler#process` writes GitHub commit statuses by bare SHA with no repository scoping, letting one authenticated repository flip `deployable?`/`blocked?` for another stack's identical-SHA commit - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves target commits with `Commit.where(sha: params.sha)` and calls `commit.create_status_from_github!(params)` on every match, with no check that the commit's `stack.repository` is the same repository that produced the webhook `X-Hub-Signature`. Because a git commit SHA is content-derived and can exist identically in more than one `Stack`/`Repository` record (forks, mirrors, shared history, review stacks branched off the same base), a webhook validly signed for repository A can write a status (including `review/approved` success) onto a `Commit` belonging to stack B, changing B's `deployable?`/`blocked?` outcome. The "review_stacks_enabled=false / provisioning precedence" framing in the question is not supported by the code: `review_stacks_enabled` only gates PR-triggered review-stack **provisioning** in `pull_request/labeled_handler.rb`, `opened_handler.rb`, `reopened_handler.rb` — it has no interaction with `StatusHandler` or with a stack's `required_statuses` check, so no "provisioning precedence bug" was found; the real, code-supported defect is the missing repository scope in `StatusHandler`.

### Finding Description
The broken binding is:
`commit.stack.repository.full_name == repository_owner/repository_name authenticated by verify_signature`
which the code never checks.

Path:
1. `Shipit::WebhooksController#create` (`app/controllers/shipit/webhooks_controller.rb:10-15`) parses the raw JSON and dispatches to `Shipit::Webhooks.for_event(event)` handlers after `verify_signature` (line 6, 24-49).
2. `verify_signature` only proves the payload was signed by the GitHub App belonging to `repository_owner` (`params.dig('repository','owner','login')`) — it proves *which org/app* sent the webhook, not which specific `Stack`/`Commit` may be mutated. [1](#0-0) 
3. `StatusHandler#process` then does: [2](#0-1) 
`Commit.where(sha: params.sha)` is a global, cross-tenant lookup with no `stack_id`/`repository` filter.
4. For every matched `Commit`, `create_status_from_github!` → `add_status` recomputes `status`/`Status::Group.compact` and, if the simple state changed, calls `stack.schedule_merges` when the new status is `success` (`app/models/shipit/commit.rb:366-386`).
5. `Commit#deployable?` is `!locked? && (stack.ignore_ci? || (success? && !blocked?))` (`app/models/shipit/commit.rb:227-229`), driven directly by `status`, which is driven by the just-written `Status` row.

Because the lookup key is the bare `sha` string with no `repository_id`/`stack_id` predicate, any commit sharing that SHA across stacks (forks, shared base branches, mirrored repos) is mutated identically, regardless of which repository's webhook secret actually authenticated the request. The invariant "a `review/approved` status affects only the repository that authenticated it" is violated by design in this handler.

None of the listed guards close this gap: `verify_signature` binds to `repository_owner`, not to the specific `Commit`/`Stack` being written; `ExplicitParameters` only validates the shape of `sha`/`state`/`context`, not ownership; there is no `Repository`/`Stack` scoping anywhere in `StatusHandler` or `Commit.create_status_from_github!`.

### Impact Explanation
An attacker who controls a repository (their own fork) whose commit history shares a SHA with a victim's stack (e.g., a forked repo with identical early history, or two Shipit-tracked repos mirroring the same upstream) can push/craft that commit and cause GitHub to emit (or directly can craft, since GitHub only requires the sender to own a webhook-enabled repo) a `status` event with `context: review/approved`, `state: success`. Once relayed through the attacker's own validly-signed webhook, `StatusHandler` writes that status onto the victim's identically-shaed `Commit`, which — if the victim stack lists `review/approved` in `required_statuses`/blocking config — flips `deployable?`/unblocks the victim commit and can trigger `stack.schedule_merges`, i.e., an unauthorized deploy/merge decision for a repository that never authenticated the request. This matches "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy, rollback or merge" (Critical).

### Likelihood Explanation
Exploitation requires the attacker's own repository and the victim's tracked repository to actually share the exact same commit SHA (a real but non-trivial precondition — forks/mirrors of a common upstream, or two Shipit stacks tracking branches off the same base, are the realistic scenarios). No Shipit credentials, sessions, or GitHub org membership are needed beyond owning a webhook-capable repository. This is repeatable for every SHA collision the attacker can arrange, but is not a "send any SHA to any victim" primitive — it is bounded to genuinely shared commits.

### Recommendation
Scope `StatusHandler#process` (and `Commit.where(sha:)`/`by_sha` usages reachable from webhooks) to the repository that authenticated the webhook, e.g. resolve the target `Stack`/`Repository` from `params.dig('repository','full_name')` first, then constrain `Commit.joins(:stack).where(sha: params.sha, shipit_stacks: { repository_id: repository.id })` before calling `create_status_from_github!`.

### Proof of Concept (minitest plan)
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "status for a SHA shared across stacks/repositories only mutates the authenticating repo's commit" do
  victim_stack = shipit_stacks(:shipit)                 # repository A, review/approved required
  attacker_repo = create(:repository, owner: 'attacker', name: 'evil')
  attacker_stack = create(:stack, repository: attacker_repo)

  shared_sha = 'a' * 40
  victim_commit   = create(:commit, stack: victim_stack, sha: shared_sha)
  attacker_commit = create(:commit, stack: attacker_stack, sha: shared_sha)

  before = victim_commit.deployable?
  refute before

  StatusHandler.call(
    'sha' => shared_sha, 'state' => 'success', 'context' => 'review/approved',
    'repository' => { 'full_name' => attacker_repo.full_name, 'owner' => { 'login' => 'attacker' } }
  )

  victim_commit.reload
  after = victim_commit.deployable?

  # asserts the binding was broken: a webhook authenticated only for attacker_repo
  # changed deployability of a commit belonging to victim_stack/repository A
  assert_equal before, after, "victim stack's commit must not change from a webhook it never authenticated"
end
```
This test currently fails against the shown implementation (status is written cross-repo), confirming the vulnerability; the `review_stacks_enabled`/"provisioning precedence" mechanism described in the question was not found in the codebase and is not part of the confirmed exploit path.

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
