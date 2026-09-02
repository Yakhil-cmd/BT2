### Title
Cross-repository commit status forgery via unscoped `Commit.where(sha:)` lookup enables unauthorized merge - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits purely by `sha` with no scoping to the repository/org that sent the webhook, and `MergeRequest#all_status_checks_passed?` trusts whatever status rows exist on the `head` commit. Since the `sha` is attacker-controlled (any git commit's SHA-1 is determined solely by its content, and GitHub's Statuses API does not require the sha to belong to a real commit in the sender's repo), an attacker who reproduces or copies a victim's exact commit content into their own repository, then sets a "success" status there, causes Shipit to record that status against the victim's `MergeRequest#head` commit and can trigger `merge_request.merge!`.

### Finding Description
The claimed binding — "repository/org named in the status payload == the repository/org owning the MergeRequest whose head commit's status is consulted" — is **false**. Nowhere in the reachable code path is this equality checked.

- `StatusHandler`'s param schema only declares `sha`, `state`, `description`, `target_url`, `context`, `created_at`, `branches`; it never requires/reads a `repository` field: [1](#0-0) 
- `process` resolves commits with a bare, cross-tenant SQL lookup and blindly attaches the incoming status to every matching commit: [2](#0-1) 
- `Commit.create_status_from_github!` / `statuses.replicate_from_github!` records the status with no check that `stack.repository` matches any sender identity: [3](#0-2) 
- `MergeRequest#all_status_checks_passed?` simply reads `head.statuses_and_check_runs` and evaluates them via `StatusChecker`, with no re-validation of source: [4](#0-3) 
- `ProcessMergeRequestsJob#perform` calls `merge_request.refresh!` (which re-fetches statuses from the victim's real GitHub repo) and then, in the same iteration, checks `all_status_checks_passed?` and calls `merge_request.merge!`: [5](#0-4) 

Because `sha` is content-addressed, an attacker can produce an identical sha in their own repository (e.g. by copying the exact tree/parent/author/committer/timestamp data of the victim's open PR head commit, which is often publicly visible before merge) without any cryptographic collision. GitHub's Status API does not require the target sha to correspond to a commit actually present in the sender's repository, so the attacker can set `state: success` for that sha in their own org and GitHub will deliver a validly-signed `status` webhook naming the attacker's own repo — but carrying the victim's sha.

Existing guards do not prevent this: `verify_signature` only proves the webhook was legitimately sent for *some* repo/installation known to Shipit (per the question's precondition, the attacker's own org), not that the *sha* belongs to that repo. The `ExplicitParameters` schema for `StatusHandler` does not require or enforce a repository/sha ownership binding at all.

### Impact Explanation
An attacker can inject a fabricated "success" status onto an arbitrary victim `MergeRequest`'s head commit merely by knowing/reproducing that commit's content and controlling a repository of their own. If the victim stack has `merge_queue_enabled` and the MergeRequest is `pending`, this directly causes `merge_request.merge!` to run — an unauthorized merge of the victim's PR triggered entirely by a webhook about a repository the victim never authorized. This matches the Critical category "a payload for one repository mutating another's stack, commit, task or task or ... an unauthorized deploy, rollback or merge," and is repeatable against any tenant sharing the same Shipit instance whose commit content the attacker can reproduce (most straightforward when the victim repo/PR is public).

### Likelihood Explanation
Preconditions: victim stack has `merge_queue_enabled: true` with a `pending` MergeRequest; attacker needs a repository capable of emitting a validly-signed `status` webhook to the shared Shipit instance (as stated in the question's preconditions) and the ability to reproduce the exact byte content of the victim's head commit so the SHA-1 matches — feasible for public/visible PRs since git commit hashes are deterministic from content, not from hosting repo. No Shipit credentials, sessions, or GitHub tokens are required beyond what an ordinary GitHub user already has for their own repo. This is repeatable per pending MergeRequest whose head content the attacker can observe/reproduce.

### Recommendation
Scope the `Commit` lookup in `StatusHandler#process` (and the analogous `check_suite`/`check_run` handlers) to the repository named in the webhook payload, e.g. join through `stack` and filter `stack.repository_owner`/`stack.repository_name` (or equivalent) against the payload's `repository.owner.login` / `repository.name`, rejecting/ignoring statuses whose sender repo does not match the commit's own stack.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`-style, no live GitHub):
1. Create `stack_a` (victim) with `merge_queue_enabled: true`, and a `MergeRequest` `mr` in `pending` state whose `head` commit has `sha: SHARED_SHA`, belonging to `stack_a`.
2. Create `stack_b` (attacker-controlled, different repo/org) with no relation to `stack_a`.
3. Assert precondition: `stack_a.repository.full_name != stack_b.repository.full_name` (the binding under test).
4. Post a signed `status` webhook payload with `repository: stack_b.repository`, `sha: SHARED_SHA`, `state: 'success'` to `POST /webhooks`.
5. Assert `mr.head.reload.statuses.last.state == 'success'` even though the payload's `repository` was `stack_b`'s, proving the cross-repo write.
6. Mock `MergeRequest#merge!` with a Mocha `expects(:merge!)` and run `ProcessMergeRequestsJob.perform_now(stack_a)`; assert the expectation is satisfied, proving unauthorized merge triggered by a webhook about an unrelated repository.

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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
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

**File:** app/jobs/shipit/process_merge_requests_job.rb (L21-30)
```ruby
      merge_requests.select(&:pending?).each do |merge_request|
        merge_request.refresh!
        next unless merge_request.all_status_checks_passed?

        begin
          merge_request.merge!
        rescue MergeRequest::NotReady
          ProcessMergeRequestsJob.set(wait: 10.seconds).perform_later(stack)
          return false
        end
```
