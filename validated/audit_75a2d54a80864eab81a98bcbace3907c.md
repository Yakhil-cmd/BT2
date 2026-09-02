This confirms the vulnerability path: `create_status_from_github!` writes a `Status` row that determines `commit.deployable?`, drives `ProcessMergeRequestsJob` (merge queue), and fires `deployable_status`/`commit_status` webhooks — i.e., it directly gates deploys/merges.### Title
Cross-tenant commit status forgery via sha-only lookup in `StatusHandler#process` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` looks up every `Commit` row that shares the incoming `sha`, regardless of which repository/stack it belongs to, and writes a GitHub status onto all of them. Because webhook signature verification is scoped only to the organization that owns the payload's `repository.owner.login` (`Shipit.github(organization: repository_owner)` in `WebhooksController#verify_signature`), a valid signature from org A's own repo authorizes writes onto Commit rows belonging to org B/C's stacks whenever a sha collision exists.

### Finding Description
The broken binding is: **the set of Stack rows mutated by one signed webhook == {stack of the org that signed the request}**. Actual code: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [1](#0-0)  — this query has no filter on `stack_id`, `repository_id`, or any tie back to the payload's `repository` field, so it mutates *every* commit sharing the sha, across all stacks/orgs.

Signature verification in `WebhooksController#verify_signature` only proves the request was signed for the org identified by `params.dig('repository','owner','login')` [2](#0-1) [3](#0-2) . It never checks that the `repository` in the payload actually corresponds to the `sha`/`Commit` rows being mutated in `process`. The handler dispatch in `create` passes the whole payload to every registered handler for the event with no per-stack scoping [4](#0-3) .

Exploit flow: an attacker who owns/controls org A's GitHub repo (their own repo, with a legitimate Shipit GitHub App/webhook secret for org A) can:
1. Arrange or predict a sha collision — e.g., an initial empty commit generated identically by a template across many repos, a cherry-pick, or an intentionally crafted commit whose tree/parent/message/timestamps reproduce a victim's known sha (git shas are content-addressed but not attacker-secret; a victim's commit sha is public if the victim's repo is public, or discoverable via Shipit's own UI/API).
2. POST a `status` event to `/webhooks` for that sha, signed with org A's own valid webhook secret (`X-Hub-Signature` validated against org A only).
3. `StatusHandler#process` finds all `Commit` rows with that sha, including the victim's `Commit` row under a completely different `Stack`/org, and calls `create_status_from_github!` on it.
4. This creates a `Status` record for the victim stack, which feeds `Commit#state`/`#deployable?` and triggers `ProcessMergeRequestsJob` (merge queue) and `deployable_status`/`commit_status` hooks [5](#0-4) , i.e., it can flip a victim commit from failing/pending CI to `success`, unblocking deploys or the merge queue for a stack the attacker does not own or control.

None of the existing guards catch this: `verify_signature`/`GitHubApp#verify_webhook_signature` only authenticate "this payload was sent by org A," not "org A owns the sha/commit being written"; `drop_unhandled_event` only checks the event type is registered; there is no `ExplicitParameters` check tying `repository` to `stack`; no `ApiClient`/session logic is involved at all since this is the unauthenticated webhook path.

### Impact Explanation
A payload legitimately signed for one repository/org mutates another tenant's `Stack`'s `Commit`/`Status` state — this is exactly the "payload for one repository mutating another's stack/commit" Critical category. The practical effect is forging a passing (or failing) CI status on a victim's commit, which can unblock automated deploys via the merge queue (`ProcessMergeRequestsJob`) or corrupt CI signal used to gate deploys, across any stack whose commit happens to share a sha with an attacker-controlled repo. Blast radius spans all tenants configured on the same Shipit instance; it is repeatable for every sha collision the attacker can engineer.

### Likelihood Explanation
The attacker needs: (a) a GitHub org/repo they control with a working Shipit GitHub App integration (an "unprivileged" attacker per the rules, since they only need to own their own repo and its own legitimate webhook secret — not the victim's), and (b) a sha collision with a target commit. Sha collisions are readily achievable in practice for cases like identical template-generated initial commits, identical empty commits, or reproducible cherry-picks/reverts with identical author/committer/timestamp/tree data — these are not cryptographic collisions, just content-identical commits, which is a realistic and low-cost precondition (matches the question's own scenario of "N repos initialized from the same template producing an identical initial empty commit"). No secrets or elevated roles are required beyond the attacker's own repo's legitimate signing key, which they possess by design.

### Recommendation
Scope the lookup in `StatusHandler#process` to only commits belonging to stacks whose repository matches the payload's `repository` (owner/name), e.g. join `Commit` to `Stack`/`Repository` and filter `Commit.joins(stack: :repository).where(sha: params.sha, shipit_repositories: { owner: payload repository owner, name: payload repository name })`, instead of a bare `Commit.where(sha: ...)`. Apply the same repository-scoping fix to any other webhook handler that resolves records purely by `sha` without validating against the payload's `repository`.

### Proof of Concept
Minitest plan (no live GitHub):
1. Seed three `Repository`/`Stack` fixtures for three distinct orgs/owners (`org1/repo`, `org2/repo`, `org3/repo`), each with a `Commit` row sharing the identical `sha` (e.g., `"deadbeef" * 5`).
2. Stub/allow `GithubApp#verify_webhook_signature` to succeed only for `org1` (simulating a valid signature computed with org1's real webhook secret), matching real signature-check semantics.
3. POST to `/webhooks` with `X-Github-Event: status`, a valid signature for org1, and payload `{ "sha": "<shared sha>", "state": "success", "context": "ci/x", "repository": { "owner": { "login": "org1" }, "name": "repo" } }`.
4. Assertions on both sides of the binding:
   - Expected (secure) binding: `Stack.where(id: stacks_mutated_status_ids) == [org1_stack]`, i.e. `assert_equal [org1_stack.id], mutated_stack_ids`.
   - Currently: `org1_stack.commits.first.reload.state == 'success'` AND `org2_stack.commits.first.reload.state == 'success'` AND `org3_stack.commits.first.reload.state == 'success'` all become true — proving all three stacks were mutated by a single webhook signed only for org1, violating the intended one-to-one binding.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** test/models/commits_test.rb (L763-777)
```ruby
    test "#add_status schedule a MergeMergeRequests job if the commit transition to `pending` or `success`" do
      commit = shipit_commits(:second)
      github_status = OpenStruct.new(
        state: 'success',
        description: 'Cool',
        context: 'metrics/coveralls',
        created_at: 1.day.ago.to_formatted_s(:db)
      )

      assert_equal 'failure', commit.state
      assert_enqueued_with(job: ProcessMergeRequestsJob, args: [@commit.stack]) do
        commit.create_status_from_github!(github_status)
        assert_equal 'success', commit.state
      end
    end
```
