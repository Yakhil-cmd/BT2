### Title
Cross-repository status webhook lets attacker set `Commit#status` on another stack's commit, triggering unauthorized deploy - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` looks up commits purely by `sha` with no scoping to the repository/stack that authenticated the webhook (`Commit.where(sha: params.sha)`), while `Commit`/`sha` is only unique per `stack_id` (see the `index_commits_on_stack_id_and_sha` migration), meaning any two stacks can hold rows with the identical `sha`. An attacker who owns a GitHub repo wired into Shipit (or any repo whose org is configured with a `webhook_secret`) can send a signed `status` webhook for their own repository naming a `sha` that happens to also exist as a commit on a victim stack, and the handler will create/replicate that status on the victim's `Commit` row, changing its state to `success`.

### Finding Description
The broken binding: `authenticated_repository_of_status_payload('attacker/repo') == repository_of_stack_that_deploys(victim)` is asserted by the webhook signature check, but the actual write path never enforces it.

- `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) only authenticates that the payload was signed by *some* org's webhook secret (`Shipit.github(organization: repository_owner)`), it never binds the payload to a specific `Stack`/`Commit`.
- `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`):
  ```
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
  ```
  This ignores `params['repository']` entirely and matches **every** `Commit` row across **every** `Stack` that shares the same `sha`. Since commits are only unique per `(stack_id, sha)` [1](#0-0) , nothing prevents an attacker's repo from having (or crafting, via a matching commit hash reused across forks/branches, or even a coincidental/duplicated sha already present from a shared history) a commit with the same sha as a pending commit on the victim's stack.
- `Commit#create_status_from_github!` → `add_status` recomputes `Commit#status`/`state` from the new status, and on transition to `success`/`pending` schedules `ProcessMergeRequestsJob` (see `commits_test.rb:763-777`), and separately `Stack#trigger_continuous_delivery` (invoked via `ContinuousDeliveryJob`) evaluates commit deployability (`deploy_failed?`, status/check-run state) to select commits to deploy.
- Because the handler never checks `commit.stack.repository == payload.repository`, an attacker-controlled webhook for `attacker/repo` can flip the state of a `Commit` belonging to a completely different `Stack`/repository, causing that victim commit to look CI-green and become deployable — without any CI ever running against the victim repository.

Existing guards do not stop this: `verify_signature` only confirms the *sender org* is legitimate for the org named in the payload, not that the sha named belongs to that org's stacks; `drop_unhandled_event` and the `ExplicitParameters` schema (`requires :sha`, `requires :state`, etc.) only validate payload shape, not repo ownership; there is no `Repository`/`Stack` cross-check anywhere in `StatusHandler` or `Commit#create_status_from_github!`.

### Impact Explanation
A single forged (but validly-signed-for-the-attacker's-own-org) `status` webhook can cause a `Commit` record on an unrelated victim `Stack` to become `success`, which is used both for merge-gating (`ProcessMergeRequestsJob`) and for deploy selection (`Stack#trigger_continuous_delivery` via `ContinuousDeliveryJob`). This matches the Critical category "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy, rollback or merge." The attack is repeatable against any victim stack for which the attacker can produce/guess a matching sha value, and the attacker only needs control of one repository that is itself connected to Shipit with a valid webhook secret for its own org (they do not need any privilege on the victim repo/stack).

### Likelihood Explanation
Preconditions: the attacker's own repository must be registered with Shipit's GitHub App/webhook config in the same or another organization (any org for which the attacker can trigger a signed webhook, e.g., by owning a repo under that org or a personal org they control), and there must exist a `Commit` row on the victim stack with a `sha` the attacker can produce a status for. Practically the easiest concrete exploitation is when the same commit sha legitimately exists in two stacks' commit history (e.g., shared upstream history, cherry-picks, common base commits before a fork/rename), which is a realistic occurrence given how Shipit imports commits per stack independently. The cost to the attacker is a single HTTP POST to `/webhooks` with a validly-signed payload for their own org; no secrets belonging to Shipit or the victim are required.

### Recommendation
In `StatusHandler#process`, scope the commit lookup to only stacks belonging to the repository named in the webhook payload, e.g. resolve `Repository` from `params['repository']['full_name']` (already used elsewhere for repo binding) and restrict via `Commit.joins(:stack).merge(Stack.where(repository: repo)).where(sha: params.sha)`, rejecting/ignoring updates for commits whose stack's repository doesn't match the authenticated payload repository.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb (or webhooks_controller_test.rb)
test "status webhook for one repository cannot flip status of a commit belonging to another stack's repository" do
  victim_stack = shipit_stacks(:shipit) # repository e.g. "shopify/shipit-engine"
  victim_commit = victim_stack.commits.create!(sha: "deadbeef" * 5, ...)
  attacker_repo_payload = { "sha" => victim_commit.sha, "state" => "success",
                             "repository" => { "full_name" => "attacker/unrelated-repo",
                                                "owner" => { "login" => "attacker-org" } } }

  # signature legitimately verifies for attacker-org's own webhook secret
  GithubHook.any_instance.stubs(:verify_signature).returns(true)

  assert_no_difference -> { victim_commit.reload.statuses.count } do
    post :create, body: attacker_repo_payload.to_json, as: :json,
         headers: { 'X-Github-Event' => 'status' }
  end

  assert_not_equal 'success', victim_commit.reload.state
end
```
Currently this assertion fails because `StatusHandler#process` matches `victim_commit` purely by `sha` and creates the status regardless of `attacker/unrelated-repo` vs the victim's actual repository, confirming the binding `authenticated_repository_of_status_payload != repository_of_stack_that_deploys(victim)` is violated.

### Citations

**File:** db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb (L1-5)
```ruby
class IndexCommitsOnStackIdAndSha < ActiveRecord::Migration[5.1]
  def change
    add_index :commits, %i(sha stack_id), unique: true
  end
end
```
