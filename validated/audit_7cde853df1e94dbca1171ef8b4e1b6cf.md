### Title
Cross-repository status manipulation via unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits purely by `sha`, with no repository or stack scoping, and applies the incoming GitHub `status` payload to *every* matching commit row. Because the `commits` table's uniqueness constraint is `(sha, stack_id)` rather than a global unique `sha`, the same SHA can legitimately exist across multiple stacks (e.g. forks/mirrors sharing history), letting a webhook that is only cryptographically valid for one repository/organization flip CI status (`sonarqube`, `success`) on an unrelated victim stack's commit.

### Finding Description
The broken binding is: `status.stack_id == webhook.authenticated_repository.stack_id` is assumed but never enforced. In `StatusHandler#process`:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [1](#0-0) 
this iterates over *all* `Commit` rows sharing the SHA, with no filter on `stack_id`, `repository`, or any value derived from the webhook's authenticated organization/repository. `create_status_from_github!` then writes a `Status` row and can trigger `deployable_status`/`commit_status` hooks and `stack.schedule_merges` for each matched commit, regardless of which stack actually owns/authenticated that webhook.

Signature verification (`WebhooksController#verify_signature`) only checks the HMAC against `Shipit.github(organization: repository_owner)` — i.e., it authenticates that the payload came from GitHub for a given *organization*, not that it corresponds to the specific stack/repository being mutated: [2](#0-1) 
There is no additional binding in `StatusHandler` connecting the verified `repository`/`organization` from the payload to the `Commit`/`Stack` being updated.

The `commits` table enforces uniqueness only per `(sha, stack_id)`, not globally: [3](#0-2) 
so the same SHA can exist as separate rows belonging to different stacks (this occurs naturally with forked/mirrored repositories that share commit history, which is exactly the "shared commit SHA with attacker repo" precondition in the question).

Exploit flow: an attacker who owns/controls a repository (in an org/account with a valid, real GitHub App installation producing genuine, correctly-signed webhooks — a normal precondition for any GitHub webhook sender) pushes/creates a commit whose SHA coincides with a commit already tracked in the victim's Shipit stack (trivial if the attacker's repo is a fork/mirror of the upstream the victim tracks). GitHub sends a real `status` webhook for the attacker's own repository with `context: sonarqube`, `state: success`. `StatusHandler#process` matches `Commit.where(sha: ...)` across both the attacker's and victim's stacks and calls `create_status_from_github!` on both, writing a `success` status onto the victim's commit for a context the victim requires, potentially flipping `deployable?`/unblocking or forcing continuous delivery to fire (`stack.schedule_merges`, `deployable_status` hook) on the victim stack — none of which the victim's repository authenticated.

None of the existing guards prevent this: `verify_signature` only checks organization-level HMAC, not per-stack ownership of the SHA; `drop_unhandled_event` only checks the event type is registered; the `ExplicitParameters` schema in `StatusHandler.params` validates shape, not ownership; there is no `stacks`-scoping, `Repository` matching, or stack/commit-to-webhook-repository binding anywhere in this path.

### Impact Explanation
A payload authenticated for one repository writes `Status` records (and can trigger deploy-relevant hooks/merges) on a commit belonging to a completely different, unrelated stack — this is the "payload for one repository mutating another's stack/commit" category, matching **Critical** severity. Concretely: forcing a `success` status for a required context can make `Commit#deployable?` true and drive `schedule_continuous_delivery`/`schedule_merges`, i.e., cause an unauthorized deploy or merge decision on the victim's stack. This is repeatable against any victim stack that shares commit SHAs with any repository the attacker controls (forks, mirrors, or repos with overlapping history), and is not limited to a single target.

### Likelihood Explanation
Preconditions: the attacker needs (a) a repository under a GitHub organization/account for which Shipit's GitHub App produces valid webhook signatures (a normal, unprivileged condition — any repo with the app installed, e.g., a fork within the tracked org, or any org where the operator's GitHub App is broadly installed), and (b) a commit SHA that also exists as a row in the victim's stack's `commits` table (naturally true for forks/mirrors of the same upstream, common in OSS/monorepo/multi-stack setups). No Shipit session, API token, or team membership is required — the entire path is the unauthenticated `POST /webhooks` endpoint. This is low-cost and repeatable per shared SHA/context combination.

### Recommendation
Scope the commit lookup in `StatusHandler#process` (and equivalently in `CheckSuiteHandler`/other SHA-keyed handlers) to only the stack(s) whose repository matches the webhook's authenticated `repository.full_name`/`organization`, e.g. resolve the `Repository`/`Stack` from `params.dig('repository', 'full_name')` first, then constrain `Commit.where(stack_id: stack.id, sha: params.sha)` instead of a bare, cross-tenant `Commit.where(sha:)`.

### Proof of Concept
minitest plan (to be placed under `test/`, no live GitHub calls, using existing fixture patterns from `test/controllers/webhooks_controller_test.rb` and `test/models/commits_test.rb`):
1. Create two stacks/repositories, `victim_stack` and `attacker_stack`, each with its own `Repository`/`GithubHook` fixture (mirroring `shipit_status`/`cyclimse_push` fixtures).
2. Create a `Commit` row with the **same** `sha` value in both `victim_stack` and `attacker_stack` (simulating shared history), and configure `victim_stack` to require `context: 'sonarqube'` (e.g., via `required_statuses`).
3. Assert precondition: `victim_commit.deployable? == false` (or `required?`/blocked state reflecting no `sonarqube` status yet) — establishing the binding `victim_status.stack_id != attacker_webhook.stack_id`.
4. Stub `GithubHook.any_instance.stubs(:verify_signature).returns(true)` (as done in `webhooks_controller_test.rb`) and `POST /webhooks` with `X-Github-Event: status`, body `{ sha: <shared_sha>, state: 'success', context: 'sonarqube' }.merge(repository_params_for_attacker_repo)`.
5. Assert `victim_commit.reload.statuses.where(context: 'sonarqube').exists?` is now `true` and `victim_commit.deployable?` (or the relevant merge/block state) has changed, even though the webhook only authenticated for `attacker_stack`'s repository — proving the cross-tenant write.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb (L1-5)
```ruby
class IndexCommitsOnStackIdAndSha < ActiveRecord::Migration[5.1]
  def change
    add_index :commits, %i(sha stack_id), unique: true
  end
end
```
