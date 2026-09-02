### Title
`StatusHandler#process` writes commit statuses across all repositories sharing a sha, breaking repository scoping - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` resolves target commits via `Commit.where(sha: params.sha)` with no filter on the repository that the verified webhook payload actually names, unlike `PushHandler` which scopes through `stacks` (derived from `payload.dig('repository', 'full_name')`). Any Commit row in the database whose `sha` column matches the attacker's chosen sha receives a `create_status_from_github!` call driven entirely by attacker-supplied `state`/`description`/`target_url`/`context`, regardless of which repository/organization owns that row.

### Finding Description
The binding that should hold is: `Commit.where(sha: params.sha)` == `commits belonging to Repository.from_github_repo_name(payload.dig('repository','full_name'))`. In `Handler#stacks` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`) that binding is explicitly enforced for other handlers — e.g. `PushHandler#process` calls `stacks.not_archived.where(branch:)...` (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`), scoping strictly to stacks under the verified repository.

`StatusHandler#process`, however, does:
```
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
```
(`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`)

It never calls `stacks`/`Repository.from_github_repo_name`, so the equality is broken: the left side (`Commit.where(sha:)`) spans the entire `commits` table irrespective of stack/repository, while the right side (commits scoped to the payload's named repository) is what the signed webhook should authorize. Any Shipit-tracked commit anywhere with a matching sha — including commits pushed under entirely unrelated repositories/organizations — will have `commit.create_status_from_github!(params)` invoked with the attacker's `state`, `description`, `target_url`, and `context`.

`verify_signature`/`GitHubApp#verify_webhook_signature` only proves the request was signed for *some* repository the GitHub App is installed on; it does not, and cannot, prove that no other repository in the Shipit instance has a colliding sha. Since git shas are content-addressed but not globally unique across independent repositories (two unrelated repos can trivially produce identical commit shas, e.g. by copying the same tree/parent/author/timestamp, or via short-sha collision if a `by_sha`-style prefix match were in play — though this handler uses an exact `sha` equality, exact-sha collisions are attacker-achievable by copying a commit verbatim into a repo they control and having Shipit ingest it via `sync_github`), this is a foreseeable cross-tenant write.

### Impact Explanation
A single valid, GitHub-App-signed `status` webhook for a repository the attacker legitimately controls (or was briefly granted access to) causes `Commit#create_status_from_github!` to run against every `Commit` row across the entire Shipit database that happens to carry the same `sha`, not just those under the named repository. This can flip a `state: success` status on commits belonging to unrelated stacks/organizations, which feeds `Commit#deployable?`/`Commit#blocked?`/`schedule_continuous_delivery` — i.e., a payload for one repository can influence another repository's stack/commit status and downstream deploy/continuous-delivery eligibility. This matches the Critical category "a payload for one repository mutating another's stack, commit, task or team."

### Likelihood Explanation
The attacker needs: (1) a repository they control that is added/installed with the Shipit GitHub App (a very low bar — the prompt states this can be a repo "briefly granted access to"), and (2) a commit sha collision with a commit already tracked in another organization's Shipit stack. Producing an exact sha match requires copying an existing commit's full metadata (tree, parents, author, committer, timestamps, message) into their own repository/branch, which is technically feasible since git shas are deterministic content hashes and nothing prevents cloning a public commit's exact metadata into a controlled repo, then pushing it so Shipit's `sync_github` ingests it as a `Commit` row, and finally triggering (or waiting for) a real `status` event from GitHub for that repository. This is a realistic, low-cost, repeatable attack path once a target sha is known (target shas are often public, e.g. visible in another org's public Shipit UI or GitHub repo).

### Recommendation
Scope `StatusHandler#process` to the repository named in the verified payload, mirroring `PushHandler`, e.g.:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
using the existing `Handler#stacks` helper (which resolves `Repository.from_github_repo_name(repository_name)&.stacks`) so status updates are constrained to commits belonging to the repository that GitHub actually signed the webhook for.

### Proof of Concept
Minitest plan (no live GitHub):
1. Create three `Repository` rows for three distinct orgs (`org-a/repo`, `org-b/repo`, `org-c/repo`), each with a `Stack`.
2. Create one `Commit` under each stack with the identical `sha = "a" * 40`.
3. Build a `status` webhook payload naming only `org-a/repo` as `repository.full_name`, with `sha` equal to the shared sha and `state: "success"`.
4. Invoke `Shipit::Webhooks::Handlers::StatusHandler.call(payload)` (or POST to `/webhooks` with a valid HMAC signature using the test `webhook_secret`, matching existing `webhooks_controller_test.rb` patterns).
5. Assert:
   - `commit_a.reload.statuses.count == 1` and its state is `success` (expected/legit side).
   - `commit_b.reload.statuses.count == 0` and `commit_c.reload.statuses.count == 0` — currently this FAILS because both also gain a status, proving `Commit.where(sha:)` is unscoped to `org-a/repo`.
6. The equality to check explicitly: `Commit.where(sha: params.sha).pluck(:stack_id).uniq` should equal `[stack_a.id]` (the stack under `org-a/repo`), but before the fix it equals `[stack_a.id, stack_b.id, stack_c.id]`.