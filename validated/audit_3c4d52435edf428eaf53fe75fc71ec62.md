### Title
Cross-repository commit status injection via unscoped SHA lookup in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits to attach a GitHub status to using a global `Commit.where(sha: params.sha)` query that is not scoped to the repository that sent the webhook, unlike every other handler in the same module. Any commit SHA that also exists in an attacker-reachable repository (e.g., a fork sharing history with the victim's repo) can be used to inject a status onto the victim's commit record, which can flip `Commit#deployable?` and cause `Stack#trigger_continuous_delivery` to fire a deploy using the victim stack's own `GITHUB_TOKEN`.

### Finding Description
The broken binding: the repository that authenticated the webhook (`payload.dig('repository','full_name')`, verified only at the *organization* level in `WebhooksController#verify_signature`) should equal the repository that owns the commit being mutated (`commit.stack.repository`) — but `StatusHandler` never enforces this equality.

Code path:
- `app/models/shipit/webhooks/handlers/handler.rb` defines a `stacks` helper that scopes lookups to `Repository.from_github_repo_name(repository_name)&.stacks`, and `PushHandler#process` (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`) and `CheckSuiteHandler#process` (`app/models/shipit/webhooks/handlers/check_suite_handler.rb:13-16`) both correctly use this `stacks` scope before touching any commit.
- `StatusHandler#process`, however, does:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [1](#0-0) 
This ignores `repository_name`/`stacks` entirely and matches **any** commit row across **all** stacks that shares the SHA in the payload, regardless of which repository the webhook actually originated from.
- `WebhooksController#verify_signature` only validates the HMAC signature against the GitHub App/webhook secret configured for the *organization* named in the payload (`Shipit.github(organization: repository_owner)`), per `app/controllers/shipit/webhooks_controller.rb:24-30`. It never checks that the specific `repository.full_name` in the payload matches the stack that owns the commit SHA being updated.
- `Status#schedule_continuous_delivery` → `Commit#schedule_continuous_delivery` (`app/models/shipit/commit.rb:281-287`) fires `ContinuousDeliveryJob` whenever a status is created and the commit is `deployable?`, which flows into `Stack#trigger_continuous_delivery` → `Stack#trigger_deploy` (`app/models/shipit/stack.rb:210-229`), spawning a `Task`/`Command` with the victim stack's own `GITHUB_TOKEN`.

Exploit flow: an attacker who owns or has push/API access to any repository that is (a) covered by the same GitHub App installation/webhook secret configured in Shipit for a given organization, and (b) shares at least one commit SHA with the victim's tracked repository (trivially true for any fork, since forks retain identical commit objects/SHAs for shared history) can call the GitHub Statuses API on their own repository for that shared SHA. GitHub delivers a legitimately-signed `status` webhook (signed with the org's real webhook secret) to Shipit. `verify_signature` passes because the signature and organization are genuinely valid. `StatusHandler#process` then finds the *victim's* `Commit` row (same SHA, different stack) via the unscoped `Commit.where(sha:)` query and calls `commit.create_status_from_github!(params)` on it — attaching an attacker-chosen state/context (e.g., a required CI context, `state: 'success'`) to the victim's commit. If this flips the commit to deployable and the victim stack has continuous deployment enabled, `trigger_continuous_delivery` fires a real deploy using the victim stack's credentials, for a commit whose "approval" was manufactured by the attacker on an unrelated repository.

No existing guard stops this: `verify_signature` checks organization-level HMAC only, not per-repository correspondence; the `stacks` scoping helper exists in `Handler` but `StatusHandler` simply doesn't use it (a straightforward oversight/divergence from the pattern used everywhere else); `Commit#create_status_from_github!` performs no repository-ownership check against the payload.

### Impact Explanation
Critical. This allows a payload authenticated for one repository to mutate commit/status state belonging to a different stack/repository, and can trigger an unauthorized deploy (spawning `PTY.spawn`/`Command#start` with the victim stack's `GITHUB_TOKEN`/`GIT_ASKPASS`) for a commit the victim never actually approved via their own CI. This matches the explicitly in-scope Critical categories: "a payload for one repository mutating another's stack, commit, task or team" and "an unauthorized deploy." It is repeatable against any stack whose commits share a SHA with an attacker-reachable repository under the same GitHub App/org trust boundary, and it does not require possession of the victim's token — only correct exploitation of the code-level scoping gap.

### Likelihood Explanation
Requires: (1) Shipit configured with a GitHub App covering an organization/installation that also covers a repository the attacker controls (single-app-per-org is the documented default setup per `docs/setup.md`), and (2) a commit SHA shared between attacker's repository and the victim stack's repository — trivially satisfiable via forking (fork commits retain identical SHAs) or via repos derived from a common template/base commit. Attacker cost is low: create/own a repo in-scope, identify a target SHA (public git data), and issue one Statuses API call against their own repo. This is fully repeatable against any number of target stacks whose commits intersect with attacker-controlled repositories, requiring no privileged Shipit role, no team membership, and no secrets.

### Recommendation
Scope `StatusHandler#process` to the originating repository the same way `PushHandler` and `CheckSuiteHandler` do: resolve `stacks` from `repository_name` (payload's `repository.full_name`) first, then only look up/update commits belonging to those stacks, e.g.:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
This enforces that the webhook's repository owns the commit/stack being mutated, closing the cross-tenant status-injection path.

### Proof of Concept
Minitest plan (no live GitHub, add under `test/models/shipit/webhooks/handlers/status_handler_test.rb` or extend `webhooks_controller_test.rb`):
1. Fixtures: two stacks, `victim_stack` (repo `victim/prod`, `continuous_deployment: true`) with a commit `shared_commit` (sha `"deadbeef"`), and `attacker_stack` (repo `attacker/fork`) — do **not** create a commit row for `attacker_stack` sharing this sha (simulating that Shipit only tracks `victim/prod`'s commit, while GitHub allows the attacker to post a status against that sha because their fork shares the object).
2. Stub `GithubHook`/`verify_signature` (or stub `Shipit.github(organization:).verify_webhook_signature`) to return `true`, simulating a legitimately-signed webhook from `attacker/fork`'s org-shared GitHub App installation.
3. POST to `/webhooks` with `X-Github-Event: status`, payload: `{ "sha" => "deadbeef", "state" => "success", "context" => "ci/travis", "repository" => { "full_name" => "attacker/fork", "owner" => { "login" => "attacker-org" } }, "branches" => [] }`.
4. Assert equality-before: `victim_stack.commits.find_by(sha: "deadbeef").statuses.count == 0` and `commit.deployable? == false`.
5. Assert equality-after: `commit.reload.statuses.count == 1` and, if it flips `deployable?` to `true`, `assert_enqueued_with(job: ContinuousDeliveryJob, args: [victim_stack])`.
6. Assert the binding fails: the status was recorded on `victim_stack`'s commit even though the authenticated `repository.full_name` in the payload was `attacker/fork`, i.e. `status.commit.stack != Stack.find_by(repository: payload_repository)`.
7. To fully demonstrate deploy-time credential exposure, stub `Command#start`/`PTY.spawn` and assert it is invoked with `ENV` containing `victim_stack`'s `GITHUB_TOKEN` after running `ContinuousDeliveryJob.new.perform(victim_stack)`.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
