### Title
Cross-repository SHA-collision webhook forges a `success` `Status` on a foreign stack's commit, triggering unauthorized continuous deployment - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits by `sha` globally across the entire database (`Commit.where(sha: params.sha)`), ignoring the `repository` named in the verified webhook payload entirely. An attacker who owns any repository with the Shipit GitHub App installed can craft a commit whose SHA collides with a commit already tracked under a victim's stack, then POST a signed `status` event for that SHA from their own repo. Shipit creates a `Status` on the victim's `Commit`/`Stack`, which can flip `deployable?` to true and, if the victim stack has `continuous_deployment: true`, cascades into an unauthorized deploy.

### Finding Description
The binding that should hold but does not:
`payload.dig('repository','full_name')` (attacker's repo, the entity actually authenticated by `verify_signature`) `== commit.stack.repository.full_name` (the repository owning the stack that receives the forged status and, later, an unauthorized deploy).

Code path:
- `Shipit::WebhooksController#create` (`app/controllers/shipit/webhooks_controller.rb:10-15`) verifies only that the raw payload is validly signed for `repository_owner` (`params.dig('repository','owner','login')`), via `Shipit.github(organization: repository_owner).verify_webhook_signature` (`app/controllers/shipit/webhooks_controller.rb:24-30`). This proves the payload genuinely originated from a GitHub App installation the attacker controls (e.g., installed on their own account/org) — it proves nothing about which Shipit stack the event is allowed to affect.
- `Shipit::Webhooks::Handlers::Handler` base class (`app/models/shipit/webhooks/handlers/handler.rb:32-38`) does define a `stacks` helper that scopes lookups to `Repository.from_github_repo_name(repository_name)&.stacks`, correctly binding the payload's repository to Shipit stacks. `StatusHandler`, however, does **not** use this helper.
- `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`):
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
This queries `Commit` by `sha` alone, with no `stack_id`/`repository` scoping, so it will match *any* commit in the database sharing that SHA, regardless of which repository the signed payload names.
- `Commit#create_status_from_github!` (`app/models/shipit/commit.rb:165-169`) creates a `Status` via `statuses.replicate_from_github!(stack_id, github_status)` using the victim's `stack_id` (the commit's own stack), not the attacker's stack.
- `Status` (`app/models/shipit/status.rb:19,42-44`) fires `after_commit :schedule_continuous_delivery` → `commit.schedule_continuous_delivery`.
- `Commit#schedule_continuous_delivery` (`app/models/shipit/commit.rb:281-287`) checks `deployable? && stack.continuous_deployment? && stack.deployable?`; `deployable?` (`app/models/shipit/commit.rb:227-229`) becomes true once `success?` is true and the commit isn't blocked — which the forged `success` status satisfies. It then enqueues `ContinuousDeliveryJob.perform_later(stack)` for the **victim's** stack.
- `ContinuousDeliveryJob#perform` → `Stack#trigger_continuous_delivery` proceeds to select the newly-"deployable" commit via `next_commit_to_deploy`/`deployable_commits`, and (subject to lock/`active_task?`/`deployment_checks_passed?` preconditions) triggers a deploy through `Task#enqueue` → `Command#start`/`PTY.spawn`, running the victim stack's deploy script.

Why guards fail: `verify_signature` authenticates the *sender* (a legitimate GitHub App installation, which the attacker can control by installing the app on their own account/org and pushing to their own repo), but does not authenticate *which stack's data may be mutated*. The one place that binding should be enforced — the `stacks`/`repository_name` scoping in `Handler` — is bypassed because `StatusHandler` queries `Commit` directly by SHA rather than through `stacks`. Because Git commit SHA1s are computed purely from commit content (tree, parents, author/committer identities and timestamps, message) and not from any repository identifier, an attacker can trivially reproduce the exact SHA of a known/public victim commit in a repository they own (e.g., by cloning/mirroring, replaying an identical commit, or forking a public repo and pushing the identical commit object elsewhere).

### Impact Explanation
An unprivileged internet user who owns a Shipit-integrated GitHub repository (their own account/org with the Shipit GitHub App installed) can forge a `success` CI status on an arbitrary victim stack's commit merely by knowing/reproducing that commit's SHA, without ever touching the victim's repository, session, API token, or webhook secret. If the victim stack has `continuous_deployment: true` and no in-progress task, this results in an **unauthorized deploy of the victim's stack**, i.e., arbitrary command execution via `PTY.spawn` on the deploy host running the victim's deploy script. This is repeatable against any stack/commit whose SHA the attacker can reproduce, and matches the "Critical" category: an unauthorized deploy triggered by a payload from a different repository mutating another repository's stack/commit.

### Likelihood Explanation
Preconditions required on the victim side: `continuous_deployment: true`, `cached_deploy_spec` present, stack not locked, no active task, and `deployment_checks_passed?` true — all standard, common configuration for CD-enabled stacks. Attacker cost: register/own any repository with the Shipit GitHub App installed (a normal, self-service action any GitHub user can do if the app is public — a typical Shipit deployment model), and reproduce a target commit SHA (straightforward for public repos, or via git object crafting for known commit metadata). No secrets, sessions, or elevated permissions are required. This is directly and repeatably exploitable.

### Recommendation
Scope `StatusHandler#process` (and any other SHA-keyed handler, e.g. `CheckRunHandler` if it has the same pattern) to only touch commits belonging to stacks resolved from the payload's `repository.full_name`, using the existing `stacks` helper, e.g.:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
This restores the binding between the authenticated payload's repository and the stack/commit being mutated.

### Proof of Concept
Minitest plan (no live GitHub, using `perform_enqueued_jobs`):
```ruby
test "cross-repo sha collision forges status and triggers unauthorized deploy" do
  victim_stack = shipit_stacks(:shipit)
  victim_stack.update!(continuous_deployment: true)
  colliding_sha = "a" * 40
  victim_commit = victim_stack.commits.create!(sha: colliding_sha, message: "victim commit")

  attacker_payload = {
    'sha' => colliding_sha,
    'state' => 'success',
    'context' => 'ci',
    'repository' => { 'full_name' => 'attacker/evil', 'owner' => { 'login' => 'attacker' } },
  }

  assert_difference -> { Shipit::Deploy.where(stack_id: victim_stack.id).count } do
    perform_enqueued_jobs do
      Shipit::Webhooks::Handlers::StatusHandler.call(attacker_payload)
    end
  end

  # Equality that should hold but doesn't:
  assert_not_equal attacker_payload.dig('repository', 'full_name'), victim_stack.repository.full_name
  assert victim_commit.reload.success?
end
```
This asserts the exact binding violation: the payload's `repository.full_name` (`attacker/evil`) never equals `victim_stack.repository.full_name`, yet the status is applied to `victim_commit` and a `Deploy` is created for `victim_stack`.