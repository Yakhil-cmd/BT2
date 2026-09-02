### Title
Cross-repository status forgery — `StatusHandler` resolves commits by `sha` alone, letting a properly-signed webhook from an attacker's own repository mutate a victim's `Stack` and fire `Hook.emit(:deployable_status, victim_stack, ...)` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits with `Commit.where(sha: params.sha)` and calls `create_status_from_github!` on every match, without ever checking that the matched commit's `stack`/repository corresponds to the repository that authenticated the webhook. Since git SHAs are shared across forks (or can otherwise collide across independently-tracked repos in the same Shipit instance), a status event legitimately signed for the attacker's own repository can update a status on a commit that belongs to a different, victim stack, causing `Commit#add_status` to emit `Hook.emit(:deployable_status, victim_stack, ...)` and even schedule merges for the victim.

### Finding Description
The binding that should hold is: `commit.stack.repository.full_name == payload['repository']['full_name']` for every `Commit` mutated by a `status` webhook. This binding is never checked.

- `WebhooksController#verify_signature` only validates that the raw payload was signed by the GitHub App/organization named in `payload['repository']['owner']['login']` (`repository_owner`) — it authenticates *who sent the payload*, not *which commits the payload may touch*: [1](#0-0) .
- `StatusHandler#process` then resolves target commits purely by `sha`, globally, across the whole `commits` table, with no repository/stack scoping at all: [2](#0-1) .
- `Commit#add_status` (invoked transitively via `create_status_from_github!`) computes `new_status` from whatever record was matched and emits `Hook.emit(:deployable_status, stack, ...)` using `self.stack`, i.e., whichever stack happens to own the matched `Commit` row — not the stack of the repository that signed the webhook: [3](#0-2) .

Because git commit SHAs are content-addressed and shared across a repo and all of its forks, an attacker who forks a victim's public repository automatically has commits in their own fork with identical SHAs to commits Shipit already tracks for the victim's stack. The attacker:
1. Forks the victim's public GitHub repository (any unprivileged GitHub user can do this) — the fork shares the exact same commit SHAs as the upstream/victim repo.
2. Installs/authorizes the Shipit GitHub App on their own fork (a repo they own), or otherwise arranges for GitHub to deliver a legitimately-signed `status` webhook for their own repo — e.g., by calling GitHub's `POST /repos/{attacker}/{fork}/statuses/{sha}` API on a `sha` that is one of the shared/inherited ancestor commits.
3. GitHub signs and delivers the resulting `status` webhook using the attacker's own app credentials; `verify_signature` succeeds because it only checks the attacker's own org/app secret against `payload['repository']['owner']['login']`, which correctly names the attacker's own repo.
4. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, which returns the **victim's** `Commit` row (same sha, different stack), and calls `create_status_from_github!` on it.
5. `add_status` computes a state transition for the victim's commit and, depending on the transition, calls `Hook.emit(:deployable_status, victim_stack, ...)` and/or `victim_stack.schedule_merges`, mutating/observing state for a repository the attacker's webhook never authenticated.

None of the existing guards catch this: `verify_signature` authenticates the sender's own repo/org, not the target commit's ownership; `drop_unhandled_event` only filters unknown event types; the `ExplicitParameters` schema in `StatusHandler` only validates payload shape (`sha`, `state`, etc.), not repository binding; there is no `Repository`/`Stack` lookup or `full_name` comparison anywhere in this path.

### Impact Explanation
This lets an attacker who owns nothing more than a fork of a public repository inject fabricated CI/deployable-status state transitions into a completely different tenant's `Stack`: `Hook.emit(:deployable_status, victim_stack, ...)` fires outbound webhooks (potentially to third-party systems) claiming a state transition on the victim's commit, and `stack.schedule_merges` can enqueue `ProcessMergeRequestsJob` for the victim stack, which can affect the victim's merge queue / continuous-deployment processing. This is a payload for one repository (the attacker's) mutating another's stack/commit state — matching the Critical category ("a payload for one repository mutating another's stack, commit, task or team"). It is repeatable against any repository whose commits are reachable (via fork ancestry or independently generated identical SHAs) by an attacker-controlled repository, and scales to any number of stacks/commits.

### Likelihood Explanation
Preconditions are low-cost and fully within an unprivileged GitHub user's reach: fork a public repository tracked by the target Shipit instance, and have (or create) a GitHub App/webhook installation on that fork (a repo they own) so a `status` event is legitimately signed. No Shipit session, API token, or GitHub App private key belonging to the operator is required — only the attacker's own, self-owned app credentials for their own fork. The exploit is trivially repeatable for every shared ancestor commit.

### Recommendation
Scope commit lookup in `StatusHandler#process` (and any other handler resolving records by `sha` alone) to the repository that authenticated the webhook: join through `Stack`/`Repository` and filter by `payload['repository']['full_name']` (e.g., `Commit.joins(stack: :repository).where(sha: params.sha, shipit_repositories: { name: repo_name, owner: repo_owner })`) before calling `create_status_from_github!`, rather than matching `sha` globally across all tenants.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb (new/expanded test)
test "status webhook from attacker's own repository must not mutate a different repository's stack" do
  victim_stack = shipit_stacks(:shipit)
  victim_commit = shipit_commits(:cyclimse_first) # belongs_to victim_stack

  attacker_repository_full_name = "attacker/attacker-fork" # not victim_stack.repository.full_name
  refute_equal victim_commit.stack.repository.full_name, attacker_repository_full_name

  payload = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'context' => 'ci/travis',
    'description' => 'forged',
    'repository' => { 'full_name' => attacker_repository_full_name, 'owner' => { 'login' => 'attacker' } }
  }

  Hook.expects(:emit).with(:deployable_status, victim_stack, has_entries(commit: victim_commit)).never
  # currently FAILS: StatusHandler.process still fires Hook.emit(:deployable_status, victim_stack, ...)
  Shipit::Webhooks::Handlers::StatusHandler.new(payload).call
end
```
This asserts that `Hook.emit` must never be invoked with `stack: victim_stack` from a payload whose `repository.full_name` names the attacker's own repository — currently the assertion fails because `StatusHandler#process` matches by `sha` alone (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) and `Commit#add_status` emits using `self.stack` unconditionally (`app/models/shipit/commit.rb:366-386`).

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
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
